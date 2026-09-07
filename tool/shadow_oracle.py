#!/usr/bin/env python3
"""Settle the uniform shadow representation by executing it.

`span_oracle` proves the span representation: the upper half of every value
lives in a slot FOR THE LENGTH OF THE SPAN. It reaches arithmetic whose
source is memory, because `narrow_piece` can address the high half at an
offset. It cannot reach arithmetic whose source is a REGISTER, where the
high half is in the inaccessible upper part of a ymm -- and that is the
largest refused bucket on the frontier, 1,875 sites of "256-bit: arithmetic
rather than a copy", plus most of the 5,383 regions refused for reading a
ymm defined outside them.

The uniform representation answers both by making the slot PERMANENT: every
ymm register has one, every 256-bit write maintains it, every 256-bit read
consults it. Nothing then has to be proved about where a value came from,
which is what the whole provenance walk exists to establish.

This asks whether the arithmetic itself is right under that representation:

    vaddps %ymm1,%ymm2,%ymm3   ->   movaps %xmm2,%xmm3       low half
                                    addps  %xmm1,%xmm3
                                    movaps s2,%xmm15         high half
                                    addps  s1,%xmm15
                                    movaps %xmm15,s3

Five instructions and a scratch register for one, which is the price of the
representation and is why it is measured rather than assumed.

**Both sides run, and in different places** -- `span_oracle`'s shape. The
256-bit original goes under qemu-x86_64, which decodes VEX on a host that
has none; the lowering runs natively, because it is pure SSE. Both write 32
bytes and the two must agree bit for bit.

The harness populates the slots on load and reads them on store, so what is
tested is the representation end to end -- definition, arithmetic, use --
and not one instruction in isolation.

Usage:  shadow_oracle.py [build directory]
"""
import subprocess
import sys
from pathlib import Path

IN_BYTES = 128
OUT_BYTES = 32
TIMEOUT = 300
QEMU = ["qemu-x86_64"]
WORK = Path("build") / "shadow-oracle"
SCRATCH = "%xmm15"

# (name, mnemonic, sse) -- three-operand VEX, register source.
CASES = [
	("packed single add", "vaddps", "addps"),
	("packed single multiply", "vmulps", "mulps"),
	("packed single subtract", "vsubps", "subps"),
	("packed single maximum", "vmaxps", "maxps"),
	("packed single minimum", "vminps", "minps"),
	("bitwise and", "vandps", "andps"),
	("bitwise xor", "vxorps", "xorps"),
	("packed double add", "vaddpd", "addpd"),
	("packed double multiply", "vmulpd", "mulpd"),
]


def vex_side(mnemonic):
	"""The original: two 256-bit loads, the operation, one 256-bit store."""
	return "\n".join([
		".text", ".globl run", ".type run, @function", "run:",
		"\tvmovups\t(%rsi),%ymm1",
		"\tvmovups\t0x20(%rsi),%ymm2",
		f"\t{mnemonic}\t%ymm1,%ymm2,%ymm3",
		"\tvmovups\t%ymm3,(%rdi)",
		"\tvzeroupper", "\tret", ""])


def shadow_side(sse):
	"""The same, under the uniform representation.

	Slot 1 is at 0(%rsp), slot 2 at 16, slot 3 at 32 -- standing in for the
	permanent per-register block a real build puts in thread-local storage.
	The loads populate them and the store reads one back, which is what
	makes this a test of the REPRESENTATION rather than of one lowering.
	"""
	return "\n".join([
		".text", ".globl run", ".type run, @function", "run:",
		# **The frame must be 16-byte aligned and a `call` leaves it 8 mod
		# 16.** `movaps` to a slot and `addps` from one both require an
		# aligned memory operand, so the first version faulted and printed
		# nothing -- nine cases DIFFER with the lowering visibly correct,
		# the harness measuring itself. A real stub borrows the callee home
		# space, which is aligned by the ABI; this stands in for it.
		"\tpushq\t%rbp",
		"\tmovq\t%rsp, %rbp",
		"\tsubq\t$128, %rsp",
		"\tandq\t$-16, %rsp",
		# ymm1 = (low in %xmm1, high in slot 1)
		"\tmovups\t(%rsi),%xmm1",
		f"\tmovups\t0x10(%rsi),{SCRATCH}",
		f"\tmovaps\t{SCRATCH},(%rsp)",
		# ymm2 = (low in %xmm2, high in slot 2)
		"\tmovups\t0x20(%rsi),%xmm2",
		f"\tmovups\t0x30(%rsi),{SCRATCH}",
		f"\tmovaps\t{SCRATCH},0x10(%rsp)",
		# ymm3 = ymm2 OP ymm1, both halves
		"\tmovaps\t%xmm2,%xmm3",
		f"\t{sse}\t%xmm1,%xmm3",
		f"\tmovaps\t0x10(%rsp),{SCRATCH}",
		f"\t{sse}\t(%rsp),{SCRATCH}",
		f"\tmovaps\t{SCRATCH},0x20(%rsp)",
		# store ymm3: low from the register, high from its slot
		"\tmovups\t%xmm3,(%rdi)",
		f"\tmovaps\t0x20(%rsp),{SCRATCH}",
		f"\tmovups\t{SCRATCH},0x10(%rdi)",
		"\tmovq\t%rbp, %rsp", "\tpopq\t%rbp", "\tret", ""])


def broken_side(sse):
	"""The same lowering with the high half taken from the LOW one.

	**The control.** Nine cases agreeing proves nothing unless the
	comparison can tell a wrong answer from a right one, and the failure
	this guards against is precise: a lowering that operates on the low
	half twice and never consults the slot. It differs only in the upper
	sixteen bytes, so a harness comparing fewer than 32 would pass it.
	"""
	return shadow_side(sse).replace("\tmovaps\t0x10(%rsp),%xmm15",
	                                "\tmovaps\t(%rsp),%xmm15")


MAIN = r"""
#include <stdio.h>
extern void run(void *out, const void *in);
int main(void) {
	static unsigned char in[%d] __attribute__((aligned(32)));
	static unsigned char out[%d];
	for (int i = 0; i < %d; i++) in[i] = (unsigned char)(i * 7 + 3);
	run(out, in);
	for (int i = 0; i < %d; i++) printf("%%02x", out[i]);
	printf("\n");
	return 0;
}
"""


def build(where, asm):
	WORK.mkdir(parents=True, exist_ok=True)
	(WORK / f"{where}.s").write_text(asm)
	(WORK / f"{where}.c").write_text(
		MAIN % (IN_BYTES, OUT_BYTES, IN_BYTES, OUT_BYTES))
	binary = WORK / where
	subprocess.run(["gcc", "-Os", "-o", str(binary), str(WORK / f"{where}.c"),
	                str(WORK / f"{where}.s")], check=True, timeout=TIMEOUT)
	return binary


def run_it(binary, under_qemu):
	command = (QEMU if under_qemu else []) + [str(binary)]
	done = subprocess.run(command, capture_output=True, text=True,
	                      timeout=TIMEOUT)
	return done.stdout.strip()


def require_oracle():
	"""qemu present and able to run a 256-bit instruction.

	Without this the whole tool reports agreement over nothing, which is
	the vacuous pass every gate here is written against.
	"""
	probe = "\n".join([".text", ".globl run", ".type run, @function", "run:",
	                   "\tvmovups\t(%rsi),%ymm0", "\tvmovups\t%ymm0,(%rdi)",
	                   "\tvzeroupper", "\tret", ""])
	try:
		binary = build("probe", probe)
	except Exception as exc:
		print(f"shadow_oracle: cannot build the probe: {exc}", file=sys.stderr)
		return False
	if not run_it(binary, True):
		print("shadow_oracle: SKIPPED -- qemu-x86_64 cannot run AVX here",
		      file=sys.stderr)
		return False
	return True


def main():
	if len(sys.argv) > 1:
		global WORK
		WORK = Path(sys.argv[1]) / "shadow-oracle"
	if not require_oracle():
		return 0
	bad = 0
	for name, mnemonic, sse in CASES:
		want = run_it(build("vex", vex_side(mnemonic)), True)
		got = run_it(build("shadow", shadow_side(sse)), False)
		if not want:
			print(f"shadow_oracle: FAILED -- {mnemonic} produced no output "
			      f"under qemu", file=sys.stderr)
			bad += 1
		elif want != got:
			print(f"shadow_oracle: DIFFER {mnemonic} ({name})",
			      file=sys.stderr)
			print(f"    256-bit {want}\n    shadow  {got}", file=sys.stderr)
			bad += 1
	# The control, before any pass above is believed.
	want = run_it(build("vex", vex_side("vaddps")), True)
	broke = run_it(build("broken", broken_side("addps")), False)
	if want == broke:
		print("shadow_oracle: FAILED -- the control agrees, so the "
		      "comparison cannot tell a wrong lowering from a right one",
		      file=sys.stderr)
		bad += 1
	else:
		print("shadow_oracle: control -- a high half taken from the low one "
		      "differs, so the comparison discriminates")
	if bad:
		print(f"shadow_oracle: {bad} of {len(CASES)} case(s) differ",
		      file=sys.stderr)
		return 1
	print(f"shadow_oracle: {len(CASES)} register-source 256-bit operation(s) "
	      f"lower through permanent slots and agree bit for bit")
	return 0


if __name__ == "__main__":
	sys.exit(main())
