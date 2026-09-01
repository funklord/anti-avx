#!/usr/bin/env python3
"""Settle `detour.lower_ymm_span` by executing it, not by reading it.

**This machine is a Westmere.** It cannot execute a VEX instruction, which
is the project's premise -- but it CAN execute the lowering, because the
lowering is the point: pure SSE. So the two sides of the question run in
different places. The 256-bit original goes under `qemu-x86_64`, which
decodes and executes VEX on a host that has none; the span goes natively on
silicon that can run it. Both write 32 bytes and the two must agree bit for
bit.

That is `vex_oracle`'s shape applied to a SEQUENCE rather than to one
instruction, and the difference is why it earns a tool of its own. A span
is a representation: the upper half of every value it tracks lives in a
16-byte slot for the length of the span, and what has to be proved is not
that one instruction lowered correctly but that the representation holds
from the definition to the death. Only running it end to end asks that.

The slot lives in a 32-byte frame the harness allocates, because the
lowering addresses it as `(%rsp)` -- which in a function entered by `call`
is the return address. `build_stub` puts it in the callee home space
instead, which is what `borrow_offset` is for.

Usage:  span_oracle.py [build directory]
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour

WORK = Path("build") / "spanoracle"
QEMU = ["qemu-x86_64", "-cpu", "max"]
TIMEOUT = 300

# `(what, rows, members, slots, peak)` where a row is
# `(encoding, mnemonic, operands)` and the members name what the span makes
# of each. Every case reads from %rsi and writes to %rdi.
#
# The encodings are the assembler's, taken from `as` on the source spelled
# in the comment beside each.
CASES = [
	("a load, a memory-source add and a store",
	 [("c5fc1006", "vmovups", "(%rsi),%ymm0"),		# vmovups (%rsi),%ymm0
	  ("c5fc584640", "vaddps", "0x40(%rsi),%ymm0,%ymm0"),
	  ("c5fc1107", "vmovups", "%ymm0,(%rdi)")],
	 [("load", 0, "%ymm0"), ("lane", 1, "%ymm0"), ("store", 2, "%ymm0")],
	 {"%ymm0": 0}),
	# **Two values, two slots**, which is what the slot table's second row
	# is about. A span that gave both the same sixteen bytes would return
	# one value twice, and this is the case that says so.
	("two values in two slots, each stored",
	 [("c5fc1006", "vmovups", "(%rsi),%ymm0"),
	  ("c5fc104e20", "vmovups", "0x20(%rsi),%ymm1"),
	  ("c5fc584640", "vaddps", "0x40(%rsi),%ymm0,%ymm0"),
	  ("c5f4584e60", "vaddps", "0x60(%rsi),%ymm1,%ymm1"),
	  ("c5fc1107", "vmovups", "%ymm0,(%rdi)"),
	  ("c5fc114f20", "vmovups", "%ymm1,0x20(%rdi)")],
	 [("load", 0, "%ymm0"), ("load", 1, "%ymm1"), ("lane", 2, "%ymm0"),
	  ("lane", 3, "%ymm1"), ("store", 4, "%ymm0"), ("store", 5, "%ymm1")],
	 {"%ymm0": 0, "%ymm1": 1}),
	# **The register second source**, which is what `slot_tail` was written
	# for: the operation reaches the other value's slot as a memory OPERAND
	# rather than having it moved in and out. Both slots are in play at
	# once and the answer depends on reading the right one -- a span that
	# addressed the destination's slot twice would return ymm0 + ymm0.
	("a register second source, with both slots in play",
	 [("c5fc1006", "vmovups", "(%rsi),%ymm0"),
	  ("c5fc104e20", "vmovups", "0x20(%rsi),%ymm1"),
	  ("c5fc58c1", "vaddps", "%ymm1,%ymm0,%ymm0"),
	  ("c5fc1107", "vmovups", "%ymm0,(%rdi)")],
	 [("load", 0, "%ymm0"), ("load", 1, "%ymm1"), ("lane", 2, "%ymm0"),
	  ("store", 3, "%ymm0")],
	 {"%ymm0": 0, "%ymm1": 1}),
	# **Three distinct registers**, the shape Finding 150 counted at 1,367
	# and the largest the region reaches that no span could. SSE has no
	# three-operand form, so both halves are a move and an operation, and
	# THREE slots are in play: two read, one written. A span that wrote the
	# result into a source's slot would return the wrong value from the
	# next instruction that read it.
	("a register second source with a destination of its own",
	 [("c5fc1006", "vmovups", "(%rsi),%ymm0"),
	  ("c5fc104e20", "vmovups", "0x20(%rsi),%ymm1"),
	  ("c5fc58d1", "vaddps", "%ymm1,%ymm0,%ymm2"),
	  ("c5fc1117", "vmovups", "%ymm2,(%rdi)")],
	 [("load", 0, "%ymm0"), ("load", 1, "%ymm1"), ("lane", 2, "%ymm2"),
	  ("store", 3, "%ymm2")],
	 {"%ymm0": 0, "%ymm1": 1, "%ymm2": 2}),
	# A multiply rather than an add, so the answer depends on the opcode
	# surviving the split rather than on the operands alone.
	("a multiply, whose result differs from an add's",
	 [("c5fc1006", "vmovups", "(%rsi),%ymm0"),
	  ("c5fc594640", "vmulps", "0x40(%rsi),%ymm0,%ymm0"),
	  ("c5fc1107", "vmovups", "%ymm0,(%rdi)")],
	 [("load", 0, "%ymm0"), ("lane", 1, "%ymm0"), ("store", 2, "%ymm0")],
	 {"%ymm0": 0}),
]

# How many bytes each case writes, and how much input it reads.
OUT_BYTES = {0: 32, 1: 64, 2: 32, 3: 32, 4: 32}
IN_BYTES = 256


def rows_of(case):
	"""The instruction list `lower_ymm_span` walks, laid out from 0x1000."""
	out, at = [], 0x1000
	for encoding, mnemonic, operands in case[1]:
		bits = bytes.fromhex(encoding)
		out.append((at, bits, mnemonic, operands, None))
		at += len(bits)
	return out


def emit(case, helper=5):
	"""The span's bytes, or None if it refuses."""
	entries = detour.span_entries(case[2], rows_of(case), case[3], None, [])
	return detour.lower_ymm_span(entries, 0, helper, 0x2000, 0,
	                             second_helper=4)


def source(name, body):
	"""A function of (out in %rdi, in in %rsi) wrapping raw bytes.

	The 32-byte frame is the slot's, and it is the harness standing in for
	the callee home space a real stub borrows.
	"""
	# **128 bytes, not 32.** The frame holds the span's slots, and the
	# three-register shape uses three -- the third at 0x20, which a
	# 32-byte frame does not contain. It wrote past the allocation and the
	# case came back DIFFER with the emission visibly correct, which is
	# the harness measuring itself. `TLS_SLOTS` slots of sixteen bytes is
	# the most any span here asks for, and 128 is comfortably that.
	lines = [".text", f".globl {name}", f".type {name}, @function",
	         f"{name}:", "\tsubq\t$128, %rsp"]
	for i in range(0, len(body), 8):
		lines.append("\t.byte " + ", ".join(str(b) for b in body[i:i + 8]))
	lines += ["\taddq\t$128, %rsp", "\tret", ""]
	return "\n".join(lines) + "\n"


def vex_source(name, case):
	"""The original, spelled from the same operands the span was built from."""
	lines = [".text", f".globl {name}", f".type {name}, @function",
	         f"{name}:"]
	for _encoding, mnemonic, operands in case[1]:
		lines.append(f"\t{mnemonic}\t{operands}")
	lines += ["\tvzeroupper", "\tret", ""]
	return "\n".join(lines) + "\n"


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


def build(where, name, asm, out_bytes):
	"""Assemble and link one side. The binary's path."""
	WORK.mkdir(parents=True, exist_ok=True)
	(WORK / f"{where}.s").write_text(asm.replace(name, "run"))
	(WORK / f"{where}.c").write_text(
		MAIN % (IN_BYTES, out_bytes, IN_BYTES, out_bytes))
	binary = WORK / where
	subprocess.run(["gcc", "-Os", "-o", str(binary), str(WORK / f"{where}.c"),
	                str(WORK / f"{where}.s")], check=True, timeout=TIMEOUT)
	return binary


def run(binary, under_qemu):
	command = (QEMU if under_qemu else []) + [str(binary)]
	done = subprocess.run(command, capture_output=True, text=True,
	                      timeout=TIMEOUT)
	return done.stdout.strip()


def require_oracle():
	"""qemu present and able to run AVX, or say so and skip.

	**Absent and working are different claims**, which is `evidence.md`'s
	point and `lane_oracle`'s. 77 is the skip code.
	"""
	import shutil
	if shutil.which(QEMU[0]) is None:
		print("no qemu-x86_64: install qemu-user. SKIPPED, not passed.",
		      file=sys.stderr)
		raise SystemExit(77)
	probe = subprocess.run(QEMU + ["-cpu", "help"], capture_output=True,
	                       text=True, timeout=60)
	if "avx2" not in probe.stdout:
		print("qemu-x86_64 reports no avx2 model. SKIPPED, not passed.",
		      file=sys.stderr)
		raise SystemExit(77)


def main():
	global WORK
	if len(sys.argv) > 1:
		WORK = Path(sys.argv[1]) / "spanoracle"
	require_oracle()
	problems = 0

	print("== capability control: the 256-bit side must not run here ==")
	native_check = build("cap", "cap", vex_source("cap", CASES[0]),
	                     OUT_BYTES[0])
	done = subprocess.run([str(native_check)], capture_output=True,
	                      timeout=TIMEOUT)
	print(f"   native exit {done.returncode}"
	      f"{' (SIGILL -- host cannot execute the input)' if done.returncode == -4 else ' -- EXPECTED SIGILL'}")
	if done.returncode != -4:
		print("span_oracle: FAILED -- this host executed a 256-bit "
		      "instruction, so the comparison proves nothing",
		      file=sys.stderr)
		problems += 1

	for i, case in enumerate(CASES):
		body = emit(case)
		if body is None:
			print(f"span_oracle: FAILED -- {case[0]}: the span refused to "
			      f"lower", file=sys.stderr)
			problems += 1
			continue
		sse = run(build(f"sse{i}", f"sse{i}", source(f"sse{i}", body),
		                OUT_BYTES[i]), False)
		vex = run(build(f"vex{i}", f"vex{i}", vex_source(f"vex{i}", case),
		                OUT_BYTES[i]), True)
		agree = sse == vex and sse != ""
		print(f"   {case[0][:52]:54} {'agree' if agree else 'DIFFER'}")
		if not agree:
			print(f"       span {sse}\n       vex  {vex}", file=sys.stderr)
			problems += 1

	# **A harness that agrees with itself proves nothing.** The sabotage
	# gives the second slot the first's offset, which is the defect Finding
	# 118 met in the home space: two values saved to the same sixteen bytes,
	# each coming back holding the other's. It must be caught.
	print("== control: two values sharing one slot must be rejected ==")
	case = CASES[1]
	shared = (case[0], case[1], case[2], {"%ymm0": 0, "%ymm1": 0})
	body = emit(shared)
	caught = True
	if body is not None:
		sse = run(build("sab", "sab", source("sab", body), OUT_BYTES[1]),
		          False)
		vex = run(build("vex1", "vex1", vex_source("vex1", case),
		                OUT_BYTES[1]), True)
		caught = sse != vex
	print(f"   collapsing two slots into one: "
	      f"{'rejected' if caught else 'ACCEPTED'}")
	if not caught:
		print("span_oracle: FAILED -- the inputs cannot tell two slots "
		      "from one, so the agreements above are unearned",
		      file=sys.stderr)
		problems += 1

	if not problems:
		print(f"span_oracle: {len(CASES)} span(s) lower to SSE that computes "
		      f"what the 256-bit original computes, bit for bit")
	return 1 if problems else 0


if __name__ == "__main__":
	raise SystemExit(main())
