#!/usr/bin/env python3
"""Close the gap: compare each lowering against the VEX it replaced.

`make check-lowering` executes every lowering and compares it against GCC
compiling the equivalent SSE intrinsic. That is a separate producer, but it
is **the compiler, not the original instruction** -- so a lowering and a
reference that are wrong the same way agree, and a mnemonic whose intrinsic
nobody wrote has no case at all.

This asks the question that one cannot. `qemu-x86_64` decodes and executes
VEX on a host that has none, because it translates rather than dispatches,
so the ORIGINAL instruction can be run here after all. Every case is:

    the original VEX encoding, under qemu       ->  16 xmm registers
    detour.lower_vex's bytes, on this Westmere  ->  16 xmm registers

compared over all sixteen, because a lowering that computes the right
answer and clobbers a bystander is still wrong.

**The case list is not written again here.** `lowering_cases.build()` is
called, and `detour.lower_vex` is wrapped to record the encoding it was
handed -- so the originals and the lowerings come out of one pass over one
list, in one order, and there is no second copy of the shape rules to drift
from the first.

Two kinds of difference are expected rather than wrong, and each is
asserted rather than excused:

  * **Class F.** `vfmadd*` becomes a multiply and an add: two roundings
    where the hardware did one, Finding 4, and the only rule in the design
    that is not semantics-preserving. A Class F case that DIFFERS is
    recorded; one that does not differ anywhere is reported too, because an
    exemption nothing exercises is an exemption nobody checked.
  * **The oracle's own defect.** qemu's softfloat returns SRC2's NaN where
    Intel returns SRC1's, and only when BOTH operands are NaN -- measured
    with `nanprobe.c`, and identical for the SSE and the VEX encodings, so
    it is qemu's arithmetic and not its VEX decoder. Elements where both
    inputs are NaN are counted and reported separately. They are the
    oracle's limit, not a finding about any lowering.

**It runs only where qemu-user is installed**, and says SKIPPED rather than
passing when it is not -- see `require_oracle`. `check-lowering` is the one
that runs everywhere and compares against GCC; the two are complementary and
both are worth keeping.

Usage:  vex_oracle.py [build directory]

`SABOTAGE=n` in the environment flips one bit of case n's lowered bytes, so
that the harness can be seen to fail. A check nobody has watched fail is a
check nobody has watched.
"""

import os
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour
import lowering_cases

QEMU = ["qemu-x86_64", "-cpu", "max"]
TIMEOUT = 300

REGISTERS = 16
SLOT = 16
SABOTAGE = int(os.environ.get("SABOTAGE", "-1"))
WORK = Path("build") / "vexoracle"

# Class F: two roundings replace one, so these are allowed to differ and
# `lowering_cases.FMAS` is the list rather than a second copy of it.
CLASS_F = frozenset(lowering_cases.FMAS)


def patterns():
	"""[(name, 256 bytes)] -- one 16-byte slot per xmm register.

	The harness loads xmm{r} from r*16(%rdi), which is
	`lowering_cases.emit`'s own convention, so a pattern is 16 registers
	laid end to end. Slots 0, 1 and 2 carry the operands every shape uses;
	the rest are bystanders whose only job is to still be there afterwards.
	"""
	out = []

	rolled = bytearray()
	state = 0x9E3779B97F4A7C15
	for _ in range(REGISTERS * SLOT):
		state = (state * 6364136223846793005 + 1442695040888963407) \
			& ((1 << 64) - 1)
		rolled.append((state >> 33) & 0xff)
	out.append(("random", bytes(rolled)))

	floats = [1.5, -2.25, 0.0, -0.0, 3.5e30, -7.75e-30, 1.0, 2.0,
	          -1.5, 4.0, 0.5, -0.25, 8.0, 1e-40, -3.0, 65536.0]
	blob = bytearray()
	for r in range(REGISTERS):
		for i in range(4):
			blob += struct.pack("<f", floats[(r * 4 + i) % len(floats)])
	out.append(("floats", bytes(blob)))

	blob = bytearray()
	for r in range(REGISTERS):
		blob += struct.pack("<dd", 1.5 + r, -0.25 * (r + 1))
	out.append(("doubles", bytes(blob)))

	blob = bytearray()
	for r in range(REGISTERS):
		for i in range(4):
			blob += struct.pack("<I", (0x80000000, 0x7fffffff, 0x00000001,
			                           0xffff0000)[i] ^ (r * 0x01010101))
	out.append(("edges", bytes(blob)))

	# One all-NaN pattern, deliberately: it is where the oracle's own
	# defect lives, so it must be present and must be counted rather than
	# quietly dropped.
	blob = bytearray()
	for r in range(REGISTERS):
		for i in range(4):
			blob += struct.pack("<I", 0x7fc00000 | (r * 4 + i + 1)
			                    | (0x80000000 if r & 1 else 0))
	out.append(("all_nan", bytes(blob)))

	# **Two patterns built to make Finding 4 visible.** The first run
	# exempted four Class F cases as "expected divergence" and every one of
	# them was really the all-NaN pattern: the two-roundings difference the
	# exemption exists for had never once been observed, so the exemption
	# was excusing something other than what it names. These triples were
	# searched for -- 600,000 candidates, and the winner diverges under all
	# twelve combinations of the three operand assignments (132 is
	# dst*src2+src1, 213 is src1*dst+src2, 231 is src1*src2+dst) with and
	# without the negation and the subtract. Slots 0, 1 and 2 are xmm0,
	# xmm1 and xmm2, which is what every FMA case names.
	for name, values, width, fmt in (
			("fma_f32", (0x3f9c8ead, 0x3fca329b, 0x3fc28053), 4, "<I"),
			("fma_f64", (0x3fff242097b43426, 0x3ff5effadb2139bd,
			             0x3ff3099835076ce1), 8, "<Q")):
		blob = bytearray()
		for r in range(REGISTERS):
			value = values[r] if r < 3 else (values[r % 3] ^ (r << 8))
			blob += struct.pack(fmt, value) * (SLOT // width)
		out.append((name, bytes(blob)))

	for name, data in out:
		assert len(data) == REGISTERS * SLOT, (name, len(data))
	return out


PATTERNS = patterns()


def collect():
	"""[(case, original encoding)] -- one pass, one list, no second copy."""
	recorded = []
	real = detour.lower_vex

	def recording(address, encoding, operands, mnemonic, at, scratch):
		body = real(address, encoding, operands, mnemonic, at, scratch=scratch)
		recorded.append((encoding, mnemonic, operands))
		return body

	detour.lower_vex = recording
	try:
		cases = lowering_cases.build()
	finally:
		detour.lower_vex = real
	if len(recorded) != len(cases):
		raise SystemExit(f"vex_oracle: recorded {len(recorded)} originals for "
		                 f"{len(cases)} cases -- the wrapper missed a path")
	return list(zip(cases, recorded))


def program(pairs, which):
	"""The asm: `which` selects the original bytes or the lowered ones.

	Both sides use `lowering_cases.emit`'s shape exactly -- all sixteen
	registers loaded from %rdi, the bytes under test, all sixteen stored to
	%rsi -- so the only difference between the two binaries is which
	encoding sits in the middle.
	"""
	lines = [".text"]
	for i, (case, (encoding, _mnemonic, _operands)) in enumerate(pairs):
		body = encoding if which == "vex" else case[-1]
		if which == "low" and i == SABOTAGE:
			body = bytes(body[:-1]) + bytes([body[-1] ^ 0x01])
		lines += [f".globl {which}_{i}", f".type {which}_{i}, @function",
		          f"{which}_{i}:"]
		for r in range(REGISTERS):
			lines.append(f"\tmovaps {r * SLOT}(%rdi), %xmm{r}")
		lines.append("\t.byte " + ", ".join(f"0x{b:02x}" for b in body))
		for r in range(REGISTERS):
			lines.append(f"\tmovaps %xmm{r}, {r * SLOT}(%rsi)")
		lines += ["\tret", ""]
	return "\n".join(lines) + "\n"


def data_source():
	lines = [".section .rodata", ".balign 32", ".globl inputs", "inputs:"]
	for name, blob in PATTERNS:
		lines.append(f"\t/* {name} */")
		lines.append("\t.byte " + ", ".join(f"0x{b:02x}" for b in blob))
	return "\n".join(lines) + "\n"


MAIN = r"""
#include <stdio.h>
#include <string.h>
extern const unsigned char inputs[];
typedef void (*fn)(const void *, void *);
static const fn table[] = { %s };
int main(void) {
	static unsigned char out[%d] __attribute__((aligned(32)));
	for (int c = 0; c < %d; c++) {
		for (int p = 0; p < %d; p++) {
			memset(out, 0x5a, sizeof out);
			table[c](inputs + p * %d, out);
			printf("%%d %%d ", c, p);
			for (int i = 0; i < %d; i++) printf("%%02x", out[i]);
			printf("\n");
		}
	}
	return 0;
}
"""


def main_source(prefix, count):
	span = REGISTERS * SLOT
	decls = "\n".join(f"void {prefix}_{i}(const void *, void *);"
	                  for i in range(count))
	table = ", ".join(f"{prefix}_{i}" for i in range(count))
	return decls + "\n" + MAIN % (table, span, count, len(PATTERNS), span, span)


def build(name, prefix, pairs, which):
	(WORK / f"{which}.s").write_text(program(pairs, which))
	(WORK / f"{name}.c").write_text(main_source(prefix, len(pairs)))
	done = subprocess.run(["gcc", "-Os", "-static", "-o", str(WORK / name),
	                       str(WORK / f"{name}.c"), str(WORK / f"{which}.s"),
	                       str(WORK / "data.s")],
	                      capture_output=True, text=True, timeout=TIMEOUT)
	if done.returncode != 0:
		print(done.stderr.rstrip()[-3000:], file=sys.stderr)
		raise SystemExit(f"vex_oracle: {name} did not build")


def run(name, under_qemu):
	done = subprocess.run((QEMU if under_qemu else []) + [str(WORK / name)],
	                      capture_output=True, text=True, timeout=TIMEOUT)
	if done.returncode != 0:
		print(done.stderr.rstrip()[-3000:], file=sys.stderr)
		raise SystemExit(f"vex_oracle: {name} exited {done.returncode}")
	rows = {}
	for line in done.stdout.splitlines():
		c, p, value = line.split()
		rows[(int(c), int(p))] = bytes.fromhex(value)
	return rows


def both_nan(a, b, width):
	"""Is every differing element a case where BOTH inputs were NaN?

	The oracle's defect is exactly there and nowhere else, so this is what
	separates "qemu is wrong" from "the lowering is wrong". It reads the
	OUTPUTS, since either side's output is a NaN in that case and the two
	NaNs differ -- an element where only one input was NaN has both sides
	agreeing already and never reaches here.
	"""
	fmt, mask, quiet = ("<I", 0x7f800000, 0x007fffff) if width == 4 \
		else ("<Q", 0x7ff0000000000000, 0x000fffffffffffff)
	assert width in (4, 8)
	for i in range(0, len(a), width):
		x = struct.unpack(fmt, a[i:i + width])[0]
		y = struct.unpack(fmt, b[i:i + width])[0]
		if x == y:
			continue
		if not ((x & mask) == mask and (x & quiet)
		        and (y & mask) == mask and (y & quiet)):
			return False
	return True


def require_oracle():
	"""qemu present, and able to run AVX2 -- or say so and skip.

	**Absent and working are different claims.** A harness that treats a
	missing qemu as a pass turns its own absence into evidence, which is
	the failure `evidence.md` names; one that treats it as a failure makes
	every machine without qemu-user look broken. So it reports which, and
	exits 77 -- the skip code -- rather than 0.
	"""
	import shutil
	if shutil.which(QEMU[0]) is None:
		print("no qemu-x86_64: install qemu-user. SKIPPED, not passed.",
		      file=sys.stderr)
		raise SystemExit(77)
	try:
		probe = subprocess.run(QEMU + ["-cpu", "help"], capture_output=True,
		                       text=True, timeout=60)
	except OSError as error:
		print(f"{QEMU[0]} will not run ({error}). SKIPPED, not passed.",
		      file=sys.stderr)
		raise SystemExit(77)
	if "avx2" not in probe.stdout:
		print("qemu-x86_64 reports no avx2 model. SKIPPED, not passed.",
		      file=sys.stderr)
		raise SystemExit(77)


def main():
	global WORK
	if len(sys.argv) > 1:
		WORK = Path(sys.argv[1]) / "vexoracle"
	require_oracle()
	WORK.mkdir(parents=True, exist_ok=True)
	pairs = collect()
	(WORK / "data.s").write_text(data_source())
	build("vexside", "vex", pairs, "vex")
	build("sseside", "low", pairs, "low")

	# **What proves the oracle is doing the work.** The same binary run
	# natively must die of an illegal instruction on a host without AVX; if
	# it does not, this machine has AVX and qemu was never the thing under
	# test. Either way the comparison below is sound -- the point of
	# printing it is that a reader can tell which machine they are on.
	print("== capability control ==")
	native = subprocess.run([str(WORK / "vexside")], capture_output=True,
	                        timeout=TIMEOUT)
	verdict = " (SIGILL -- this host has no AVX)" if native.returncode == -4 \
		else " -- this host executed VEX itself"
	print(f"   the VEX binary on this CPU: exit {native.returncode}{verdict}")

	vex, low = run("vexside", True), run("sseside", False)

	agree, classf, oracle, bad = 0, [], [], []
	scratch = lowering_cases.SCRATCH
	for c, (case, (_encoding, mnemonic, operands)) in enumerate(pairs):
		shape, lane = case[1], case[6]
		for p, (pname, _blob) in enumerate(PATTERNS):
			a, b = vex[(c, p)], low[(c, p)]
			# The scratch register is the one a lowering may destroy.
			a = a[:scratch * SLOT] + a[(scratch + 1) * SLOT:]
			b = b[:scratch * SLOT] + b[(scratch + 1) * SLOT:]
			if a == b:
				agree += 1
			elif mnemonic in CLASS_F:
				classf.append((mnemonic, shape, pname))
			# **The exemption is narrowed twice, because a wide one
			# excuses the bug it was written to describe.** It applies
			# only on the pattern where both operands are NaN by
			# construction -- qemu's defect exists nowhere else, measured
			# with nanprobe.c -- and only when every differing element is
			# a quiet NaN on both sides. The element width comes from the
			# mnemonic rather than from the Class F `lane` field, which is
			# zero for everything that is not an FMA and would have read a
			# double as two single-precision halves.
			elif pname == "all_nan" and both_nan(
					a, b, 8 if mnemonic.endswith(("sd", "pd")) else 4):
				oracle.append((mnemonic, shape, pname))
			else:
				bad.append((mnemonic, shape, pname, a.hex(), b.hex()))

	total = len(pairs) * len(PATTERNS)
	print(f"== {len(pairs)} cases x {len(PATTERNS)} patterns = {total} "
	      f"comparisons of 15 registers each ==")
	print(f"   identical                        {agree}")
	print(f"   Class F, two roundings (expected) {len(classf)}")
	print(f"   both operands NaN (oracle defect) {len(oracle)}")
	print(f"   UNEXPLAINED                       {len(bad)}")

	exercised = {row[0] for row in classf}
	unexercised = CLASS_F - exercised
	print(f"   Class F mnemonics that actually differed: "
	      f"{len(exercised)}/{len(CLASS_F)}")
	if unexercised:
		print(f"   Class F never differing (exemption unearned): "
		      f"{' '.join(sorted(unexercised))}")

	for row in classf:
		print(f"   class-F   {row[0]:14} {row[1]:14} {row[2]}")
	for row in oracle:
		print(f"   both-NaN  {row[0]:14} {row[1]:14} {row[2]}")

	for row in bad[:40]:
		print(f"   UNEXPLAINED {row[0]:14} {row[1]:14} {row[2]}")
		for r in range(REGISTERS - 1):
			x, y = row[3][r * 32:(r + 1) * 32], row[4][r * 32:(r + 1) * 32]
			if x != y:
				reg = r if r < scratch else r + 1
				print(f"      xmm{reg:<2} vex {x}\n           low {y}")
	return 1 if bad else 0


if __name__ == "__main__":
	raise SystemExit(main())
