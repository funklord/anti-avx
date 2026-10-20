#!/usr/bin/env python3
"""Run every register-only VEX shape the binary contains against its lowering.

`shape_census` says which shapes exist and whether the lowering produces
BYTES for them. This says whether those bytes compute the same thing, which
is the question that matters and the one no hand-written case list can ask
about a shape nobody wrote down.

The original runs under `qemu-x86_64`, which decodes VEX on a host that has
none; the lowering runs natively, because the lowering is SSE and that is
the project's premise. Both load all sixteen xmm registers from a buffer,
execute, and store all sixteen back. Everything but the scratch register
must agree bit for bit.

**Register-only shapes, and the restriction is honest rather than
convenient.** A real instruction's memory operand points into the binary --
a RIP displacement to a constant, or a base register the harness does not
control -- and making one runnable means rewriting the operand, at which
point the thing under test is no longer the instruction the program
contains. `vex_oracle` covers memory operands with synthesised cases whose
addresses it owns. This covers what that cannot: the actual aliasing
patterns, at the actual widths, that this binary actually has.

The scratch register is excluded from the comparison because a lowering may
destroy it -- that is what it is for.

Usage:  shape_oracle.py <listing> [build directory]
"""

import collections
import subprocess
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour
import patch as inplace
import scratch as scratch_finder
import shape_census

WORK = Path("build") / "shapeoracle"
QEMU = ["qemu-x86_64", "-cpu", "max"]
TIMEOUT = 600
REGISTERS = 16
SLOT = 16


def patterns():
	"""[(name, 256 bytes)] -- one value per xmm register.

	Three, and each is here for a reason. `counter` makes every register
	and every lane distinguishable, so a lowering that moves the right
	bytes to the wrong place is visible. `floats` gives the FP mnemonics
	something with an exponent to disagree about. `edges` carries the
	sign bits and the all-ones patterns the bitwise forms turn into
	something else.
	"""
	out = []
	out.append(("counter", bytes((i * 7 + 3) & 0xFF
	                             for i in range(REGISTERS * SLOT))))
	values = []
	for i in range(REGISTERS * SLOT // 4):
		values.append(struct.pack("<f", (i % 13) - 6.5 + 0.25 * (i % 5)))
	out.append(("floats", b"".join(values)))
	edge = struct.pack("<IIII", 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF, 0)
	out.append(("edges", edge * REGISTERS))
	for name, blob in out:
		assert len(blob) == REGISTERS * SLOT, (name, len(blob))
	return out


PATTERNS = patterns()


def cases(listing, limit=None):
	"""[(shape, encoding, mnemonic, operands, lowered, scratch)].

	One example per shape, register operands only, and only where the
	lowering does not depend on the constant pool -- which is detected by
	lowering the same instruction at two different pool addresses and
	seeing whether the bytes move. A pool-dependent lowering reads memory
	this harness does not have, and running it would measure the harness.
	"""
	seen = {}
	for address, encoding, mnemonic, operands in inplace.parse_listing(
			listing):
		shape = shape_census.shape_of(encoding, mnemonic, operands)
		if shape is None or "mem" in shape or shape not in seen:
			if shape is None or "mem" in shape:
				continue
		seen.setdefault(shape, (address, encoding, mnemonic, operands))
	out = []
	for shape, (address, encoding, mnemonic, operands) in sorted(
			seen.items()):
		# **Nothing that names a general-purpose register.** This harness
		# holds its output pointer in %rsi and compares xmm state, so an
		# instruction writing a GPR overwrites the pointer and faults --
		# `vpextrd $0x2,%xmm2,%esi` did, and took the run down at shape
		# 206 of 319 with both sides stopping at the same line. It is
		# outside what this can check rather than a lowering fault, and
		# `vex_oracle`'s synthesised cases are where such a shape belongs.
		# **`vblendv` is run like everything else.** It was skipped here as
		# not self-contained -- SSE takes the mask in an implicit xmm0 --
		# but `lower_blendv` saves and restores xmm0 itself, in the
		# scratch this harness already excludes. The skip hid the shape
		# 1,018 sites have, mask and destination both xmm0, which the
		# lowering got wrong. Finding 360.
		fields = inplace.split_operands(operands or "")
		if any(f.startswith("%") and not f.startswith(("%xmm", "%ymm"))
		       for f in fields):
			continue
		used = set(scratch_finder.xmm_numbers(operands or ""))
		free = next((n for n in range(REGISTERS) if n not in used), None)
		if free is None:
			continue
		try:
			one = detour.lower_vex(address, encoding, operands, mnemonic,
			                       address, scratch=free, pool=address)
			two = detour.lower_vex(address, encoding, operands, mnemonic,
			                       address, scratch=free,
			                       pool=address + 0x10000)
		except Exception:					# noqa: BLE001
			continue
		if one is None or one != two:
			# None: no lowering. Different: it reads the pool, and this
			# harness has no pool to give it.
			continue
		# **Is the lowering a pure prefix strip?** If the bytes are the
		# same instruction with the VEX prefix replaced by the legacy
		# escape, then it IS the same instruction, and a difference in
		# what it computes is the two executors disagreeing rather than
		# anything this project wrote. That is a checkable property, not
		# a list of mnemonics to forgive -- and the difference matters,
		# because a forgiving list grows to cover the bug it was written
		# to describe. Finding 119 met the same question with qemu's NaN
		# defect and answered it by narrowing twice.
		vex = inplace.decode_vex(encoding)
		strip = None
		if vex is not None:
			try:
				strip = inplace.sse_encoding(dict(vex, L=0),
				                             encoding[vex["length"]:])
			except Exception:				# noqa: BLE001
				strip = None
		out.append((shape, encoding, mnemonic, operands, one, free,
		            strip is not None and one == strip))
		if limit and len(out) >= limit:
			break
	return out


def program(rows, which):
	"""The asm. Each function loads 16 xmm from %rdi, runs, stores to %rsi."""
	lines = [".text"]
	for i, (_shape, encoding, _m, _o, lowered, _s, _strip) in enumerate(rows):
		body = encoding if which == "vex" else lowered
		lines += [f".globl {which}_{i}", f".type {which}_{i}, @function",
		          f"{which}_{i}:"]
		for r in range(REGISTERS):
			lines.append(f"\tmovups\t{r * SLOT}(%rdi), %xmm{r}")
		lines.append("\t.byte " + ", ".join(str(b) for b in body))
		for r in range(REGISTERS):
			lines.append(f"\tmovups\t%xmm{r}, {r * SLOT}(%rsi)")
		lines += ["\tvzeroupper" if which == "vex" else "", "\tret", ""]
	return "\n".join(line for line in lines if line != "") + "\n"


MAIN = r"""
#include <stdio.h>
#define COUNT %d
#define PATTERNS %d
#define WIDE %d
extern const unsigned char inputs[];
typedef void (*fn)(const void *in, void *out);
%s
static const fn table[] = { %s };
int main(void) {
	static unsigned char out[WIDE];
	for (int c = 0; c < COUNT; c++)
		for (int p = 0; p < PATTERNS; p++) {
			table[c](inputs + p * WIDE, out);
			for (int i = 0; i < WIDE; i++) printf("%%02x", out[i]);
			printf("\n");
		}
	return 0;
}
"""


def data_source():
	lines = [".section .rodata", ".balign 32", ".globl inputs", "inputs:"]
	for name, blob in PATTERNS:
		lines.append(f"\t/* {name} */")
		lines.append("\t.byte " + ", ".join(f"0x{b:02x}" for b in blob))
	return "\n".join(lines) + "\n"


def build(name, rows, which):
	WORK.mkdir(parents=True, exist_ok=True)
	(WORK / f"{name}.s").write_text(program(rows, which))
	(WORK / "data.s").write_text(data_source())
	# **Every function needs a declaration as well as a name.** The table
	# is C and the bodies are assembly, so the compiler has to be told
	# they exist; without it the table is 318 undeclared identifiers and
	# nothing builds.
	names = [f"{which}_{i}" for i in range(len(rows))]
	decls = "\n".join(f"extern void {n}(const void *in, void *out);"
	                  for n in names)
	(WORK / f"{name}.c").write_text(
		MAIN % (len(rows), len(PATTERNS), REGISTERS * SLOT, decls,
		        ", ".join(names)))
	binary = WORK / name
	subprocess.run(["gcc", "-Os", "-o", str(binary), str(WORK / f"{name}.c"),
	                str(WORK / f"{name}.s"), str(WORK / "data.s")],
	               check=True, timeout=TIMEOUT)
	return binary


def run(binary, under_qemu):
	done = subprocess.run((QEMU if under_qemu else []) + [str(binary)],
	                      capture_output=True, text=True, timeout=TIMEOUT)
	return done.stdout.split()


def require_oracle():
	"""qemu present, able to start, and able to run AVX2.

	One implementation for all four oracles, in `detour`, because
	four copies of this guard have been wrong twice: once asking
	presence where the others asked capability, and once blaming a
	missing AVX2 model for a qemu that produced no output at all.
	"""
	detour.require_qemu(QEMU)


def main():
	global WORK
	if len(sys.argv) < 2:
		print("usage: shape_oracle.py <listing> [build directory]",
		      file=sys.stderr)
		return 2
	if len(sys.argv) > 2:
		WORK = Path(sys.argv[2]) / "shapeoracle"
	require_oracle()
	rows = cases(sys.argv[1])
	if not rows:
		print("shape_oracle: no runnable shape found, which means the "
		      "listing or the filter is wrong rather than that the binary "
		      "is simple", file=sys.stderr)
		return 2
	print(f"== {len(rows)} register-only shapes, each an instruction this "
	      f"binary contains ==")

	vex_binary = build("vexside", rows, "vex")
	sse_binary = build("sseside", rows, "low")

	native = subprocess.run([str(vex_binary)], capture_output=True,
	                        timeout=TIMEOUT)
	print(f"   capability control: the VEX binary natively exits "
	      f"{native.returncode}"
	      f"{' (SIGILL -- this host has no AVX)' if native.returncode == -4 else ' -- THIS HOST RAN VEX'}")
	if native.returncode != -4:
		print("shape_oracle: FAILED -- this host executed VEX, so qemu was "
		      "never the thing under test", file=sys.stderr)
		return 1

	vex, low = run(vex_binary, True), run(sse_binary, False)
	# **The lowering under qemu as well**, which is what turns a
	# disagreement into a verdict. If the original and the lowering agree
	# when ONE executor runs both, the lowering computes the right answer
	# and the difference against native silicon is the two executors
	# disagreeing about the instruction. That is a direct proof rather
	# than the inference the prefix-strip test makes, and it subsumes it:
	# identical bytes trivially agree with themselves.
	same = run(build("lowqemu", rows, "low"), True)
	if len(vex) != len(low) or len(same) != len(low) \
			or len(vex) != len(rows) * len(PATTERNS):
		print(f"shape_oracle: FAILED -- {len(vex)} vex lines and {len(low)} "
		      f"sse for {len(rows) * len(PATTERNS)} expected",
		      file=sys.stderr)
		return 1

	agree, differ, executor = 0, collections.Counter(), collections.Counter()
	detail = {}
	for c, row in enumerate(rows):
		scratch = row[5]
		for p, (pname, _blob) in enumerate(PATTERNS):
			c_index = c * len(PATTERNS) + p
			a, b = vex[c_index], low[c_index]
			# The scratch register is the one a lowering may destroy.
			cut = slice(scratch * SLOT * 2, (scratch + 1) * SLOT * 2)
			a = a[:cut.start] + a[cut.stop:]
			b = b[:cut.start] + b[cut.stop:]
			# **`q` and not `c`.** The first version named this `c`,
			# which is the enumerate index two lines above -- so the
			# second pattern of the first shape indexed a string and the
			# run died. Shadowing a loop variable inside its own body.
			q = same[c_index]
			q = q[:cut.start] + q[cut.stop:]
			if a == b:
				agree += 1
			elif a == q:
				# One executor ran both and they agreed, so the lowering
				# is right and the difference against native silicon is
				# qemu -- an approximate reciprocal, or a NaN the manual
				# leaves implementation-specific.
				executor[row[0]] += 1
				detail.setdefault(row[0], (pname, a, b))
			else:
				differ[row[0]] += 1
				detail.setdefault(row[0], (pname, a, b))
	total = len(rows) * len(PATTERNS)
	print(f"   {agree:,}/{total:,} comparisons agree bit for bit")
	if executor:
		print(f"   {sum(executor.values())} disagreement(s) where ONE "
		      f"executor running both sides agreed, so the lowering is "
		      f"right and qemu and this CPU differ:")
		for shape, count in executor.most_common(10):
			print(f"     {shape}  ({count} pattern(s), "
			      f"{detail[shape][0]})")
	for shape, count in differ.most_common(12):
		pname, a, b = detail[shape]
		print(f"   DIFFER {shape}  ({count} pattern(s), e.g. {pname})",
		      file=sys.stderr)
		print(f"          vex {a[:64]}...\n          sse {b[:64]}...",
		      file=sys.stderr)
	if differ:
		print(f"shape_oracle: FAILED -- {len(differ)} shape(s) lower to "
		      f"something that computes a different answer", file=sys.stderr)
		return 1
	print(f"shape_oracle: every one of {len(rows)} shapes lowers to SSE that "
	      f"computes what the VEX original computes")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
