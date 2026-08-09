#!/usr/bin/env python3
"""Generate executable test cases from the real lowering rules.

`lower.py verify` proves every lowering assembles and leaves no VEX prefix.
That is a statement about *shape*, and the src2-aliasing bug of Finding 25
passed it while computing a constant zero -- so shape is not enough. What
was never tested is whether a lowering computes the same thing the AVX
instruction computed.

**This machine can run the output but not the input.** It is a Westmere:
SSE4.2 and no AVX, which is the whole reason the project exists. So the
reference cannot be the original instruction executed -- it has to come from
somewhere else, and it comes from GCC compiling the equivalent SSE
intrinsic. That is a genuinely separate producer: a different encoder, a
different register allocator, and a compiler that has no idea what this
project thinks the answer is.

What is generated, per case:

  * the VEX instruction, assembled by `as` -- which encodes AVX happily on a
    CPU that cannot execute it;
  * its lowering, from `detour.lower_vex`, the same function the rewriter
    calls;
  * a function that loads all sixteen xmm registers from memory, executes
    the lowered bytes, and stores all sixteen back.

Storing all sixteen is deliberate. The destination has to hold the right
answer, and **every other register has to be untouched** -- a lowering that
gets the arithmetic right and clobbers a bystander is still wrong, and only
comparing the destination would miss it. The scratch register is the one
exception, since a lowering is entitled to destroy it.

Three operand shapes per mnemonic, because the aliasing is the whole point:

    distinct      op %xmm2,%xmm1,%xmm0     Class C
    dst_is_src1   op %xmm2,%xmm0,%xmm0     Class B
    dst_is_src2   op %xmm0,%xmm1,%xmm0     the Finding 25 case

  emit <asm> <table>
"""

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import detour
import patch as inplace

# Mnemonics with a direct SSE form, chosen to cover what can go wrong rather
# than to be exhaustive: commutative and not, scalar and packed, single and
# double, float and integer, with an immediate and without. Every one needs
# a reference in tests/lowering_test.c or the test fails rather than skips.
CASES = [
	"vaddss", "vaddps", "vaddsd", "vaddpd",
	"vsubss", "vsubps", "vsubsd", "vsubpd",
	"vmulss", "vmulps", "vdivss", "vdivps",
	"vminss", "vminps", "vmaxss", "vmaxps",
	"vandps", "vandnps", "vorps", "vxorps",
	"vunpcklps", "vunpckhps", "vunpcklpd",
	"vpand", "vpandn", "vpor", "vpxor",
	"vpaddd", "vpsubd", "vpcmpeqd", "vpcmpgtd", "vpunpckldq",
	"vmovss", "vmovsd",
	"vshufps $0x1b", "vcmpltps", "vcmpless",
]

# The destination is always xmm0, so the harness knows where to look, and
# the scratch is always xmm15, so it knows what to forgive.
DESTINATION = 0
SCRATCH = 15

# The shift-by-immediate forms, whose destination is in vvvv and whose
# modrm.rm is therefore the SOURCE. They print as imm, src, dst -- two
# registers, not three -- so they need shapes of their own. A distinct
# immediate per mnemonic keeps one reference per entry.
SHIFTS = [("vpsrld", "$0x2"), ("vpslld", "$0x3"), ("vpsrlq", "$0x5"),
          ("vpsllq", "$0x1"), ("vpsrad", "$0x4"), ("vpsrldq", "$0x4"),
          ("vpslldq", "$0x2"), ("vpsrlw", "$0x1"), ("vpsllw", "$0x2")]

# (name, source register) for a shift: the destination is always xmm0, so
# "same" is the case patch.py takes in place and "distinct" is the one that
# needs the source copied first.
SHIFT_SHAPES = [("distinct", 1), ("same", 0)]

# (name, src2, src1) -- AT&T order is src2, src1, dst.
SHAPES = [
	("distinct", 2, 1),
	("dst_is_src1", 2, 0),
	("dst_is_src2", 0, 1),
]


def assemble(lines):
	"""Assemble AT&T source and return objdump's view of each instruction."""
	with tempfile.TemporaryDirectory() as tmp:
		asm, obj, listing = (Path(tmp) / n for n in ("t.s", "t.o", "t.txt"))
		asm.write_text(".text\n" + "".join(f"\t{line}\n" for line in lines))
		done = subprocess.run(["as", "--64", "-o", str(obj), str(asm)],
		                      capture_output=True, text=True)
		if done.returncode != 0:
			print(done.stderr.rstrip(), file=sys.stderr)
			raise SystemExit(1)
		listing.write_text(subprocess.run(["objdump", "-d", str(obj)],
		                                  capture_output=True,
		                                  text=True).stdout)
		return list(inplace.parse_listing(str(listing)))


def build():
	"""[(mnemonic, shape, src1, src2, lowered bytes)] for every case."""
	wanted = []
	for case in CASES:
		mnemonic, _, immediate = case.partition(" ")
		for shape, source2, source1 in SHAPES:
			operands = f"%xmm{source2},%xmm{source1},%xmm{DESTINATION}"
			text = f"{mnemonic} {immediate + ',' if immediate else ''}{operands}"
			wanted.append((mnemonic, shape, source1, source2, text))

	for mnemonic, immediate in SHIFTS:
		for shape, source in SHIFT_SHAPES:
			text = f"{mnemonic} {immediate},%xmm{source},%xmm{DESTINATION}"
			# Both source slots name the same register: a shift has one.
			wanted.append((mnemonic, shape, source, source, text))

	assembled = assemble([text for *_rest, text in wanted])
	if len(assembled) != len(wanted):
		raise SystemExit(f"assembled {len(assembled)} of {len(wanted)} cases")

	out = []
	for (mnemonic, shape, source1, source2, _text), site in zip(wanted,
	                                                            assembled):
		address, encoding, printed, operands = site
		body = detour.lower_vex(address, encoding, operands, printed, 0,
		                        scratch=SCRATCH)
		if body is None:
			raise SystemExit(f"no lowering for {printed} {operands} "
			                 f"({shape}) -- the generator must not skip")
		out.append((mnemonic, shape, source1, source2, body))
	return out


def emit(cases, asm_path, table_path):
	asm = [".text"]
	for i, (_m, _s, _a, _b, body) in enumerate(cases):
		asm.append(f".globl case_{i}")
		asm.append(f".type case_{i}, @function")
		asm.append(f"case_{i}:")
		# Every register loaded, so that "nothing else changed" can be
		# checked; rdi and rsi are untouched by any lowering here.
		for r in range(16):
			asm.append(f"\tmovaps {r * 16}(%rdi), %xmm{r}")
		asm.append("\t/* the lowering under test */")
		asm.append("\t.byte " + ", ".join(f"0x{b:02x}" for b in body))
		for r in range(16):
			asm.append(f"\tmovaps %xmm{r}, {r * 16}(%rsi)")
		asm.append("\tret")
		asm.append("")
	Path(asm_path).write_text("\n".join(asm) + "\n")

	table = ["/* Generated by tools/lowering_cases.py -- do not edit. */",
	         f"#define LOWERING_DESTINATION {DESTINATION}",
	         f"#define LOWERING_SCRATCH {SCRATCH}",
	         f"#define LOWERING_CASES {len(cases)}", ""]
	for i, _case in enumerate(cases):
		table.append(f"void case_{i}(const void *in, void *out);")
	table.append("")
	table.append("static const struct lowering_case lowering_table[] = {")
	for i, (mnemonic, shape, source1, source2, body) in enumerate(cases):
		table.append(f'\t{{ "{mnemonic}", "{shape}", {source1}, {source2}, '
		             f'{len(body)}, case_{i} }},')
	table.append("};")
	Path(table_path).write_text("\n".join(table) + "\n")


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	if argv[0] != "emit":
		print(f"lowering_cases.py: unknown mode {argv[0]!r}", file=sys.stderr)
		return 2
	cases = build()
	emit(cases, argv[1], argv[2])
	print(f"lowering_cases: {len(cases)} cases from {len(CASES)} mnemonics")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
