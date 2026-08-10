#!/usr/bin/env python3
"""Build a small x86-64 PE that uses AVX, so the rewriter has a target it owns.

Milestone 2. Everything the rewriter does to Starfield is checked
structurally, because Starfield cannot be run here: it is a Windows binary
and this is Linux, and it wants AVX from a CPU that has none. A PE this
project builds itself is small enough to reason about completely and, under
wine, small enough to *run* -- and the same CPU that cannot execute the
input can execute the output.

That asymmetry is the test. The original must fail with an illegal
instruction, because the very first thing it does is an AVX instruction this
Westmere does not implement. The rewritten one must run and return the right
answer. Neither result is interesting alone; together they are the end-to-end
claim the whole project rests on.

There is no mingw here, so the PE is assembled with `as` and wrapped by
hand. That is less of a detour than it sounds: the file format work already
exists in tools/detour.py, which appends a section to a 102 MB PE without
disturbing it, and the headers below are the same fields read from the other
side.

**No imports and no relocations.** The entry point computes a number and
returns it, and returning from the entry of a PE terminates the thread with
that value as the exit code, so nothing needs `ExitProcess` and nothing
needs a CRT. DllCharacteristics is left at zero so the image is loaded at
its preferred base and no `.reloc` is required.

The layout is deliberately the shape the rewriter expects to find:

  * `.text` holds the code and, past it, the constants it loads
    RIP-relatively. A linear disassembly walks into those constants and
    decodes nonsense, which is exactly the situation `.pdata` exists to
    resolve -- and `.pdata` here covers the function only. If the rewriter
    patches a constant, the test says so.
  * `.pdata` and `.xdata` give the function the unwind data a non-leaf
    function must have, so `patch.function_ranges` sees it.

  names                    list the programs and their expected exit codes
  sample <name> <out.exe>  build one
"""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

IMAGE_BASE = 0x140000000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
HEADER_SIZE = 0x400

CODE = 0x60000020		# CODE | EXECUTE | READ
DATA = 0x40000040		# INITIALIZED_DATA | READ

# The programs. Each exists to exercise a piece of the REWRITER, not to
# vary the arithmetic -- tests/lowering_test.c already executes the lowerings
# themselves across 37 mnemonics. What only a whole binary can test is the
# machinery around them: windows, branch targets, RIP displacements moved
# into a stub, and the code oracle deciding what is code.
#
# Every one begins with `vzeroupper`, which is Class Z and must be erased
# rather than lowered: it has no SSE form and this CPU faults on it, so a
# program that runs at all proves it was removed.
#
# Exit codes are small and far apart on purpose. A wrong lowering should not
# be able to look like a rounding difference.

PROGRAMS = {}

# 1. The aliasing case, and the reason this file exists.
#
#     vsubss %xmm0,%xmm1,%xmm0   is dst = src1 - src2 with dst AND src2 both
#                                %xmm0 -- Finding 25.
#
# Lowered correctly that is 10 - 3 = 7 and the answer is 169. Lowered the way
# the bug did it -- movaps %xmm1,%xmm0 then subss %xmm0,%xmm0 -- it is 0 and
# the answer is 36.
PROGRAMS["aliasing"] = (169, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vxorps	%xmm3, %xmm3, %xmm3
	vmovss	three(%rip), %xmm0
	vmovss	ten(%rip), %xmm1
	vsubss	%xmm0, %xmm1, %xmm0	/* dst == src2: 10 - 3 = 7 */
	vmovss	six(%rip), %xmm2
	vaddss	%xmm2, %xmm0, %xmm0	/* 7 + 6 = 13 */
	vmulss	%xmm0, %xmm0, %xmm0	/* 169 */
	vaddss	%xmm3, %xmm0, %xmm0	/* + 0, so the zeroing idiom is used */
	vcvttss2si %xmm0, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
six:	.float 6.0
""")

# 2. A site whose own operand is memory, detoured. The stub executes at an
# address 12 KB from where the instruction was, so the RIP displacement has
# to be recomputed or the load reads the wrong bytes -- and reading the wrong
# bytes here gives an answer, not a crash, which is why it is worth a test.
PROGRAMS["memory"] = (16, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	ten(%rip), %xmm1
	vaddss	six(%rip), %xmm1, %xmm0	/* Class C, src2 in memory: 10 + 6 */
	vcvttss2si %xmm0, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
ten:	.float 10.0
six:	.float 6.0
""")

# 3. A four-byte site with a branch target immediately after it, which is
# the case forward widening MUST refuse: swallowing that instruction would
# leave the jump landing in the middle of the five-byte jump that replaced
# it. Backward widening takes it instead, over the `nop` in front.
#
# The branch is taken at run time, so the target really is entered. If the
# rewriter swallowed it anyway the program does not merely compute the wrong
# number, it jumps into the middle of an instruction.
PROGRAMS["branch"] = (6, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	three(%rip), %xmm0
	vmovss	ten(%rip), %xmm1
	xorl	%ecx, %ecx
	cmpl	$0, %ecx
	je	skip			/* taken */
	nop				/* what the window widens backwards over */
	vsubss	%xmm0, %xmm1, %xmm0	/* four bytes, and skipped at run time */
skip:
	vaddss	%xmm0, %xmm0, %xmm0	/* 3 + 3 = 6; this is the branch target */
	vcvttss2si %xmm0, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
""")


# 4. A 256-bit copy, and a read back from the UPPER half of it. This is the
# Y1 case, and the only thing that can prove it: if the pair is lowered as
# two 128-bit moves the top sixteen bytes are never written, and the read at
# offset 16 returns whatever was on the stack instead of 91.
#
# It also proves the ORDER inside the lowering. Emitting the low half last
# is what leaves the register holding the low sixteen bytes; get it backwards
# and this still copies correctly, so the program is deliberately not the
# whole test -- tests/lowering_test.c cannot reach ymm at all, and the
# ordering argument is carried by lower_ymm_pair's comment and Finding 38.
PROGRAMS["ymm"] = (91, """
	.text
	.globl _start
_start:
	subq	$72, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* 32 bytes in ... */
	vmovups	%ymm0, (%rdi)		/* ... and back out: the Y1 pair */
	movl	16(%rdi), %eax		/* from the upper half */
	addq	$72, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 91, 6, 7, 8
""")



# 5. A 256-bit store of a register a VEX.128 zeroing idiom emptied, over a
# buffer poisoned first. `vpxor %xmm0,%xmm0,%xmm0` zeroes bits [255:128] of
# ymm0 as well -- that is what VEX.128 does -- so the store writes 32 zero
# bytes without any 256-bit value ever being produced.
#
# The poison is the whole test. Read back the low half, the high half, and
# the LAST dword of the high half, and or them together: a truncated store
# leaves 0x5a5a5a5a in the top sixteen bytes, and an off-by-sixteen leaves it
# in the last four. Only 32 bytes of zeroes give 77.
PROGRAMS["zerofill"] = (77, """
	.text
	.globl _start
_start:
	subq	$72, %rsp
	vzeroupper
	movq	%rsp, %rdi
	movl	$0x5a5a5a5a, (%rdi)
	movl	$0x5a5a5a5a, 4(%rdi)
	movl	$0x5a5a5a5a, 8(%rdi)
	movl	$0x5a5a5a5a, 12(%rdi)
	movl	$0x5a5a5a5a, 16(%rdi)
	movl	$0x5a5a5a5a, 20(%rdi)
	movl	$0x5a5a5a5a, 24(%rdi)
	movl	$0x5a5a5a5a, 28(%rdi)
	vpxor	%xmm0, %xmm0, %xmm0	/* all 256 bits of ymm0, not the low half */
	vmovups	%ymm0, (%rdi)		/* 32 zero bytes over the poison */
	movl	(%rdi), %eax
	orl	16(%rdi), %eax
	orl	28(%rdi), %eax
	addl	$77, %eax
	addq	$72, %rsp
	ret
func_end:
	.p2align 5
""")



# 6. An unrolled copy: two 256-bit pairs through the same ymm. The first
# pair's upper half is dead, because the second pair's load replaces all 256
# bits of the register without reading any of them -- but the scan used to
# see the mention and refuse.
#
# Refused, the first load stays VEX and the program dies of an illegal
# instruction rather than returning a wrong number, so this is a test of
# whether the rule fires at all. Both upper halves are read back, which is
# what makes it a test of the lowering as well: 40 + 30.
PROGRAMS["unrolled"] = (70, """
	.text
	.globl _start
_start:
	subq	$104, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* the first pair ... */
	vmovups	%ymm0, (%rdi)
	vmovups	32(%rsi), %ymm0		/* ... whole-register overwrite ... */
	vmovups	%ymm0, 32(%rdi)		/* ... and the second */
	movl	16(%rdi), %eax		/* upper half of the first copy: 40 */
	addl	48(%rdi), %eax		/* upper half of the second: 30 */
	addq	$104, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 40, 6, 7, 8
	.long 9, 10, 11, 12
	.long 30, 14, 15, 16
""")


def assemble(source):
	"""(raw .text bytes, offset of func_end) for one assembly source."""
	with tempfile.TemporaryDirectory() as tmp:
		asm, obj, bin_ = (Path(tmp) / n for n in ("p.s", "p.o", "p.bin"))
		asm.write_text(source)
		done = subprocess.run(["as", "--64", "-o", str(obj), str(asm)],
		                      capture_output=True, text=True)
		if done.returncode != 0:
			print(done.stderr.rstrip(), file=sys.stderr)
			raise SystemExit(1)
		subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
		                str(obj), str(bin_)], check=True)
		symbols = subprocess.run(["objdump", "-t", str(obj)],
		                         capture_output=True, text=True).stdout
		end = None
		for line in symbols.splitlines():
			if line.endswith(" func_end"):
				end = int(line.split()[0], 16)
		if end is None:
			raise SystemExit("pe_build: func_end not found")
		return bin_.read_bytes(), end


def align(value, to):
	return (value + to - 1) // to * to


def build(path, text, code_size):
	"""Write a PE whose entry point is the start of `text`."""
	# .xdata first, because .pdata points into it. A minimal UNWIND_INFO:
	# version 1, no flags, no prolog, no unwind codes. Nothing here ever
	# unwinds; it exists so the function HAS unwind data, which is what
	# puts it in .pdata and therefore in the rewriter's code oracle.
	xdata = struct.pack("<BBBB", 1, 0, 0, 0)

	sections = []
	rva = SECTION_ALIGNMENT
	offset = HEADER_SIZE
	for name, body, flags in ((b".text", text, CODE),
	                          (b".xdata", xdata, DATA),
	                          (b".pdata", None, DATA)):
		if name == b".pdata":
			# RUNTIME_FUNCTION: begin, end, unwind info -- all RVAs.
			text_rva = sections[0][1]
			xdata_rva = sections[1][1]
			body = struct.pack("<III", text_rva, text_rva + code_size,
			                   xdata_rva)
		sections.append((name, rva, offset, body, flags))
		rva = align(rva + len(body), SECTION_ALIGNMENT)
		offset += align(len(body), FILE_ALIGNMENT)

	image = bytearray(HEADER_SIZE)
	image[0:2] = b"MZ"
	struct.pack_into("<I", image, 0x3C, 0x40)
	pe = 0x40
	image[pe:pe + 4] = b"PE\0\0"
	# COFF: x86-64, three sections, executable, large address aware.
	struct.pack_into("<HHIIIHH", image, pe + 4,
	                 0x8664, len(sections), 0, 0, 0, 240, 0x0022)
	opt = pe + 24
	code_bytes = align(len(text), FILE_ALIGNMENT)
	data_bytes = sum(align(len(b), FILE_ALIGNMENT)
	                 for _n, _r, _o, b, f in sections if f == DATA)
	struct.pack_into("<HBBIIIIII", image, opt,
	                 0x20B, 14, 0,		# PE32+, linker version
	                 code_bytes, data_bytes, 0,
	                 sections[0][1],	# entry point RVA
	                 sections[0][1], 0)	# base of code, unused word
	struct.pack_into("<Q", image, opt + 24, IMAGE_BASE)
	struct.pack_into("<II", image, opt + 32, SECTION_ALIGNMENT, FILE_ALIGNMENT)
	# OS 6.0, image 0.0, subsystem 6.0, reserved.
	struct.pack_into("<HHHHHHI", image, opt + 40, 6, 0, 0, 0, 6, 0, 0)
	struct.pack_into("<II", image, opt + 56,
	                 align(sections[-1][1] + len(sections[-1][3]),
	                       SECTION_ALIGNMENT),
	                 HEADER_SIZE)
	# Checksum 0, console subsystem, DllCharacteristics 0 -- no ASLR, so
	# the image loads at IMAGE_BASE and needs no relocations.
	struct.pack_into("<IHH", image, opt + 64, 0, 3, 0)
	struct.pack_into("<QQQQ", image, opt + 72,
	                 0x100000, 0x1000, 0x100000, 0x1000)
	struct.pack_into("<II", image, opt + 104, 0, 16)
	# Data directory 3 is the exception table, which is .pdata.
	struct.pack_into("<II", image, opt + 112 + 3 * 8,
	                 sections[2][1], len(sections[2][3]))

	table = opt + 240
	for i, (name, section_rva, section_offset, body, flags) in \
			enumerate(sections):
		entry = table + i * 40
		image[entry:entry + 8] = name.ljust(8, b"\0")
		struct.pack_into("<IIII", image, entry + 8,
		                 len(body), section_rva,
		                 align(len(body), FILE_ALIGNMENT), section_offset)
		struct.pack_into("<IIHHI", image, entry + 24, 0, 0, 0, 0, flags)

	for _name, _rva, section_offset, body, _flags in sections:
		if len(image) < section_offset:
			image += bytes(section_offset - len(image))
		image[section_offset:section_offset + len(body)] = body
		pad = align(len(body), FILE_ALIGNMENT) - len(body)
		image += bytes(pad) if section_offset + len(body) == len(image) else b""
	total = sections[-1][2] + align(len(sections[-1][3]), FILE_ALIGNMENT)
	if len(image) < total:
		image += bytes(total - len(image))
	Path(path).write_bytes(bytes(image))
	return sections


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	if argv[0] == "names":
		for name, (code, _source) in PROGRAMS.items():
			print(f"{name} {code}")
		return 0
	if argv[0] != "sample":
		print(f"pe_build.py: unknown mode {argv[0]!r}", file=sys.stderr)
		return 2
	name, output = argv[1], argv[2]
	if name not in PROGRAMS:
		print(f"pe_build.py: no program {name!r}", file=sys.stderr)
		return 2
	expected, source = PROGRAMS[name]
	text, code_size = assemble(source)
	sections = build(output, text, code_size)
	print(f"pe_build: {name} -> {output}, {len(text)} bytes of .text, "
	      f"function is {code_size} of them, expected exit code {expected}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
