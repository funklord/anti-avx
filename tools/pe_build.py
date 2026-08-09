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

  sample <out.exe>     build the AVX test program
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

# The program. Every arithmetic step is AVX, and the subtract is written in
# the one operand shape that has already been got wrong once:
#
#     vsubss %xmm0,%xmm1,%xmm0    is  dst = src1 - src2, with dst AND src2
#                                 both %xmm0 -- Finding 25's aliasing case.
#
# Lowered correctly that is 10 - 3 = 7, and the program returns 169. Lowered
# the way the bug did it -- movaps %xmm1,%xmm0 then subss %xmm0,%xmm0 -- it
# is 0, and the program returns 36. The two answers are far apart on purpose:
# a wrong lowering here cannot look like a rounding difference.
PROGRAM = """
	.text
	.globl _start
_start:
	subq	$40, %rsp		/* non-leaf: it must have unwind data */
	vxorps	%xmm3, %xmm3, %xmm3
	vmovss	three(%rip), %xmm0
	vmovss	ten(%rip), %xmm1
	vsubss	%xmm0, %xmm1, %xmm0	/* dst == src2: 10 - 3 = 7 */
	vmovss	six(%rip), %xmm2
	vaddss	%xmm2, %xmm0, %xmm0	/* 7 + 6 = 13 */
	vmulss	%xmm0, %xmm0, %xmm0	/* 13 * 13 = 169 */
	vaddss	%xmm3, %xmm0, %xmm0	/* + 0, so the zeroing idiom is used */
	vcvttss2si %xmm0, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
six:	.float 6.0
"""


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
	if argv[0] != "sample":
		print(f"pe_build.py: unknown mode {argv[0]!r}", file=sys.stderr)
		return 2
	text, code_size = assemble(PROGRAM)
	sections = build(argv[1], text, code_size)
	print(f"pe_build: {argv[1]}, {len(text)} bytes of .text, "
	      f"function is {code_size} of them")
	for name, rva, offset, body, _flags in sections:
		print(f"  {name.decode():<8} rva 0x{rva:x}  file 0x{offset:x}  "
		      f"{len(body)} bytes")
	print("  expected exit code 169; a wrong aliasing lowering gives 36")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
