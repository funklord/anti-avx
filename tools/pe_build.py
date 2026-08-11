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

# WRITE is here so that a program can store into its own data, which sits
# after `func_end` in `.text` because `objcopy --only-section=.text` is what
# extracts the assembled program and a symbol in another section would have
# no address at assembly time. A RIP-relative 256-bit store cannot be tested
# at all without somewhere legal to land, and the displacement arithmetic
# does not care which section the target is in -- Starfield's own are into
# `.data`, and its `.text` is not writable.
CODE = 0xE0000020		# CODE | EXECUTE | READ | WRITE
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



# 7. A pair whose use is on the far side of a conditional branch. Both
# successors reach a `ret` without naming the ymm, so the upper half is dead
# on every path -- but only a scan that follows the edges can say so.
#
# Stopping at the branch refuses the pair, the load stays VEX, and the
# program dies of an illegal instruction rather than returning 55.
PROGRAMS["crossblock"] = (55, """
	.text
	.globl _start
_start:
	subq	$104, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* the pair ... */
	vmovups	%ymm0, (%rdi)
	xorl	%ecx, %ecx
	testl	%ecx, %ecx
	jne	other			/* ... and a branch before its use */
	movl	16(%rdi), %eax		/* upper half of the copy: 55 */
	addq	$104, %rsp
	ret
other:
	movl	$1, %eax
	addq	$104, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 55, 6, 7, 8
""")



# 8. RIP-relative operands on both sides of the 256-bit work. A pair whose
# load reads a RIP-relative source, and a zero store whose destination is
# RIP-relative -- the two shapes Finding 38 refused rather than combining
# the +16 with the move into the stub.
#
# Both corrections land on the same four displacement bytes, and getting
# either wrong reads or writes sixteen bytes away from where it should. The
# buffer is poisoned first so that a store to the wrong place leaves the
# poison behind rather than a plausible zero. Its low byte is 0xa5 so that
# a failure lands at 165 rather than next door to 88 -- exit codes here
# are far apart on purpose.
PROGRAMS["riprel"] = (88, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vpxor	%xmm0, %xmm0, %xmm0
	vmovups	%ymm0, scratch(%rip)	/* zero store, RIP-relative */
	vmovups	source(%rip), %ymm1	/* the pair: RIP-relative load ... */
	vmovups	%ymm1, buffer(%rip)	/* ... and a RIP-relative store */
	movl	buffer+16(%rip), %eax	/* upper half of the copy: 88 */
	orl	scratch(%rip), %eax	/* both halves of the zeroed store */
	orl	scratch+16(%rip), %eax
	orl	scratch+28(%rip), %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 88, 6, 7, 8
scratch:
	.long 0x5a5a5aa5, 0x5a5a5aa5, 0x5a5a5aa5, 0x5a5a5aa5
	.long 0x5a5a5aa5, 0x5a5a5aa5, 0x5a5a5aa5, 0x5a5a5aa5
buffer:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
""")



# 9. A zero store with a conditional branch between it and the zeroing, and
# the branch not taken. Walking back over a `jcc` is sound -- reaching the
# store by falling through one means it was not taken on this execution --
# but the scan used to stop at any control transfer in either direction.
#
# Refused, the store stays VEX and the program dies of an illegal
# instruction rather than returning 111.
PROGRAMS["fallthrough"] = (111, """
	.text
	.globl _start
_start:
	subq	$72, %rsp
	vzeroupper
	movq	%rsp, %rdi
	movl	$0x5a5a5aa5, 16(%rdi)
	movl	$0x5a5a5aa5, 20(%rdi)
	movl	$0x5a5a5aa5, 24(%rdi)
	movl	$0x5a5a5aa5, 28(%rdi)
	vpxor	%xmm0, %xmm0, %xmm0
	xorl	%ecx, %ecx
	testl	%ecx, %ecx
	jne	other			/* not taken, and walked back over */
	vmovups	%ymm0, (%rdi)		/* the zero store */
	movl	16(%rdi), %eax		/* upper half, which must be zero */
	addl	$111, %eax
	addq	$72, %rsp
	ret
other:
	movl	$1, %eax
	addq	$72, %rsp
	ret
func_end:
	.p2align 5
""")



# 10. A zero store with an instruction between it and the zeroing that READS
# the register. A read cannot have changed the value, so the walk goes past
# it -- but "the nearest mention decides" used to stop there.
#
# Refused, the store stays VEX and the program dies of an illegal
# instruction rather than returning 123.
PROGRAMS["pastread"] = (123, """
	.text
	.globl _start
_start:
	subq	$88, %rsp
	vzeroupper
	movq	%rsp, %rdi
	movl	$0x5a5a5aa5, 16(%rdi)
	movl	$0x5a5a5aa5, 20(%rdi)
	movl	$0x5a5a5aa5, 24(%rdi)
	movl	$0x5a5a5aa5, 28(%rdi)
	vpxor	%xmm0, %xmm0, %xmm0
	vmovups	%xmm0, 32(%rdi)		/* reads xmm0, writes memory */
	vmovups	%ymm0, (%rdi)		/* the zero store, past that read */
	movl	16(%rdi), %eax		/* upper half, which must be zero */
	orl	32(%rdi), %eax
	addl	$123, %eax
	addq	$88, %rsp
	ret
func_end:
	.p2align 5
""")



# 11. A four-byte site whose window widens forward over a neighbour that
# needs a scratch of its own. The swallowed `vsubss` has dst == src2, the
# Finding 25 shape, so lowering it takes a register to preserve src2 in --
# and nothing was asking for one, so the whole window was refused.
#
# Refused, both instructions stay VEX and the program dies of an illegal
# instruction rather than returning 20.
PROGRAMS["swallowed"] = (20, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	ten(%rip), %xmm1
	vmovss	three(%rip), %xmm0
	vaddss	%xmm0, %xmm1, %xmm2	/* the site: four bytes, 10 + 3 = 13 */
	vsubss	%xmm0, %xmm1, %xmm0	/* swallowed, dst == src2: 10 - 3 = 7 */
	vaddss	%xmm2, %xmm0, %xmm3	/* 7 + 13 = 20 */
	vcvttss2si %xmm3, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
""")



# 12. A site with no dead register anywhere, for comparing the ways a stub
# can get one. The indirect jump is what makes the liveness scan give up:
# it cannot be followed, so nothing forward is provable, and a function
# containing one is disqualified from the whole-function fallback too.
#
# `%xmm2` is the register `spill_register` will borrow, and it is loaded
# before the site and read after it -- so a save or restore that does not
# round-trip returns something other than 107. Under `--spill=none` the site
# is refused, stays VEX, and the program dies at 29.
#
# Not in PE_NAMES: `make check-pe` runs the default rewriter, which refuses
# this by design. `make check-spill` is where it belongs.
PROGRAMS["spill"] = (107, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	ten(%rip), %xmm1
	vmovss	three(%rip), %xmm0
	vmovss	hundred(%rip), %xmm2	/* the register the spill will borrow */
	vsubss	%xmm0, %xmm1, %xmm0	/* aliased, and no register is dead */
	leaq	after(%rip), %rax
	jmp	*%rax			/* indirect: nothing forward is provable */
after:
	vaddss	%xmm2, %xmm0, %xmm0	/* 7 + 100, only if xmm2 came back */
	vcvttss2si %xmm0, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
hundred:	.float 100.0
""")



# 13 and 14. Can an exception be dispatched from inside a stub?
#
# `scratch.py` rejects spilling because a stub has no `.pdata`, so
# `RtlVirtualUnwind` treats it as a leaf and reads the frame from an `rsp`
# the spill has moved. That reasoning has a hole worth testing: a stub is
# entered by a JUMP, so `[rsp]` was never a return address, and the unwind is
# wrong whether or not anything moved it.
#
# Both programs fault deliberately and both register a handler through
# `.pdata` -- which is how a PE with no imports and no CRT gets SEH at all,
# the dispatcher finding the handler in the unwind info rather than through
# anything registered at run time. The handler points `CONTEXT.Rip` at
# `recover` and `CONTEXT.Rsp` at the establisher frame, so a dispatch that
# reaches it returns 42.
#
# `unwind` faults on a plain `mov` that no rewriting touches: the control.
# `unwindstub` faults on the lowered `addss` inside a stub. If the two
# disagree, the stub is the reason.
_UNWIND_TAIL = """
recover:
	movl	$42, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
handler:
	/* rcx record, rdx establisher frame, r8 context, r9 dispatcher */
	leaq	recover(%rip), %rax
	movq	%rax, 0xf8(%r8)		/* CONTEXT.Rip */
	movq	%rdx, 0x98(%r8)		/* CONTEXT.Rsp */
	xorl	%eax, %eax		/* ExceptionContinueExecution */
	ret
ten:	.float 10.0
"""

PROGRAMS["unwind"] = (42, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	ten(%rip), %xmm1
	xorl	%eax, %eax
	movl	(%rax), %ecx		/* faults, and nothing rewrites it */
	movl	$7, %eax
	addq	$40, %rsp
	ret
""" + _UNWIND_TAIL)

PROGRAMS["unwindstub"] = (42, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	ten(%rip), %xmm1
	xorl	%eax, %eax
	vaddss	(%rax), %xmm1, %xmm0	/* faults INSIDE the stub */
	nop
	movl	$7, %eax
	addq	$40, %rsp
	ret
""" + _UNWIND_TAIL)


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
		listing = subprocess.run(["objdump", "-t", str(obj)],
		                         capture_output=True, text=True).stdout
		symbols = {}
		for line in listing.splitlines():
			fields = line.split()
			if len(fields) >= 2 and ".text" in line:
				try:
					symbols[fields[-1]] = int(fields[0], 16)
				except ValueError:
					pass
		if "func_end" not in symbols:
			raise SystemExit("pe_build: func_end not found")
		return bin_.read_bytes(), symbols


def align(value, to):
	return (value + to - 1) // to * to


def build(path, text, code_size, handler=None):
	"""Write a PE whose entry point is the start of `text`."""
	# .xdata first, because .pdata points into it. A minimal UNWIND_INFO:
	# version 1, no flags, no prolog, no unwind codes. Nothing here ever
	# unwinds; it exists so the function HAS unwind data, which is what
	# puts it in .pdata and therefore in the rewriter's code oracle.
	#
	# **Unless the program has a `handler` symbol**, in which case the flags
	# byte carries UNW_FLAG_EHANDLER and a handler RVA follows the (empty,
	# and therefore already even) unwind-code array. That is how a program
	# with no imports and no CRT gets structured exception handling: the
	# dispatcher finds the handler through `.pdata` rather than through
	# anything the program registers at run time.
	if handler is None:
		xdata = struct.pack("<BBBB", 1, 0, 0, 0)
	else:
		xdata = struct.pack("<BBBBI", 1 | (1 << 3), 0, 0, 0,
		                    SECTION_ALIGNMENT + handler)

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
	text, symbols = assemble(source)
	code_size = symbols["func_end"]
	sections = build(output, text, code_size, symbols.get("handler"))
	print(f"pe_build: {name} -> {output}, {len(text)} bytes of .text, "
	      f"function is {code_size} of them, expected exit code {expected}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
