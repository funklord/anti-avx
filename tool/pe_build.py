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
exists in tool/detour.py, which appends a section to a 102 MB PE without
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
# How many bytes the loader zeroes per thread after the raw template. The
# real binary's directory asks for 0; raising it is the whole mechanism.
TLS_ZERO_FILL = 32
CODE = 0xE0000020		# CODE | EXECUTE | READ | WRITE
CODE_READONLY = 0x60000020	# CODE | EXECUTE | READ
DATA = 0x40000040		# INITIALIZED_DATA | READ

# The programs. Each exists to exercise a piece of the REWRITER, not to
# vary the arithmetic -- test/lowering_test.c already executes the lowerings
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
# whole test -- test/lowering_test.c cannot reach ymm at all, and the
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
# Three outcomes rather than two, because "the handler ran" and "the frame it
# was given was right" are different claims and the second is the one a spill
# puts at risk. `_start` records its own post-prologue `rsp`, the handler
# compares that against the establisher frame the unwinder computed, and
# resumption always uses the recorded value -- so an answer comes back either
# way and says which.
#
#   42  the handler ran and the establisher frame was correct
#   99  the handler ran and the frame was wrong
#    5  the handler was never reached at all
_UNWIND_TAIL = """
recover:
	movl	verdict(%rip), %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
handler:
	/* rcx record, rdx establisher frame, r8 context, r9 dispatcher */
	leaq	recover(%rip), %rax
	movq	%rax, 0xf8(%r8)		/* CONTEXT.Rip */
	movq	frame(%rip), %rax
	movq	%rax, 0x98(%r8)		/* CONTEXT.Rsp, from the recorded value */
	movl	$99, %eax
	movl	$42, %ecx
	cmpq	frame(%rip), %rdx	/* did the unwinder agree? */
	cmovel	%ecx, %eax
	movl	%eax, verdict(%rip)
	xorl	%eax, %eax		/* ExceptionContinueExecution */
	ret
	.p2align 4
frame:	.quad 0
verdict:	.long 0
ten:	.float 10.0
"""

PROGRAMS["unwind"] = (42, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	movq	%rsp, frame(%rip)
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
	movq	%rsp, frame(%rip)
	vzeroupper
	vmovss	ten(%rip), %xmm1
	xorl	%eax, %eax
	vaddss	(%rax), %xmm1, %xmm0	/* faults INSIDE the stub */
	nop
	movl	$7, %eax
	addq	$40, %rsp
	ret
""" + _UNWIND_TAIL)



# 15. A fault inside a stub that has MOVED RSP, which is the case the unwind
# data has to describe rather than merely be present for.
#
# The FMA needs a scratch and no register is dead -- the indirect jump sees
# to that -- so under `--spill=stack` the stub allocates sixteen bytes. It
# then faults on its own memory operand, in the middle of that allocation.
#
# **It answers 99, and that is the finding.** The handler is reached -- the
# chain does its job -- but the establisher frame is sixteen bytes out,
# because the chained fragment's own `UWOP_ALLOC_SMALL` is not applied.
# Measured at exactly -16, and unchaining to get the code applied loses the
# handler instead. Finding 49: a stub that moves `rsp` cannot be described,
# which is why `--spill=none` is the default on evidence rather than caution.
PROGRAMS["unwindspill"] = (99, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	movq	%rsp, frame(%rip)
	vzeroupper
	vmovss	ten(%rip), %xmm1
	vmovss	ten(%rip), %xmm2	/* a register worth borrowing */
	xorl	%eax, %eax
	vfmadd213ss (%rax), %xmm1, %xmm0	/* needs a scratch, and faults */
	leaq	skip(%rip), %rcx
	jmp	*%rcx			/* indirect: nothing is provably dead */
skip:
	movl	$7, %eax
	addq	$40, %rsp
	ret
""" + _UNWIND_TAIL)



# 16. A 256-bit copy with instructions between the load and the store, which
# is what Finding 39 refused and Finding 50 takes by holding the upper half
# in a second register.
#
# The instructions in between are the point. They compute the destination
# address, so they cannot be moved after the store and they cannot be moved
# before the load -- which is exactly why interleaving the four moves does
# not work and why the register does. Reading back offset 16 proves the
# upper half made the trip.
PROGRAMS["gapped"] = (64, """
	.text
	.globl _start
_start:
	subq	$104, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	vmovups	(%rsi), %ymm0		/* the load ... */
	movq	%rsp, %rdi
	addq	$8, %rdi
	subq	$8, %rdi		/* ... a gap that decides where ... */
	vmovups	%ymm0, (%rdi)		/* ... the store goes */
	movl	16(%rdi), %eax		/* upper half of the copy: 64 */
	addq	$104, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 64, 6, 7, 8
""")



# 17. Two 256-bit copies interleaved -- load, load, store, store -- which is
# what MSVC emits for a block bigger than 32 bytes and what a single-pair
# span cannot take: the second load sits inside the first pair's span, is
# itself 256-bit, and will not move.
#
# Each copy gets a helper of its own, and both upper halves are read back so
# that a shared or transposed helper shows up as a wrong number rather than
# as nothing.
PROGRAMS["interleaved"] = (77, """
	.text
	.globl _start
_start:
	subq	$136, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* two copies, interleaved */
	vmovups	32(%rsi), %ymm1
	vmovups	%ymm0, (%rdi)
	vmovups	%ymm1, 32(%rdi)
	movl	16(%rdi), %eax		/* upper half of the first: 33 */
	addl	48(%rdi), %eax		/* upper half of the second: 44 */
	addl	(%rdi), %eax		/* and both LOW halves, which a shared */
	addl	32(%rdi), %eax		/* helper silently loses: 1 + 9 */
	subl	$10, %eax
	addq	$136, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 33, 6, 7, 8
	.long 9, 10, 11, 12
	.long 44, 14, 15, 16
""")



# 18. The variable-control vpermilps, inlined rather than called.
#
# The last lowering with no executable case, and the reason is structural:
# it reads its permute constants from the stub section's pool through a
# RIP-relative displacement, so tool/lowering_cases.py cannot generate it --
# that generator emits `.byte` and cannot know where the assembler will put
# them. A whole PE can, because the rewriter lays the pool down itself.
#
# make check-permil is exhaustive over all 256 controls and tests
# src/permil.c, the reference implementation. This tests the bytes the
# rewriter actually emits, which is a different claim.
#
# Only bits [1:0] of each control element are read, so {3,2,1,0} reverses
# the vector and lane 0 comes back holding what lane 3 held.
PROGRAMS["permilps"] = (88, """
	.text
	.globl _start
_start:
	subq	$56, %rsp
	vzeroupper
	vmovups	source(%rip), %xmm2
	vmovups	control(%rip), %xmm1
	vpermilps %xmm1, %xmm2, %xmm0	/* control, data, dst */
	vmovups	%xmm0, (%rsp)
	movl	(%rsp), %eax		/* lane 0 = source[3] = 88 */
	addq	$56, %rsp
	ret
func_end:
	.p2align 4
source:	.long 1, 2, 3, 88
control:	.long 3, 2, 1, 0
""")



# 19. One source copied to TWO destinations, which stores the same ymm twice.
#
# The second store reads an upper half the first store did not consume, so
# closing the run on the first store refused the whole thing -- 1,019 pairs
# in Starfield. A register stays tracked across as many stores as follow,
# and both upper halves are read back so that losing either shows.
PROGRAMS["twostore"] = (90, """
	.text
	.globl _start
_start:
	subq	$136, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* one load ... */
	vmovups	%ymm0, (%rdi)		/* ... and two stores */
	vmovups	%ymm0, 64(%rdi)
	movl	16(%rdi), %eax		/* upper half of the first: 45 */
	addl	80(%rdi), %eax		/* upper half of the second: 45 */
	addq	$136, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 45, 6, 7, 8
""")



# 27. A four-byte Class C site with a CONDITIONAL branch before it and that
# branch's target immediately after it -- the shape of 304 refused sites, and
# of 0x14004d456 where Starfield stopped.
#
# Forward widening is refused because the next instruction is branched to:
# swallowing it would leave the `je` landing inside the five-byte jump that
# replaced it. Backward widening was refused too, because the previous
# instruction transfers control -- but a CONDITIONAL branch is the one
# transfer that falls through into the site, which is exactly what makes the
# window sound. Its target lies outside the window, so nothing is relocated;
# the branch is re-emitted as `0f 8x rel32` inside the stub.
#
# %xmm0 is poisoned with 100.0 first, so a branch re-aimed wrongly -- taken
# when it should fall through -- returns 10000 rather than something near 27.
PROGRAMS["condbefore"] = (27, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	hundred(%rip), %xmm0	/* poison */
	vmovss	nine(%rip), %xmm1
	vmovss	three(%rip), %xmm3
	xorl	%ecx, %ecx
	cmpl	$1, %ecx		/* 0 != 1, so the branch is NOT taken */
	je	skip			/* two bytes, and falls through to the site */
	vdivss	%xmm3, %xmm1, %xmm0	/* four bytes, dst != src1: 9/3 = 3 */
skip:
	vmulss	%xmm0, %xmm0, %xmm0	/* 3 * 3 = 9, the branch target */
	vmulss	%xmm3, %xmm0, %xmm0	/* 9 * 3 = 27 */
	vcvttss2si %xmm0, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
nine:	.float 9.0
three:	.float 3.0
hundred:	.float 100.0
""")



# 26. A four-byte Class C site with an unconditional `jmp` immediately after
# it, which is what 367 of the 427 refused sites look like.
#
# The site needs seven bytes as SSE and has four, so it must widen -- and the
# only neighbour is a jump, which the collector refused to swallow because a
# relative displacement cannot be MOVED. It can be re-aimed: `jmp rel8`
# becomes `jmp rel32` at the same absolute target, and a stub containing an
# unconditional jump simply never reaches its trailing jump home.
#
# The jump is TAKEN at run time, so a displacement re-aimed wrongly does not
# compute a wrong number -- it lands somewhere else entirely. `far` is placed
# past a `ud2` that must never execute, so a jump landing short traps rather
# than falling through to the answer by luck.
# **The site must be boxed in on BOTH sides**, or the test proves nothing.
# Forward widening is what this rule enables, but when it is refused the
# collector widens BACKWARDS instead -- and the first version of this program
# had an ordinary `vmovss` in front, so the site was lowered either way and
# the program returned 81 with the rule reverted. The real site at
# 0x14004d240 has a `je` above it and a `jmp` below it, which is why it is
# refused, so the `jne` here is load-bearing rather than scenery.
PROGRAMS["swallowjmp"] = (81, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	nine(%rip), %xmm1
	vmovss	three(%rip), %xmm3
	xorl	%ecx, %ecx
	testl	%ecx, %ecx
	jne	wrong			/* not taken, and blocks widening backwards */
	vdivss	%xmm3, %xmm1, %xmm5	/* four bytes, dst != src1: 9/3 = 3 */
	jmp	far			/* two bytes, and the only padding left */
	ud2				/* must never execute */
wrong:
	movl	$1, %eax
	addq	$40, %rsp
	ret
far:
	vmulss	%xmm5, %xmm5, %xmm0	/* 3 * 3 = 9 */
	vmulss	%xmm5, %xmm0, %xmm0	/* 9 * 3 = 27 */
	vmulss	%xmm3, %xmm0, %xmm0	/* 27 * 3 = 81 */
	vcvttss2si %xmm0, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
nine:	.float 9.0
three:	.float 3.0
""")



# 25. The store AFTER a loop head, whose backward walk must cross it.
#
# Finding 83 taught the scan that a loop head keeps its zero, and gained
# nothing: the second store in the body walks back, meets the head -- a
# branch target -- and refuses on the older rule. Finding 84 recurses there,
# because a branch target is only opaque if the value at it is, and the head
# has just been proved zero.
#
# This is the shape Starfield stops on at 0x14186e921, minus the widths. Both
# stores must land, over two iterations, so a lowering that takes the head
# and refuses the body leaves poison at offset 48 and never returns 33.
PROGRAMS["zerochain"] = (33, """
	.text
	.globl _start
_start:
	subq	$200, %rsp
	movq	%rsp, %rax
	movl	$0xa5a5a5a5, 16(%rax)	/* poison every upper half */
	movl	$0xa5a5a5a5, 48(%rax)
	movl	$0xa5a5a5a5, 80(%rax)
	movl	$0xa5a5a5a5, 112(%rax)
	movl	$33, 128(%rax)		/* the answer, past the cleared range */
	vzeroupper
	movq	$2, %rdx
	vpxor	%xmm0, %xmm0, %xmm0
loop:
	vmovups	%ymm0, (%rax)		/* the head: Finding 83 */
	vmovups	%ymm0, 0x20(%rax)	/* the body: needs Finding 84 */
	leaq	0x40(%rax), %rax
	subq	$1, %rdx
	jne	loop
	movq	%rsp, %rax
	movl	16(%rax), %ecx
	addl	48(%rax), %ecx
	addl	80(%rax), %ecx
	addl	112(%rax), %ecx
	addl	128(%rax), %ecx
	movl	%ecx, %eax
	addq	$200, %rsp
	ret
func_end:
""")



# 24. A memset loop whose HEAD is the zero store, which Finding 82 refused
# and Finding 83 takes back.
#
# The store is a branch target -- its own back edge -- so another path
# reaches it without passing the `vpxor`. That path is the previous
# iteration, and the body writes nothing to ymm0, so the register is still
# zero when it arrives. The induction needs every premise: only the head is
# entered, no call, no write to the register anywhere in the body.
#
# 64 bytes are cleared over two iterations from a poisoned buffer, so a
# lowering that runs once, or writes the wrong half, leaves poison behind and
# returns something far from 44.
PROGRAMS["loophead"] = (44, """
	.text
	.globl _start
_start:
	subq	$136, %rsp
	movq	%rsp, %rax
	movl	$0xa5a5a5a5, 16(%rax)	/* poison the first upper half */
	movl	$0xa5a5a5a5, 48(%rax)	/* and the second */
	movl	$44, 96(%rax)		/* the answer, past the cleared range */
	vzeroupper
	movq	$2, %rdx
	vpxor	%xmm0, %xmm0, %xmm0
loop:
	vmovups	%ymm0, (%rax)		/* the head, and a branch target */
	leaq	32(%rax), %rax
	subq	$1, %rdx
	jne	loop
	movq	%rsp, %rax
	movl	16(%rax), %ecx		/* both upper halves must be zero */
	addl	48(%rax), %ecx
	addl	96(%rax), %ecx		/* plus 44 */
	movl	%ecx, %eax
	addq	$136, %rsp
	ret
func_end:
""")



# 23. Three consecutive 256-bit zero stores with no displacement, which is
# what clearing a structure looks like and what Starfield stopped on.
#
# Each encodes in FOUR bytes and a detour needs five, so each has to widen
# its window over a neighbour -- and the neighbour is another zero store that
# wanted the same padding. The first wins, the second's window overlaps a
# committed one and is skipped, and so on. Taken as one window the group is
# already long enough and nothing has to widen.
#
# The addressing is deliberately bare: `(%rax)` rather than `0x20(%rax)`,
# because a displacement makes the instruction five bytes and the whole
# difficulty disappears. %rax is stepped between them instead, which is also
# what the real code does.
#
# 96 bytes are cleared and one poisoned dword read back, so a store landing
# at the wrong offset returns the poison rather than 88.
PROGRAMS["zerorun"] = (88, """
	.text
	.globl _start
_start:
	subq	$168, %rsp
	vzeroupper
	movq	%rsp, %rax
	movl	$0xa5a5a5a5, 32(%rax)	/* poison inside the cleared range */
	movl	$88, 128(%rax)		/* the answer, outside it */
	vpxor	%xmm0, %xmm0, %xmm0
	vmovups	%ymm0, (%rax)		/* four bytes, and the only thing */
	vmovups	%ymm0, 0x20(%rax)	/* it can widen over is another */
	vmovups	%ymm0, 0x40(%rax)	/* 256-bit store, which cannot move */
	movq	%rsp, %rax
	movl	32(%rax), %ecx		/* must be zero, not the poison */
	addl	128(%rax), %ecx		/* plus 88 */
	movl	%ecx, %eax
	addq	$168, %rsp
	ret
func_end:
""")



# 22. A copy pair, a VEX.128 write to the SAME register's low half, and a
# 256-bit store of it afterwards.
#
# The store reads the register, so `upper_half_read_later` refuses the pair --
# unless it notices the `vpxor` in between. That instruction zeroes bits
# [255:128] of %ymm0 as architecture, so the upper half the pair leaves stale
# is dead from there and nothing downstream can observe it. The scan matched
# the `%ymm` spelling only and read `%xmm0` as an unrelated register.
#
# The second store must therefore land as 32 bytes of ZERO while the first
# lands as the copy, and the program adds one to the other: 77 + 0. A pair
# lowering that leaked its stale upper half into the second store would return
# something far from 77 rather than something adjacent to it.
PROGRAMS["lowwrite"] = (77, """
	.text
	.globl _start
_start:
	subq	$136, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* the pair ... */
	vmovups	%ymm0, (%rdi)
	vpxor	%xmm0, %xmm0, %xmm0	/* ... killed by a VEX.128 write ... */
	vmovups	%ymm0, 64(%rdi)		/* ... and read after it: zero */
	movl	16(%rdi), %eax		/* upper half of the copy: 77 */
	addl	80(%rdi), %eax		/* upper half of the zero store: 0 */
	addq	$136, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 77, 6, 7, 8
""")



# 21. A copy pair whose upper half outlives a LOOP that never touches it.
#
# `upper_half_read_later` walks forward from the store, meets the `jne`, and
# recurses into both edges. Down the taken edge it comes back round to that
# same `jne` -- a position already in `visiting`. It used to answer "read"
# there and refuse the pair; Finding 78 answers "dead", because coming back
# means every instruction on the cycle was examined and none of them read the
# register.
#
# **The loop body must not mention the ymm, or this tests nothing.** A loop
# that reloads it would end the walk at a full overwrite, which is a different
# rule and one that already worked -- the walk would never reach the back edge
# at all. `spin` therefore touches only %ecx.
#
# Without the rule the pair is refused, the VEX survives, and a Westmere dies
# at 29; with it the program returns the upper half of the copy, 66.
PROGRAMS["loopcopy"] = (66, """
	.text
	.globl _start
_start:
	subq	$104, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* the pair ... */
	vmovups	%ymm0, (%rdi)
	movl	$3, %ecx		/* ... and a loop after it that */
spin:					/* touches no ymm at all, so the */
	decl	%ecx			/* walk reaches the back edge */
	jne	spin
	movl	16(%rdi), %eax		/* upper half of the copy: 66 */
	addq	$104, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 66, 6, 7, 8
""")



# 20. The same starved site, in a function that CALLS something -- which is
# what reserves the 32 bytes of callee home space at the bottom of its frame.
#
# `--spill=home` writes the borrowed register there and reads it back, moving
# nothing and needing no register to address it. `%xmm2` is loaded before the
# site and read after, so a save or restore that does not round-trip returns
# something other than 107; under `--spill=none` the site is refused and the
# program dies at 29.
#
# The `call` is not decoration. Without it the function is a leaf, no home
# space exists, and the collector refuses -- which is the case the plain
# `spill` program covers.
PROGRAMS["homespill"] = (107, """
	.text
	.globl _start
_start:
	subq	$40, %rsp		/* 32 of home space, and alignment */
	vzeroupper
	call	helper			/* makes the home space real */
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
helper:
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
hundred:	.float 100.0
""")


# 23. A copy of `rsp` that never reaches the home space -- the MSVC prologue
# idiom, and the shape the blanket refusal was written against.
#
# `movq %rsp,%r10` at entry makes a pointer to the frame, which is what
# Findings 72 and 73 refused any function for. Here it addresses a local at
# `entry-0x40`, while the callee home space this function reserves sits at
# `entry-0x68` through `entry-0x49` -- a different region, and the whole
# point of `copy_reaches_home`. The local is written before the site and read
# after it, so a borrow that landed in the wrong place returns 29 rather
# than faulting.
#
# The frame must be declared in FRAMES or the unwind codes claim zero, the
# analysis puts the home space at `entry+0`, and the test passes without
# testing the arithmetic.
#
# Under `--rsp=blanket` the function cannot lend, the aliased site is
# refused, and the surviving VEX faults on a CPU without AVX -- which is the
# A/B this program exists for.
PROGRAMS["rspcopy"] = (107, """
	.text
	.globl _start
_start:
	vzeroupper
	movq	%rsp, %r10		/* the copy the blanket rule refused */
	subq	$104, %rsp		/* 32 of home space, and locals */
	call	helper			/* makes the home space real */
	movq	$55, -0x40(%r10)	/* a local, well clear of the region */
	vmovss	ten(%rip), %xmm1
	vmovss	three(%rip), %xmm0
	vmovss	hundred(%rip), %xmm2	/* the register the spill will borrow */
	vsubss	%xmm0, %xmm1, %xmm0	/* aliased, and no register is dead */
	leaq	after(%rip), %rcx
	jmp	*%rcx			/* indirect: nothing forward is provable */
after:
	vaddss	%xmm2, %xmm0, %xmm0	/* 7 + 100, only if xmm2 came back */
	vcvttss2si %xmm0, %eax
	cmpq	$55, -0x40(%r10)	/* and the local must be untouched */
	je	done
	movl	$29, %eax
done:
	addq	$104, %rsp
	ret
helper:
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
hundred:	.float 100.0
""")

# The prologue allocation each program really makes, where a test depends on
# the unwind codes saying so. Everything absent here declares nothing, which
# is what every program before this one did.
# **A declared frame is what makes the depth walk possible, not just the
# home-space arithmetic.** `rsp_depths` resets to the body depth after every
# terminator and refuses a branch taken anywhere else, so a sample whose
# unwind codes claim a frame of zero has its `jmp` refused at -40 and the
# borrow it exists to test never happens.
FRAMES = {"rspcopy": 104, "shadowspill": 40, "regionlive": 40,
          "regioncarry": 72,
          "regionread": 40, "tlsspill": 40, "spanblock": 72}

# Samples whose `.text` is mapped without IMAGE_SCN_MEM_WRITE, so that a
# constant in it is one. See `build`.
READONLY = {"constant", "constloop"}


# 24. A 256-bit load and store too far apart for one window, carried by a
# reserved register.
#
# ymm_pair takes the adjacent case and ymm_run takes what fits a single
# stub. Here fourteen ordinary SSE instructions sit between the two, so the
# upper half dies at the window edge and the store is declined for want of
# it -- unless the load's stub parks the upper half in a register the
# original never names and the store's stub reads it back.
#
# The padding is deliberately %xmm registers the pair does not use, so a
# register really is free across the span; and it is deliberately NOT a
# branch target, since control arriving mid-span would find the shadow
# holding whatever came before. Both are conditions long_pair_store
# enforces, and the program is here to execute what it decided.
#
# The 32 bytes loaded are 1..8; the low half is stored to one place and the
# high half must arrive with it. Reading back the eighth lane gives 8, and
# 8 * 13 + 3 = 107. A shadow that never got written leaves zero there and
# the program returns 3.
PROGRAMS["longpair"] = (107, """
	.text
	.globl _start
_start:
	vzeroupper
	subq	$40, %rsp
	vmovups	source(%rip), %ymm0	/* 32 bytes; the stores are far below */
	movaps	pad(%rip), %xmm3
	mulps	%xmm3, %xmm3
	addps	%xmm3, %xmm3
	xorps	%xmm3, %xmm3
	movaps	pad(%rip), %xmm4
	mulps	%xmm4, %xmm4
	addps	%xmm4, %xmm4
	xorps	%xmm4, %xmm4
	movaps	pad(%rip), %xmm5
	mulps	%xmm5, %xmm5
	addps	%xmm5, %xmm5
	xorps	%xmm5, %xmm5
	movaps	pad(%rip), %xmm6
	mulps	%xmm6, %xmm6
	addps	%xmm6, %xmm6
	xorps	%xmm6, %xmm6
	movaps	pad(%rip), %xmm7
	mulps	%xmm7, %xmm7
	addps	%xmm7, %xmm7
	xorps	%xmm7, %xmm7
	movaps	pad(%rip), %xmm3
	mulps	%xmm3, %xmm3
	addps	%xmm3, %xmm3
	xorps	%xmm3, %xmm3
	movaps	pad(%rip), %xmm4
	mulps	%xmm4, %xmm4
	addps	%xmm4, %xmm4
	xorps	%xmm4, %xmm4
	movaps	pad(%rip), %xmm5
	mulps	%xmm5, %xmm5
	addps	%xmm5, %xmm5
	xorps	%xmm5, %xmm5
	movaps	pad(%rip), %xmm6
	mulps	%xmm6, %xmm6
	addps	%xmm6, %xmm6
	xorps	%xmm6, %xmm6
	movaps	pad(%rip), %xmm7
	mulps	%xmm7, %xmm7
	addps	%xmm7, %xmm7
	xorps	%xmm7, %xmm7
	movaps	pad(%rip), %xmm3
	mulps	%xmm3, %xmm3
	addps	%xmm3, %xmm3
	xorps	%xmm3, %xmm3
	movaps	pad(%rip), %xmm4
	mulps	%xmm4, %xmm4
	addps	%xmm4, %xmm4
	xorps	%xmm4, %xmm4
	vmovups	%ymm0, sink(%rip)	/* both halves, or the upper is lost */
	vmovups	%ymm0, sink2(%rip)	/* a SECOND store of the same value */
	movl	sink+28(%rip), %eax	/* eighth lane: 8 */
	movl	sink2+28(%rip), %ecx	/* and 8 again, if it was carried */
	addl	%ecx, %eax		/* 16 only if BOTH stores got the half */
	imull	$6, %eax, %eax
	addl	$11, %eax		/* 16 * 6 + 11 = 107 */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 5, 6, 7, 8
pad:	.long 0, 0, 0, 0
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
sink2:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
""")


# 25. A 128-bit value broadcast to both halves by vinsertf128, and stored.
#
# `vinsertf128 $1,%xmm0,%ymm0,%ymm0` copies the low half into the high half,
# so both halves hold the same sixteen bytes and the 32-byte store writes
# the value twice. The lowering emits exactly what an all-zero ymm needs --
# two 128-bit stores of one register -- because a splat has the same
# property one step weaker: both halves are the same register.
#
# The eighth lane comes from the HIGH half, so a lowering that stored only
# the low half, or stored zero above it, leaves 0 there and returns 3
# instead of 107. Reading lane 4 as well pins the low half at the same time.
PROGRAMS["splat"] = (107, """
	.text
	.globl _start
_start:
	vzeroupper
	subq	$40, %rsp
	vmovups	source(%rip), %xmm0	/* 16 bytes: 1 2 3 8 */
	vinsertf128 $0x1, %xmm0, %ymm0, %ymm0	/* both halves now 1 2 3 8 */
	vmovups	%ymm0, sink(%rip)	/* 32 bytes, the value twice */
	movl	sink+28(%rip), %eax	/* the HIGH half's fourth lane: 8 */
	movl	sink+12(%rip), %ecx	/* and the low half's: 8 */
	addl	%ecx, %eax		/* 16 only if both halves arrived */
	imull	$6, %eax, %eax
	addl	$11, %eax		/* 16 * 6 + 11 = 107 */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 8
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
""")


# 32. A 256-bit constant, loaded once and stored a long way from the load,
# with a 128-bit read of the same register in between. Every one of those is
# a reason `long_pair_stores` refuses a site -- it reserves a register from
# the load to the store, so the distance costs it and any use of the low half
# ends it. A constant costs neither: the store's stub loads both halves again
# from `source`, which cannot have changed, so nothing has to be carried.
#
# `.text` is mapped without IMAGE_SCN_MEM_WRITE for this sample (see
# `READONLY`), which is what makes `source` a constant rather than a variable
# the program has not written yet. The scratch is therefore on the stack.
#
# The poison is the test, as it is in `zerofill`: 0x5a5a5a5a everywhere the
# stores must land, and five lanes added back. A truncated store leaves
# poison at 60(%rsp) and an off-by-sixteen leaves it at 32(%rsp), and either
# blows the low byte of the sum well past 73.
PROGRAMS["constant"] = (73, """
	.text
	.globl _start
_start:
	subq	$136, %rsp
	vzeroupper
	movl	$0x5a5a5a5a, 32(%rsp)
	movl	$0x5a5a5a5a, 36(%rsp)
	movl	$0x5a5a5a5a, 40(%rsp)
	movl	$0x5a5a5a5a, 44(%rsp)
	movl	$0x5a5a5a5a, 48(%rsp)
	movl	$0x5a5a5a5a, 52(%rsp)
	movl	$0x5a5a5a5a, 56(%rsp)
	movl	$0x5a5a5a5a, 60(%rsp)
	movl	$0x5a5a5a5a, 96(%rsp)
	movl	$0x5a5a5a5a, 100(%rsp)
	movl	$0x5a5a5a5a, 104(%rsp)
	movl	$0x5a5a5a5a, 108(%rsp)
	vmovups	source(%rip), %ymm0	/* 1 2 3 8 / 16 5 6 40 */
	vmovups	%xmm0, 96(%rsp)		/* a 128-bit READ of the low half */
	vmovups	%ymm0, 32(%rsp)		/* and the whole of it, 32 bytes */
	movl	32(%rsp), %eax		/* 1  -- low half, first lane */
	addl	44(%rsp), %eax		/* 8  -- low half, last lane */
	addl	48(%rsp), %eax		/* 16 -- HIGH half, first lane */
	addl	60(%rsp), %eax		/* 40 -- HIGH half, last lane */
	addl	108(%rsp), %eax		/* 8  -- the 128-bit read, last lane */
	addq	$136, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 8
	.long 16, 5, 6, 40
""")



# 33. The same constant, but the stores are inside a loop and the load is
# outside it. This is the shape Starfield stops on at 0x1408284C7: MSVC hoists
# a 256-bit constant out of a loop that fills a structure with it.
#
# Nothing can carry a register across it. The loop head is a branch target, so
# a run's window may not span it and a reserved shadow would hold whatever the
# last iteration left. What makes it lowerable is that the value is decided
# outside and never touched inside, which is `value_survives_loop`'s induction
# reached through `reaching_definition` -- the same argument Finding 83 made
# for a zero, and it does not care which value it is about.
#
# **The first store is four bytes on purpose**, which is the whole of the
# second half of the problem. A 256-bit store with no displacement does not
# reach five bytes, so its window has to widen -- and it can widen neither
# way here: backwards is refused because the site is a branch target and
# cannot vanish into the middle of a window, forwards would have to swallow
# another 256-bit store and `moved_instruction` refuses those. The two are
# taken as one window instead, which is `store_run` and is Finding 81's
# answer reused. Without it this program still dies, at the loop head.
PROGRAMS["constloop"] = (82, """
	.text
	.globl _start
_start:
	subq	$200, %rsp
	vzeroupper
	movq	%rsp, %rax
	movl	$40, %edx
poison:
	movl	$0x5a5a5a5a, 32(%rax)
	addq	$4, %rax
	subl	$1, %edx
	jne	poison
	vmovups	source(%rip), %ymm0	/* 1 2 3 8 / 16 5 6 40 */
	movl	$2, %edx
	leaq	32(%rsp), %rcx
loop:
	vmovups	%ymm0, (%rcx)		/* four bytes, and a branch target */
	vmovups	%ymm0, 32(%rcx)		/* five, and inside the first one's window */
	addq	$64, %rcx
	subl	$1, %edx
	jne	loop
	movl	32(%rsp), %eax		/* 1  -- first store, low half */
	addl	60(%rsp), %eax		/* 40 -- first store, HIGH half */
	addl	128(%rsp), %eax		/* 1  -- last store, low half */
	addl	156(%rsp), %eax		/* 40 -- last store, HIGH half */
	addq	$200, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 8
	.long 16, 5, 6, 40
""")


# 34. The two one-operand VEX instructions, which are not a 256-bit problem
# and had been refused since the beginning. `vstmxcsr` writes the control and
# status word to memory and `vldmxcsr` reads it back; neither has a
# destination register, and both the in-place classifier and the collector
# tested for two operands and for three and fell off the end.
#
# The test is a round trip rather than a comparison against a constant,
# because what MXCSR holds when a process starts is the runtime's business
# and not this program's. Toggle FTZ -- the one bit nothing else here reads
# -- put it back, read it again, and the difference must be exactly that
# bit. Then restore the original, because a program that leaves the FPU in a
# different mode than it found it is a bad neighbour even when nothing is
# looking.
#
# 55 only if both instructions executed and the value went round; 11 if the
# store wrote nothing, if the load took nothing, or if the poison survived.
# 37. A LEAF with an aliased site: the caller's shadow, and the first
# borrow that does not come out of a home space this function allocated.
#
# `homespill` above is the same arithmetic and differs in one instruction --
# it calls `helper` for no reason but to make its own callee home space
# exist. Take the call away and `home_space_map` has nothing to lend, since
# the 32 bytes it lends are the ones a function reserves for ITS callees and
# a leaf reserves none. That refusal is `no home space to borrow`, the
# largest named cause anywhere in the residue.
#
# What this borrows instead is the 32 bytes its own caller reserved for it,
# at entry `[rsp+8..40)` -- always allocated by the Win64 caller, whatever
# the callee's arity, and the callee's to use for anything. Here the caller
# is the loader, and `rsp` sits 40 bytes below entry at the site, so the
# save is written at `0x30(%rsp)`.
#
# The A/B is the same as `homespill`'s and is the whole point: 107 only if
# %xmm2 came back holding 100.0. A borrow written at the wrong displacement
# returns something else, or faults; a site refused for want of a home space
# keeps its VEX and dies on a CPU without AVX.
PROGRAMS["shadowspill"] = (107, """
	.text
	.globl _start
_start:
	subq	$40, %rsp		/* a frame, and no call: this is a leaf */
	vzeroupper
	vmovss	ten(%rip), %xmm1
	vmovss	three(%rip), %xmm0
	vmovss	hundred(%rip), %xmm2	/* the register the borrow will take */
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


# 38. The region is dead from the site onward, so the borrow is safe --
# Finding 131. A leaf again, so only the caller's shadow can lend, and this
# one USES its shadow: it keeps a local there, reads it back, and never
# touches it again. The whole-function rule refuses the site for that
# reference alone; the liveness rule asks whether the reference can still be
# reached from the site, and it cannot.
#
# `0x30(%rsp)` is the shadow because `rsp` sits 40 bytes below entry here:
# entry-relative that is -40 + 48 = 8, the shadow's first byte. Writing it
# is legitimate -- it belongs to this function by the ABI -- which is what
# makes it a local worth keeping there.
#
# 118 = 107 + 11, and only if BOTH survived: the borrow gave %xmm2 back, and
# the local was read before the borrow destroyed it. A borrow taken when the
# local was still live returns 107 plus whatever %xmm2's bits look like as
# an integer.
PROGRAMS["regionlive"] = (121, """
	.text
	.globl _start
_start:
	subq	$40, %rsp		/* a frame, and no call: this is a leaf */
	vzeroupper
	movl	$11, 48(%rsp)		/* a local, kept in the caller's shadow */
	movl	48(%rsp), %ecx		/* read back here, and never again */
	vmovss	three(%rip), %xmm0
	vmovss	ten(%rip), %xmm1
	vmovss	hundred(%rip), %xmm2
	vmovss	one(%rip), %xmm3
	vmovss	one(%rip), %xmm4
	vmovss	one(%rip), %xmm5
	vsubss	%xmm0, %xmm1, %xmm0	/* aliased, and every volatile is live */
	vaddss	%xmm2, %xmm0, %xmm0	/* 7 + 100 */
	vaddss	%xmm3, %xmm0, %xmm0
	vaddss	%xmm4, %xmm0, %xmm0
	vaddss	%xmm5, %xmm0, %xmm0	/* + 3 = 110 */
	vcvttss2si %xmm0, %eax
	addl	%ecx, %eax		/* + 11, only if the local was read first */
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
one:	.float 1.0
hundred:	.float 100.0
""")


# 39. The same program with the read moved AFTER the site, which must still
# be refused. It is not in PE_NAMES: the correct outcome is that the site
# keeps its VEX and the program dies of an illegal instruction on a CPU
# without AVX, which `check-pe`'s "every sample returns its number" cannot
# express. `check-spill` asserts 29 instead.
#
# **The assertion discriminates because a wrong answer is not 29.** If the
# liveness rule wrongly allowed the borrow, the site would lower, the VEX
# would be gone, nothing would fault, and the program would return 107 plus
# the bits of %xmm2 read as an integer. Refusing is the only route to 29.
PROGRAMS["regionread"] = (121, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	movl	$11, 48(%rsp)		/* the same local in the shadow */
	vmovss	three(%rip), %xmm0
	vmovss	ten(%rip), %xmm1
	vmovss	hundred(%rip), %xmm2
	vmovss	one(%rip), %xmm3
	vmovss	one(%rip), %xmm4
	vmovss	one(%rip), %xmm5
	vsubss	%xmm0, %xmm1, %xmm0	/* aliased; a borrow here destroys it */
	vaddss	%xmm2, %xmm0, %xmm0
	vaddss	%xmm3, %xmm0, %xmm0
	vaddss	%xmm4, %xmm0, %xmm0
	vaddss	%xmm5, %xmm0, %xmm0
	vcvttss2si %xmm0, %eax
	addl	48(%rsp), %eax		/* read AFTER the site: still live */
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
one:	.float 1.0
hundred:	.float 100.0
""")


# 40. Static TLS: does the loader allocate and zero the bytes we ask for?
#
# `project.md` has said since Finding 69 that raising the TLS directory's
# `SizeOfZeroFill` gives the rewriter per-thread bytes of its own, and that
# it is "proven under wine" -- and the tree held nothing that proved it. A
# measurement recorded only in prose cannot be taken again, so here it is as
# a program.
#
# Four things have to hold, and the exit code separates them: the loader
# must allocate a block and write an index; the block must contain the raw
# template this image ships; the 32 bytes past the template must be present
# and ZEROED; and they must be writable and read back.
#
# The zero check is the one that matters. Without it a program that read the
# template's own bytes back would pass, and the whole question is whether
# the loader honoured `SizeOfZeroFill` rather than merely copying raw data.
#
# **Both ends of the 32 are probed, not just the first four bytes.** With
# only the first probed, a `SizeOfZeroFill` of 8 passed as readily as one of
# 32 -- the test would have confirmed that SOME bytes arrived and said
# nothing about how many, which is the whole question. Reading and writing
# at offset 44 as well makes the answer depend on the field's value.
#
# 66 only if every part holds. 11 to 17 name which failed, so a failure says
# what the loader did rather than only that it did not work.
PROGRAMS["tlsslot"] = (66, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	movq	%gs:0x58, %rax		/* ThreadLocalStoragePointer */
	testq	%rax, %rax
	movl	$11, %ecx
	je	out			/* no TLS array at all */
	movl	tls_index(%rip), %edx
	movq	(%rax,%rdx,8), %rax	/* this module's block */
	testq	%rax, %rax
	movl	$12, %ecx
	je	out			/* no block for this module */
	movl	(%rax), %edx
	movl	$13, %ecx
	cmpl	$0x55667788, %edx
	jne	out			/* the raw template was not copied */
	movl	16(%rax), %edx
	movl	$14, %ecx
	testl	%edx, %edx
	jne	out			/* the zero-fill area is not zeroed */
	movl	44(%rax), %edx		/* the LAST four bytes of the 32 */
	movl	$15, %ecx
	testl	%edx, %edx
	jne	out			/* the block is not as big as we asked */
	movl	$0x5a5a5a5a, 16(%rax)
	movl	$0xa5a5a5a5, 44(%rax)
	movl	16(%rax), %edx
	movl	$16, %ecx
	cmpl	$0x5a5a5a5a, %edx
	jne	out			/* the first slot did not hold */
	movl	44(%rax), %edx
	movl	$17, %ecx
	cmpl	$0xa5a5a5a5, %edx
	jne	out			/* the last slot did not hold */
	movl	$66, %ecx
out:
	movl	%ecx, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
tls_raw:
	.long	0x55667788, 0x11223344
	.long	0, 0
tls_raw_end:
tls_index:
	.long	0
	.long	0
tls_callbacks:
	.quad	0
	.p2align 3
tls_directory:
	.quad	0, 0, 0, 0
	.long	0, 0
""")


# 41. Static TLS as a backing store: the site no other store can reach.
#
# `regionread` above is this program without the TLS directory, and it is
# refused: a leaf reserves no callee home space of its own, and its caller's
# shadow holds a local that is read AFTER the site, so `borrow_offset`
# answers None and the VEX survives. That is the residue `no home space to
# borrow` counts, and it is the largest named cause anywhere in it.
#
# What this borrows instead is sixteen bytes the LOADER gives every thread,
# past the end of this module's own TLS template, because the directory asks
# for them with `SizeOfZeroFill`. Reaching them costs two general-purpose
# registers and three instructions -- `gs:[0x58]` is a pointer that must be
# followed before it is indexed, and the index is in memory because the
# loader assigns it (Finding 139).
#
# **The two registers are not saved, and that is the whole mechanism.**
# There is nowhere to save a general-purpose register to that does not need
# a register to address, which is the circularity Finding 69 met. Finding
# 141 broke it by measuring that the registers are already dead: here
# `r10` and `r11` are named nowhere in the program, so the borrow destroys
# nothing.
#
# The A/B is the point and it is run both ways. `--spill=home` returns 29,
# the illegal-instruction death of a surviving VEX site, because no home
# space and no shadow can be lent. `--spill=tls` returns 121 -- and only if
# BOTH halves held: %xmm2 came back holding 100.0 from a per-thread slot,
# and the local in the shadow was still there to be added, because nothing
# touched it.
PROGRAMS["tlsspill"] = (121, """
	.text
	.globl _start
_start:
	subq	$40, %rsp		/* a frame, and no call: this is a leaf */
	vzeroupper
	movl	$11, 48(%rsp)		/* a local, kept in the caller's shadow */
	vmovss	three(%rip), %xmm0
	vmovss	ten(%rip), %xmm1
	vmovss	hundred(%rip), %xmm2	/* the register the borrow will take */
	vmovss	one(%rip), %xmm3
	vmovss	one(%rip), %xmm4
	vmovss	one(%rip), %xmm5
	vsubss	%xmm0, %xmm1, %xmm0	/* aliased; every volatile xmm is live */
	vaddss	%xmm2, %xmm0, %xmm0	/* 7 + 100, only if xmm2 came back */
	vaddss	%xmm3, %xmm0, %xmm0
	vaddss	%xmm4, %xmm0, %xmm0
	vaddss	%xmm5, %xmm0, %xmm0
	vcvttss2si %xmm0, %eax
	addl	48(%rsp), %eax		/* read AFTER the site: the shadow is
					   live, so it cannot be lent */
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
three:	.float 3.0
ten:	.float 10.0
one:	.float 1.0
hundred:	.float 100.0
	.p2align 4
tls_raw:
	.long	0x55667788, 0x11223344
	.long	0, 0
tls_raw_end:
tls_index:
	.long	0
	.long	0
tls_callbacks:
	.quad	0
	.p2align 3
tls_directory:
	.quad	0, 0, 0, 0
	.long	0, 0
""")


# 42. A 256-bit SPAN whose slots live in a per-thread block.
#
# `span_oracle` proves the span lowering computes the right answer with its
# slots at `(%rsp)`, and `tlsspill` proves `gs:[0x58]` addressing reaches a
# per-thread slot. Neither proves the two together, and the combination is
# what the collector emits wherever a function will lend no frame region --
# so this is the case that would otherwise be built and never run.
#
# A leaf, so there is no callee home space; and its caller's shadow holds a
# local read AFTER the span, so the shadow cannot be lent either. Both frame
# regions refuse, exactly as in `tlsspill`, which leaves the block.
#
# The answer is read from the LAST element of the result, which is in the
# UPPER half. A span that lost the upper half -- to a slot addressed wrongly,
# a block pointer clobbered mid-span, or an operand not moved by +16 --
# returns something else or faults. The low half's own arithmetic is checked
# by nothing here on purpose: `span_oracle` compares all 32 bytes, and what
# this fixture is for is the half that travels through memory.
#
# 8.0 + 80.0 = 88.0, plus the 11 kept in the shadow, is 99.
PROGRAMS["spanblock"] = (99, """
	.text
	.globl _start
_start:
	subq	$72, %rsp		/* a leaf: no callee home space */
	vzeroupper
	movl	$11, 80(%rsp)		/* a local, in the caller's shadow */
	vmovups	values(%rip), %ymm0	/* the span's load */
	vaddps	addend(%rip), %ymm0, %ymm0	/* memory-source arithmetic */
	vmovups	%ymm0, 8(%rsp)		/* the span's store */
	cvttss2si 36(%rsp), %eax	/* element 7, from the upper half */
	addl	80(%rsp), %eax		/* read AFTER the span: shadow is live */
	addq	$72, %rsp
	ret
func_end:
	.p2align 5
values:
	.float	1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0
addend:
	.float	10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0
	.p2align 4
tls_raw:
	.long	0x55667788, 0x11223344
	.long	0, 0
tls_raw_end:
tls_index:
	.long	0
	.long	0
tls_callbacks:
	.quad	0
	.p2align 3
tls_directory:
	.quad	0, 0, 0, 0
	.long	0, 0
""")


# 44. A REGION: a 256-bit load whose value is then used 128 bits at a time,
# so the span cannot close and the region carries the stretch instead.
#
# **The region strategy shipped with no fixture behind it.** Measured by
# running every fixture and collecting the strategy rows: 15 of the 16
# strategies Starfield uses are exercised by one and `region` was not -- 16
# windows and 93 sites lowered by code nothing had ever executed, in a
# strategy that has already shipped a defect (467 wrong lowerings, found by
# reading the bytes in the image rather than by any test).
#
# `regionlive` and `regionread` sound like they cover it and do not: they
# place a `spill`, and `--region=` controls whether a region may be BORROWED
# FROM, which is a different mechanism from the region lowering.
#
# **The shape is copied from a real region rather than guessed.** Nine
# invented shapes became spans -- the span is tried first and carries almost
# everything -- so the members of Starfield's own regions were dumped and
# one was copied. Every one of them looks like this:
#
#     vmovups 0x70(%rsp),%ymm0     a 256-bit load
#     vcomiss %xmm6,%xmm0          a 128-bit use of the same register
#
# A span walks from a load and must CLOSE on a 256-bit store; a 128-bit use
# stops it, and the region is bounded by the ABI instead -- at the call
# above, every ymm upper half is dead.
#
# 1..8 plus 10..80 is 11,22,33,44,55,66,77,88. Lane 4 is in the UPPER half,
# so 55 comes back only if bits 255:128 survived; lane 0 adds 11. A region
# that dropped the upper half returns 11, and one that never formed keeps
# its VEX and dies of an illegal instruction -- three distinguishable
# outcomes.
PROGRAMS["regioncarry"] = (66, """
	.text
	.globl _start
_start:
	subq	$72, %rsp
	vzeroupper
	call	helper			/* the region's start, and home space */
	vmovups	values(%rip), %ymm0
	vcomiss	%xmm0, %xmm0		/* 128 bits of it: no span can close */
	vaddps	addend(%rip), %ymm0, %ymm0
	vmovups	%ymm0, 8(%rsp)
	cvttss2si 24(%rsp), %eax	/* lane 4 = 55, from the upper half */
	cvttss2si 8(%rsp), %ecx		/* lane 0 = 11 */
	addl	%ecx, %eax		/* 66 */
	addq	$72, %rsp
	ret
helper:
	ret
func_end:
	.p2align 5
values:
	.float	1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0
addend:
	.float	10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0
	.p2align 4
tls_raw:
	.long	0x55667788, 0x11223344
	.long	0, 0
tls_raw_end:
tls_index:
	.long	0
	.long	0
tls_callbacks:
	.quad	0
	.p2align 3
tls_directory:
	.quad	0, 0, 0, 0
	.long	0, 0
""")


PROGRAMS["mxcsr"] = (55, """
	.text
	.globl _start
_start:
	subq	$56, %rsp
	vzeroupper
	movl	$0x5a5a5a5a, 8(%rsp)
	movl	$0x5a5a5a5a, 12(%rsp)
	movl	$0x5a5a5a5a, 16(%rsp)
	vstmxcsr 8(%rsp)		/* whatever the process is running with */
	movl	8(%rsp), %eax
	xorl	$0x8000, %eax		/* toggle FTZ; bits 16-31 stay zero */
	movl	%eax, 12(%rsp)
	vldmxcsr 12(%rsp)
	vstmxcsr 16(%rsp)
	vldmxcsr 8(%rsp)		/* leave it as it was found */
	movl	16(%rsp), %eax
	xorl	8(%rsp), %eax
	cmpl	$0x8000, %eax
	movl	$55, %eax
	movl	$11, %ecx
	cmovne	%ecx, %eax
	addq	$56, %rsp
	ret
func_end:
	.p2align 5
""")


# 35. A broadcast and every store that follows it, which is Finding 108's
# shape with the lesson of Findings 105 and 106 applied to it: a store does
# not end the value's life. MSVC emits the insert once and then fills eight
# consecutive fields with it, and only the first store was being taken.
#
# The three stores are 4, 5 and 5 bytes. The first cannot widen its window
# forwards -- the neighbour is another 256-bit store, which
# `moved_instruction` refuses -- so without the group it is refused and the
# two after it are refused for having no known upper half. They do have one:
# it is the same sixteen bytes as the low half, which is what the insert
# means.
#
# The poison is 96 bytes over exactly the three stores' extent, and the read
# back takes the LAST dword of each store's high half and the first of each
# low half -- six lanes, three stores, both halves of each. A store the run
# dropped leaves 0x5a5a5a5a in two of them.
PROGRAMS["splatrun"] = (87, """
	.text
	.globl _start
_start:
	subq	$200, %rsp
	vzeroupper
	movq	%rsp, %rax
	movl	$24, %edx
poison:
	movl	$0x5a5a5a5a, 32(%rax)
	addq	$4, %rax
	subl	$1, %edx
	jne	poison
	leaq	32(%rsp), %rcx		/* before the insert: the store after it
					   must be the very next instruction */
	vmovups	source(%rip), %xmm0	/* 1 2 3 8 */
	vinsertf128 $0x1, %xmm0, %ymm0, %ymm0	/* both halves now 1 2 3 8 */
	vmovups	%ymm0, (%rcx)		/* four bytes, and the run's head */
	vmovups	%ymm0, 0x20(%rcx)
	vmovups	%ymm0, 0x40(%rcx)
	movl	60(%rsp), %eax		/* 8 -- first store, HIGH half, lane 3 */
	addl	92(%rsp), %eax		/* 8 -- second store, HIGH half */
	addl	124(%rsp), %eax		/* 8 -- third store, HIGH half */
	addl	32(%rsp), %eax		/* 1 -- first store, low half, lane 0 */
	addl	64(%rsp), %eax		/* 1 -- second store, low half */
	addl	96(%rsp), %eax		/* 1 -- third store, low half */
	addl	$60, %eax		/* 27 + 60 = 87 */
	addq	$200, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 8
""")


# 36. A broadcast, one lane-wise operation against memory, and the store of
# the result -- the shape at 0x140454762 and eighteen more. All three
# instructions are refused today: the insert for having no store after it,
# the operation for being arithmetic on a 256-bit value, the store for
# having no known upper half.
#
# It needs no helper. Both halves of the splat are the same sixteen bytes,
# so the operation is done twice against the two halves of its memory
# operand, high half first, and the destination ends holding the low one.
#
# **The mask is the test.** Its two halves are different, so an operation
# that read the wrong half of memory, or a store that wrote the wrong half
# of the destination, changes the answer rather than hiding in it: the low
# half keeps only lane 0 and the high half keeps only lane 3.
PROGRAMS["splatop"] = (69, """
	.text
	.globl _start
_start:
	subq	$200, %rsp
	vzeroupper
	movl	$0xffffffff, 64(%rsp)	/* mask, low half: keep lane 0 */
	movl	$0, 68(%rsp)
	movl	$0, 72(%rsp)
	movl	$0, 76(%rsp)
	movl	$0, 80(%rsp)		/* mask, high half: keep lane 3 */
	movl	$0, 84(%rsp)
	movl	$0, 88(%rsp)
	movl	$0xffffffff, 92(%rsp)
	movl	$0x5a5a5a5a, 96(%rsp)	/* poison the whole destination */
	movl	$0x5a5a5a5a, 100(%rsp)
	movl	$0x5a5a5a5a, 104(%rsp)
	movl	$0x5a5a5a5a, 108(%rsp)
	movl	$0x5a5a5a5a, 112(%rsp)
	movl	$0x5a5a5a5a, 116(%rsp)
	movl	$0x5a5a5a5a, 120(%rsp)
	movl	$0x5a5a5a5a, 124(%rsp)
	vmovups	source(%rip), %xmm2	/* 1 2 3 8 */
	vinsertf128 $0x1, %xmm2, %ymm2, %ymm2	/* both halves 1 2 3 8 */
	vandps	64(%rsp), %ymm2, %ymm0
	vmovups	%ymm0, 96(%rsp)
	movl	96(%rsp), %eax		/* 1 -- low half, lane 0 */
	addl	124(%rsp), %eax		/* 8 -- HIGH half, lane 3 */
	addl	$60, %eax		/* 9 + 60 = 69 */
	addq	$200, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 8
""")


# 37. `vextractf128 $0x1` inside a run. The instruction is cross-lane by
# definition -- it moves the upper 128 bits into the low half of an xmm --
# and that is exactly why it becomes trivial once a run is holding the upper
# half in a helper: the lanes have already been separated, and the whole
# thing is `movaps H(S),%xmmD`.
#
# The run needs a store to be a run at all, so the ymm is stored whole as
# well; the extracted half is stored separately by a 128-bit move the
# patcher takes in place.
#
# **Both halves of the constant are different and both are read back**, at
# lane 0 of the low half and lane 3 of the high, from the 32-byte store and
# again from the extracted 16 bytes. An extract that handed over the low
# half, or the wrong helper, changes two of the four.
PROGRAMS["extract"] = (97, """
	.text
	.globl _start
_start:
	subq	$200, %rsp
	vzeroupper
	movq	%rsp, %rax
	movl	$20, %edx
poison:
	movl	$0x5a5a5a5a, 32(%rax)
	addq	$4, %rax
	subl	$1, %edx
	jne	poison
	vmovups	source(%rip), %ymm0	/* 1 2 3 8 / 16 5 6 40 */
	vextractf128 $0x1, %ymm0, %xmm2	/* the HIGH half into xmm2 */
	vmovups	%ymm0, 32(%rsp)		/* the store the run needs */
	vmovups	%xmm2, 96(%rsp)		/* 128-bit, patched in place */
	movl	32(%rsp), %eax		/* 1  -- the store's low half */
	addl	60(%rsp), %eax		/* 40 -- the store's HIGH half */
	addl	96(%rsp), %eax		/* 16 -- the extract, lane 0 */
	addl	108(%rsp), %eax		/* 40 -- the extract, lane 3 */
	addq	$200, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 8
	.long 16, 5, 6, 40
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


def build(path, text, code_size, handler=None, frame=0, readonly=False,
          symbols=None):
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
	#
	# **And unless the program declares a `frame`.** "No unwind codes" is
	# honest enough for a program nothing unwinds, but `copy_reaches_home`
	# reads the frame size out of these codes to work out where the callee
	# home space sits -- so a program written to test THAT needs codes that
	# tell the truth, or it passes against a frame of zero and proves
	# nothing. See Finding 98.
	codes = b""
	count = 0
	if frame:
		if frame % 8 or not 8 <= frame <= 128:
			raise SystemExit(f"pe_build.py: frame {frame} is not a small "
			                 f"multiple of 8")
		# UWOP_ALLOC_SMALL, and the array is padded to an even node count.
		codes = struct.pack("<BB", 0, (((frame - 8) // 8) << 4) | 2) + b"\0\0"
		count = 1
	if handler is None:
		xdata = struct.pack("<BBBB", 1, 0, count, 0) + codes
	else:
		xdata = struct.pack("<BBBB", 1 | (1 << 3), 0, count, 0) + codes \
			+ struct.pack("<I", SECTION_ALIGNMENT + handler)

	sections = []
	rva = SECTION_ALIGNMENT
	offset = HEADER_SIZE
	# **`.text` is writable here so that a sample can keep its scratch buffer
	# in it**, which most of them do -- `sink(%rip)` is simpler to read back
	# than a stack offset. A program testing a READ-ONLY constant cannot have
	# that: `constant_ymm` decides on the section flag, so a writable section
	# is not a constant pool and the strategy would decline the very thing
	# the program exists to exercise. Those samples say so in `READONLY` and
	# keep their scratch on the stack.
	for name, body, flags in ((b".text", text,
	                           CODE_READONLY if readonly else CODE),
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

	# **Static TLS, where a sample asks for it by naming the labels.** The
	# structures live in `.text` like every other sample's data, because
	# that is the only section whose offsets `assemble` reports back -- and
	# the directory's fields are absolute VAs rather than RVAs, which is
	# workable here only because these images have no ASLR and load at
	# `IMAGE_BASE`.
	#
	# It is here to make a claim in `project.md` re-takeable. That document
	# has said static TLS is "proven under wine" since Finding 69 and the
	# tree held nothing that demonstrated it, which is a measurement
	# recorded in prose with no way to take it again.
	tls_directory = None
	if symbols and "tls_directory" in symbols:
		wanted = ("tls_raw", "tls_raw_end", "tls_index", "tls_callbacks",
		          "tls_directory")
		missing = [n for n in wanted if n not in symbols]
		if missing:
			raise SystemExit(f"pe_build: tls sample lacks {missing}")
		base = IMAGE_BASE + sections[0][1]
		at = symbols["tls_directory"]
		text = bytearray(text)
		struct.pack_into("<QQQQII", text, at,
		                 base + symbols["tls_raw"],
		                 base + symbols["tls_raw_end"],
		                 base + symbols["tls_index"],
		                 base + symbols["tls_callbacks"],
		                 TLS_ZERO_FILL,
		                 0x00100000)		# ALIGN_16BYTES
		text = bytes(text)
		sections[0] = sections[0][:3] + (text,) + sections[0][4:]
		tls_directory = (sections[0][1] + at, 40)

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
	# Data directory 9 is the TLS directory.
	if tls_directory is not None:
		struct.pack_into("<II", image, opt + 112 + 9 * 8, *tls_directory)

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
	if len(argv) > 3:
		# **How many bytes the TLS directory asks the loader to zero**, so
		# that `check-tls` can run the A/B that makes `tlsslot` mean
		# anything: a smaller number must not return 66.
		global TLS_ZERO_FILL
		TLS_ZERO_FILL = int(argv[3], 0)
	if name not in PROGRAMS:
		print(f"pe_build.py: no program {name!r}", file=sys.stderr)
		return 2
	expected, source = PROGRAMS[name]
	text, symbols = assemble(source)
	code_size = symbols["func_end"]
	sections = build(output, text, code_size, symbols.get("handler"),
	                 FRAMES.get(name, 0), name in READONLY, symbols)
	print(f"pe_build: {name} -> {output}, {len(text)} bytes of .text, "
	      f"function is {code_size} of them, expected exit code {expected}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
