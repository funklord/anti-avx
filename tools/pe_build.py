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
# RIP-relative displacement, so tools/lowering_cases.py cannot generate it --
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
