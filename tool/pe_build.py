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

class _Programs(dict):
	"""A dict that refuses a second assignment to the same name.

	**A duplicate key silently replaces a fixture**, and every gate naming
	it keeps passing while testing something else. That nearly happened
	here: `lanemem` was reused for a second shape, both entries expected
	77, and `check-shadow-pe` would have gone on reporting a `vperm2f128`
	result while running an arithmetic one. The collision was found by an
	unrelated edit failing to match its anchor.

	Refusing at definition time is the only place it can be caught for
	free -- once the dict is built the two are indistinguishable.
	Finding 257.
	"""

	def __setitem__(self, name, value):
		if name in self:
			raise SystemExit(f"pe_build.py: {name!r} is defined twice; a "
			                 f"second definition would silently replace the "
			                 f"first and every gate naming it would keep "
			                 f"passing")
		super().__setitem__(name, value)


PROGRAMS = _Programs()

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
          "regioncarry": 72, "swallowcall": 40, "condswallow": 40,
          "regionread": 40, "tlsspill": 40, "spanblock": 72,
          "dataisland": 40, "repairdrop": 40, "conservative": 40, "switchtable": 40, "laneregadd": 40, "crossregion": 40, "laneswap": 40, "lanemem": 40, "bcast": 40, "permmem": 40, "permil": 40, "onegpr": 40, "nogpr": 56, "noxmm": 56, "runborrow": 56, "regmove": 56, "nonvol": 72, "nonvolbad": 72, "unwindsave": 72, "memsrc": 56}

# **Samples whose prologue saves a non-volatile xmm**, as `(register,
# offset from rsp)`. The sample must really do the save in its code AND
# carry a `prologue_end` label, because the unwind codes below are a claim
# about the instructions rather than a decoration. Finding 255.
SAVES = {"nonvol": ((6, 0x20), (7, 0x30)),
         "unwindsave": ((6, 0x20), (7, 0x30))}

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


# 45. A window that swallows a CALL, and the call must still return.
#
# **440 calls are swallowed in Starfield and no fixture swallowed one.**
# `verify` reports 384 in the shipped stub section -- "every one an
# instruction a window covered and re-emitted" -- so the path runs in
# production and nothing had ever executed it. Finding 86 built it; the
# evidence was structural only, and structural cannot see whether the
# DISPLACEMENT was recomputed for the stub's address or whether the RETURN
# ADDRESS leads somewhere execution continues.
#
# **The helper is after `func_end` and is pure SSE**, and both halves of
# that matter. `func_end` bounds the `.pdata` function, so the helper is
# outside it and is not rewritten -- which isolates this to the call's
# re-emission rather than testing the helper's lowering as well. And pure
# SSE means an AVX-less CPU can execute it unmodified.
#
# The first version put the helper INSIDE the function and it returned 5
# rather than faulting. The rewriter had believed `rsp` sat at `_start`'s
# frame throughout, so the helper's stub borrowed the callee home space at
# `(%rsp)` -- which, inside a function entered by `call`, is the RETURN
# ADDRESS. It saved `%xmm1` over it and restored `%xmm1` from it, and the
# return address was gone. That is a fixture that puts a call target inside
# its caller's `.pdata` range, which a real binary does not do: a called
# helper is its own function, a leaf, and a leaf lends nothing -- which is
# the `no home space to borrow` refusal doing its job.
#
# The `jne` blocks widening backwards; a four-byte site cannot hold a jump,
# so the window widens forward over the five-byte call and becomes nine.
#
# 9/3 = 3 in %xmm5, the helper cubes it to 27, and 27 + 3 = 30.
PROGRAMS["swallowcall"] = (30, """
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
	vdivss	%xmm3, %xmm1, %xmm5	/* four bytes: 9/3 = 3, the site */
	call	helper			/* five bytes, swallowed into the stub */
	vaddss	%xmm5, %xmm0, %xmm0	/* 27 + 3 = 30 */
	vcvttss2si %xmm0, %eax
	addq	$40, %rsp
	ret
wrong:
	movl	$1, %eax
	addq	$40, %rsp
	ret
func_end:
helper:
	movaps	%xmm5, %xmm0		/* pure SSE: outside .pdata, not rewritten */
	mulss	%xmm5, %xmm0		/* 3 * 3 = 9 */
	mulss	%xmm3, %xmm0		/* 9 * 3 = 27 */
	ret
	.p2align 4
nine:	.float 9.0
three:	.float 3.0
""")


# 46. Four conditional branches, each swallowed and each TAKEN.
#
# **The suite swallowed `jmp` and `je` and nothing else.** Starfield
# swallows `jbe` 182 times, `ja` 132, `jb` 126 and `jae` 66, and a
# re-emitted branch whose displacement was not recomputed goes to the wrong
# place -- the program does not compute a wrong value, it transfers control
# wrongly. `verify` proves every target still BEGINS an instruction, which
# a wrong displacement satisfies by landing on a different valid one.
#
# **Each branch is TAKEN, and the first version's were not.** With all four
# arranged to fall through, the fixture passed a sabotage that moved every
# re-emitted target by two bytes: a branch nobody takes does not care where
# it points. That is a fixture naming the hazard in its title and
# exercising only the safe path.
#
# **And each branch targets the label after its own site**, which is what
# gets it swallowed rather than the instruction after. The version before
# that put a `cmp` there and every window widened FORWARD over it instead,
# swallowing four `cmp`s and no branch at all -- a window takes the
# cheapest widening available, and only a branch target blocks the forward
# one.
#
# So the site each branch skips is a POISON: taken, `%xmm5` keeps the 3 it
# was given and the answer is 3; a branch re-emitted to the wrong place
# either runs the poison, making it 9999, or lands somewhere that faults.
# Finding 219.
PROGRAMS["condswallow"] = (3, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	nine(%rip), %xmm1
	vmovss	three(%rip), %xmm3
	vmovss	huge(%rip), %xmm4
	vdivss	%xmm3, %xmm1, %xmm5	/* 9/3 = 3, the value under test */
	movl	$2, %ecx
	cmpl	$1, %ecx		/* 2 is above 1 */
	ja	b1			/* TAKEN, and swallowed */
	vdivss	%xmm3, %xmm4, %xmm5	/* poison, skipped */
b1:
	cmpl	$1, %ecx
	jae	b2			/* TAKEN, and swallowed */
	vdivss	%xmm3, %xmm4, %xmm5	/* poison, skipped */
b2:
	xorl	%ecx, %ecx
	cmpl	$1, %ecx		/* 0 is below 1 */
	jb	b3			/* TAKEN, and swallowed */
	vdivss	%xmm3, %xmm4, %xmm5	/* poison, skipped */
b3:
	cmpl	$1, %ecx
	jbe	b4			/* TAKEN, and swallowed */
	vdivss	%xmm3, %xmm4, %xmm5	/* poison, skipped */
b4:
	vcvttss2si %xmm5, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
nine:	.float 9.0
three:	.float 3.0
huge:	.float 29997.0
""")


# A data island inside `.text` whose bytes carry a VEX prefix. `c5 32 00`
# and `c4 4f 00 cb` are taken from Starfield, where 180 such sequences sit
# in the constant pools a linear sweep walks into (Finding 8), and 99 of
# them reach the candidate loop: `decode_vex` rejects on LENGTH alone --
# under three bytes, or a `c4` under four -- and never checks that the map
# field is one of the three that exist. `c5 32 00` has map 1 and opcode
# 00, which is not an instruction, and `c4 4f 00 cb` has map 0x0f, which
# does not exist.
#
# **Nothing was ever corrupted by this and a behavioural fixture would
# therefore pass without the guard.** What turned those 99 away was the
# mnemonic: objdump writes `(bad)`, every strategy is keyed on a mnemonic,
# and no table has an entry for it. That is the far wall of the room, not
# the door -- and the 256-bit strategies already branch on `vex["L"]`,
# read straight out of the unvalidated prefix. So the assertion in
# `verify` is structural rather than behavioural: no `(bad)` row may reach
# the candidate loop at all. Measured on this fixture: 1 without the guard,
# at 0x140001037, and 0 with it. One rather than four because the sweep
# aligns its own way -- `40 c5 32 00` is read as a REX byte and rejected on
# the first test, and the lone `c4` is rejected on length -- which is the
# reason to read the count off a run instead of predicting it from the
# bytes written here.
#
# The island is read as data as well, so that a rewriter which did patch
# it is caught by the answer and not only by the assertion.
PROGRAMS["dataisland"] = (7, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	vmovss	three(%rip), %xmm1
	vaddss	%xmm1, %xmm1, %xmm2
	vcvttss2si %xmm2, %eax		/* 6 */
	movzbl	island(%rip), %ecx	/* 0xc5 = 197 */
	subl	$196, %ecx		/* 1, and 0 if the byte moved */
	addl	%ecx, %eax		/* 7 */
	addq	$40, %rsp
	ret
func_end:
	.p2align 4
three:	.float 3.0
island:
	.byte 0xc5, 0x32, 0x00
	.byte 0xc5, 0x32, 0x00
	.byte 0xc4, 0x4f, 0x00, 0xcb
	.byte 0xc5, 0x2a, 0x00
""")


# The repair pass, which nothing else reaches. `repaired_placement` drops a
# window whose swallowed VEX.128 write a surviving 256-bit instruction still
# needs the zeroing of -- 184 reverts and 141 withheld windows on Starfield,
# the mechanism Findings 185, 187, 194, 197 and 198 all turn on, and
# Finding 231 measured its fixture coverage at zero: disabling the repair
# changed none of the 39 images.
#
# **The shape is forced by what cannot run here.** The repair only matters
# where a 256-bit instruction SURVIVES, and a surviving 256-bit instruction
# faults on this host, so a fixture that executes one returns 29 and proves
# nothing. The reader therefore sits on a path that is never taken: present
# for the analysis, absent from the run. The answer is 77 whether or not the
# repair happens, which is the point -- this is a fixture for `verify` and
# for the `staleupper` control, not a behavioural test, and the behaviour is
# here only so that a rewrite which corrupts the live path is still caught.
#
# `vaddss` is three-operand, so it wants a stub, and at four bytes its window
# must widen by one to fit a five-byte jump -- which swallows the `vxorps`
# after it. That `vxorps` is a VEX.128 write, so it zeroes ymm0[255:128] in
# the original and does not once re-emitted as legacy SSE inside the stub.
#
# **The whole cluster sits on the dead path, and the first version did not.**
# The repair works by WITHHOLDING that window, which leaves the `vaddss`
# un-lowered -- and a surviving VEX instruction faults on this host, so the
# fixture returned 29 with the mechanism working perfectly. Anything the
# repair may refuse to lower has to be somewhere the program never reaches.
PROGRAMS["repairdrop"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* the live path: a pair, lowered */
	vmovups	%ymm0, (%rdi)
	movl	$1, %eax
	testl	%eax, %eax
	jne	after			/* always taken */
	vmovss	one(%rip), %xmm1
	vmovss	two(%rip), %xmm2
	vaddss	%xmm1, %xmm2, %xmm3	/* three-operand: wants a stub, widens */
	vxorps	%xmm0, %xmm0, %xmm0	/* swallowed, and it zeroes ymm0[255:128] */
	vaddps	%ymm0, %ymm0, %ymm4	/* survives, and reads that zeroing */
after:
	movl	16(%rdi), %eax		/* 77 from the copy */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
one:	.float 1.0
two:	.float 2.0
source:	.long 1, 2, 3, 4
	.long 77, 6, 7, 8
""")


# A conservative candidate, which nothing else produces. `apply` keeps a
# reader the walk COULD NOT RULE OUT in its VEX form at the price of the
# site (Finding 198), and `verify` fails if one was narrowed anyway. No
# corrupted image can express "a repair that did not happen", so the check
# needs a code control -- and a code control needs an input that makes one.
# Swept across all 39 fixtures at zero before this existed.
#
# Three things have to line up. The `call` is the ABI bound: the upper half
# of every ymm is volatile across one, so `conservative_producers` searches
# back only that far. The `lea` puts `target` in `blocked` -- an address
# something can reach -- while naming no branch that goes there, so the walk
# arrives at a join whose predecessors it cannot enumerate and gives up.
# And the `vxorps` is a VEX.128 write with a same-length SSE form, so it is
# patched in place, which is what stops it zeroing [255:128].
#
# The reader sits on a never-taken path for Finding 233's reason: the repair
# leaves sites un-lowered, and surviving VEX faults on this host.
PROGRAMS["conservative"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* the live path: a pair, lowered */
	vmovups	%ymm0, (%rdi)
	call	helper			/* the ABI bound for the search back */
	leaq	target(%rip), %rax	/* blocks `target`, naming no branch to it */
	movl	$1, %ecx
	testl	%ecx, %ecx
	jne	after			/* always taken */
	vxorps	%xmm0, %xmm0, %xmm0	/* patched in place; stops zeroing */
target:
	vaddps	%ymm0, %ymm0, %ymm1	/* survives; its source is unresolvable */
after:
	movl	16(%rdi), %eax		/* 77 from the copy */
	addq	$40, %rsp
	ret
helper:
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 77, 6, 7, 8
""")


# A switch dispatch, which no fixture had. `switch_targets` reads the
# dispatch rather than guessing at the table -- Finding 174 measured the
# guessing approach at chance, 3 of 14,574 targets real -- and `verify`
# fails when dispatches are recognised and no table resolves, because that
# is what a broken resolver looks like. Finding 196 built that floor after
# an image base added twice returned zero tables for a whole build and the
# totals read as neutral.
#
# The pattern it recognises is exact, so the fixture writes it exactly:
# %r9 holds __ImageBase, the table entries are RVAs, and the dispatch is
# mov/add/jmp. The table sits after `func_end` with its entries written as
# `target - 0x140000000`, which is what an MSVC x64 table holds.
#
# Never executed: `jmp *%rcx` on the live path would leave the answer at the
# mercy of the table, and the check is static -- a dispatch is recognised by
# reading the listing, not by running it.
PROGRAMS["switchtable"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm0		/* the live path: a pair, lowered */
	vmovups	%ymm0, (%rdi)
	movl	16(%rdi), %eax		/* 77 from the copy */
	addq	$40, %rsp
	ret
dead:
	movabsq	$0x140000000, %r9	/* __ImageBase */
	xorl	%eax, %eax
	movl	0x1040(%r9,%rax,4), %ecx
	addq	%r9, %rcx
	jmp	*%rcx
case0:
	nop
case1:
	nop
	ret
func_end:
	.p2align 5
table:	.long	0x103a			/* case0, as an RVA */
	.long	0x103b			/* case1 */
source:	.long 1, 2, 3, 4
	.long 77, 6, 7, 8
""")


# Register-source 256-bit arithmetic, which is refused without permanent
# slots and lowered with them. `vpaddd %ymm1,%ymm2,%ymm2` is the `lanereg`
# shape: the second source is a REGISTER, so its upper half lives in a slot
# of its own and the operation has to reach it there. A span's slot table is
# local, so it answers None and the member is refused -- the single refusal
# behind 1,875 "arithmetic rather than a copy" sites.
#
# The answer is deliberately in the UPPER half: element 4 sits at offset 16,
# so 77 can only be right if the high halves were added and stored. A
# lowering that operated on the low half twice returns 7.
PROGRAMS["laneregadd"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm1
	vmovups	0x20(%rsi), %ymm2
	vpaddd	%ymm1, %ymm2, %ymm2	/* lanereg: second source is a register */
	vmovups	%ymm2, (%rdi)
	movl	16(%rdi), %eax		/* upper half: 70 + 7 = 77 */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 70, 6, 7, 8
	.long 0, 0, 0, 0
	.long 7, 0, 0, 0
""")


# The invariant's control: a region that reads a ymm defined OUTSIDE it.
# `region_members` refuses this today, and the refusal is soundness rather
# than bookkeeping -- 3,378 sites after a call, 1,079 after a jump, 926 at a
# branch target. A permanent slot only carries the right value if whatever
# defined the register outside also maintained it.
#
# The branch is what splits the two regions: `here` is a branch target, so
# the region below it did not define %ymm1. The answer is again in the upper
# half -- 70 + 7 -- so a region that reads an unmaintained slot returns 7,
# and one reading a maintained slot returns 77. That difference is the whole
# invariant, expressed as a number.
PROGRAMS["crossregion"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	movq	%rsp, %rdi
	vmovups	(%rsi), %ymm1		/* defines %ymm1 */
	movl	$1, %ecx
	testl	%ecx, %ecx
	jne	here			/* always taken; `here` is a branch target */
here:
	vmovups	0x20(%rsi), %ymm2	/* a new region starts here */
	vpaddd	%ymm1, %ymm2, %ymm2	/* reads %ymm1, defined outside it */
	vmovups	%ymm2, (%rdi)
	movl	16(%rdi), %eax		/* upper half: 70 + 7 = 77 */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 70, 6, 7, 8
	.long 0, 0, 0, 0
	.long 7, 0, 0, 0
	/* A TLS directory, because a PERMANENT slot has nowhere else to
	   live: the callee home space is two slots wide and a borrowed
	   frame lasts one window, while a register's slot has to outlive
	   every window in the image. Without this the unconditional
	   lowering refuses every site here and the control cannot fire --
	   which is what it did when it was first written. The zero fill
	   this asks for is a build argument, so `check-shadow-pe` can run
	   the A/B that makes the number mean something. Finding 246. */
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


# The lane operations, routed to slot moves rather than refused.
# `vextractf128 $1` reads the source's upper half -- a slot -- and
# `vinsertf128 $1` writes the destination's, so each is a 16-byte move once
# the halves are separately addressable. 510 sites in Starfield are these
# four mnemonics, and every one was refused as "no legacy encoding" until
# Finding 246 read that set correctly: it forbids PREFIX-STRIPPING them, not
# emitting them.
#
# **Two answers, because the shape has two halves and only one is obvious.**
# 77 comes back from the extracted upper half, which is the move. 0 comes
# back from ymm2's upper half, which is the part a careless lowering drops:
# `vextractf128` writes %xmm2 with a VEX.128 instruction, and a VEX.128
# write ZEROES bits 255:128 -- so the destination's own slot has to be
# zeroed, not left holding what it had. Summing them means either half
# failing changes the answer.
#
# **ymm2 is loaded with 222 first, and that load IS the test.** The
# per-thread block arrives zero-filled from the loader, so a slot nothing
# ever wrote reads 0 anyway -- the first draft read 0 out of an untouched
# slot and called that proof the zeroing had happened. Sabotaged, it scored
# 77: the term could not fail. With 222 in the slot beforehand it can.
PROGRAMS["laneswap"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vmovups	0x40(%rsi), %ymm2	/* POISON: 222 into ymm2's slot, so the */
					/* zeroing has something to clear */
	vmovups	0x20(%rsi), %ymm3	/* defined, so nothing reads a stale half */
	vmovups	(%rsi), %ymm1
	vextractf128 $0x1, %ymm1, %xmm2	/* xmm2 = ymm1 upper; ymm2 upper = 0 */
	vinsertf128 $0x1, %xmm2, %ymm3, %ymm3	/* ymm3 upper = xmm2 */
	vmovups	%ymm3, (%rdi)
	vmovups	%ymm2, 0x20(%rdi)
	movl	16(%rdi), %eax		/* 77, carried through both lane ops */
	addl	48(%rdi), %eax		/* + 0, because the VEX.128 write zeroed */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 1, 2, 3, 4
	.long 77, 6, 7, 8
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 111, 111, 111, 111
	.long 222, 222, 222, 222
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# The three lane forms `laneswap` does not reach: a lane permute, and the
# memory operands of extract and insert. All three are slot moves once the
# halves are separately addressable, and none of them is arithmetic.
#
# **Two answers again, from two different mechanisms.** 70 comes back
# through `vperm2f128` and `vextractf128`-to-memory: the permute swaps
# ymm0's halves, so the half extracted to memory is the one that started
# LOW, and a permute that did nothing would store 7 instead. 7 comes back
# through `vinsertf128`-from-memory. 10 comes back through a SECOND
# permute with `$0x20`, which selects the other source's low half -- a
# different selector value, so the twelve sites in Starfield are covered
# by their two immediates rather than by one. 60 + 7 + 10 = 77, so none of
# the three can fail quietly.
#
# **The extract-to-memory form writes no ymm**, which is the difference
# from the register form: there is no destination slot to zero, because
# the destination is sixteen bytes of memory.
PROGRAMS["lanemem"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vmovups	(%rsi), %ymm0		/* lo = 60, hi = 7 */
	vmovups	0x40(%rsi), %ymm1	/* defined, so nothing reads a stale half */
	vmovups	0x60(%rsi), %ymm2	/* lo = 10 */
	vperm2f128 $0x1, %ymm0, %ymm0, %ymm0	/* swap: lo = 7, hi = 60 */
	vextractf128 $0x1, %ymm0, (%rdi)	/* upper half -> memory, = 60 */
	vinsertf128 $0x1, 0x20(%rsi), %ymm1, %ymm1	/* ymm1 upper = 7 */
	vmovups	%ymm1, 0x20(%rdi)
	vperm2f128 $0x20, %ymm2, %ymm1, %ymm3	/* hi = ymm2 LOW, the other
						   selector: 2 rather than 1 */
	vmovups	%ymm3, 0x40(%rdi)
	movl	(%rdi), %eax		/* 60, only if the permute really swapped */
	addl	48(%rdi), %eax		/* + 7 from the insert's memory operand */
	addl	80(%rdi), %eax		/* + 10 from the $0x20 selector */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 60, 0, 0, 0
	.long 7, 0, 0, 0
	.long 7, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 10, 0, 0, 0
	.long 0, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# The broadcasts, which under this representation are the ordinary SSE
# broadcast plus one more store: both halves of the result are the same
# 128 bits, so the slot copy IS the 256-bit part. All four forms that occur
# in Starfield, and each answer is read from the LAST LANE of the UPPER
# half. Upper, so a lowering that produced a correct low half and no slot
# scores zero; last, so one that set lane 0 and skipped the shuffle scores
# zero too. The first draft read lane 0 and would have passed a broadcast
# that broadcast nothing.
#
# **Only ymm0 and xmm1 are used**, deliberately: Win64 makes just xmm0
# through xmm5 volatile, so a fixture naming six of them leaves the
# lowering no helper and is refused for a reason that has nothing to do
# with broadcasts. The first draft did exactly that.
#
# 20 + 7 + 40 + 10 = 77: vbroadcastss from memory, vbroadcastss from a
# register, vpbroadcastd from a register, and vbroadcastsd from memory,
# which needs no shuffle because movddup duplicates the low quadword by
# itself.
PROGRAMS["bcast"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vbroadcastss (%rsi), %ymm0		/* 20, from memory */
	vmovups	%ymm0, (%rdi)
	vmovups	0x10(%rsi), %xmm1
	vbroadcastss %xmm1, %ymm0		/* 7, from a register */
	vmovups	%ymm0, 0x20(%rdi)
	vmovups	0x20(%rsi), %xmm1
	vpbroadcastd %xmm1, %ymm0		/* 40, integer domain */
	vmovups	%ymm0, 0x40(%rdi)
	vbroadcastsd 0x30(%rsi), %ymm0		/* 10, 64-bit, no shuffle */
	vmovups	%ymm0, 0x60(%rdi)
	movl	28(%rdi), %eax			/* the LAST lane of each upper half: */
	addl	60(%rdi), %eax			/* upper, so the slot copy is tested, */
	addl	92(%rdi), %eax			/* and last, so the splat is too -- at */
	addl	120(%rdi), %eax			/* lane 0 a missing shuffle would pass */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 20, 0, 0, 0
	.long 7, 0, 0, 0
	.long 40, 0, 0, 0
	.long 10, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# The cross-lane 64-bit permutes, whose source is memory -- which is what
# makes them easy rather than hard. Every quadword of the source has its
# own address, so each output quadword is a 64-bit load and no shuffle unit
# is involved: `movsd` fills the low half and zeroes the high one, `movhpd`
# then fills the high one.
#
# Source quadwords are 1, 3, 5, 70. `$0x1b` reverses them to 70, 5, 3, 1
# and `$0x4e` swaps the 128-bit halves to 5, 70, 1, 3, so every selector
# value 0 through 3 is exercised. 70 + 1 + 5 + 1 = 77, and two of the four
# terms are read from an UPPER half, which is a slot.
#
# **The read positions are deliberately ASYMMETRIC between the two
# immediates.** `$0x1b` and `$0x4e` differ by exactly one bit per selector,
# so a lowering that inverted that bit would swap the two results -- and
# the first draft read the same offsets from both, which makes the sum
# invariant under exactly that swap. It scored 77 with the selector
# sabotaged. Reading offset 0 from one and offsets 8 and 24 from the other
# breaks the symmetry: the sabotage now scores 81.
#
# The third site uses a SIB memory operand, because `offset_operand` has to
# grow a displacement on an operand that has none and the base+index form
# is where that is easiest to get wrong.
PROGRAMS["permmem"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	xorl	%eax, %eax
	vpermq	$0x1b, (%rsi), %ymm0		/* reverse: 70, 4, 2, 1 */
	vmovups	%ymm0, (%rdi)
	vpermq	$0x4e, (%rsi), %ymm0		/* swap halves: 4, 70, 1, 2 */
	vmovups	%ymm0, 0x20(%rdi)
	vpermpd	$0x1b, (%rsi,%rax,8), %ymm0	/* the same, through a SIB */
	vmovups	%ymm0, 0x40(%rdi)
	movl	(%rdi), %eax			/* 70 */
	addl	48(%rdi), %eax			/* 1, an UPPER half */
	addl	72(%rdi), %eax			/* 5 */
	addl	88(%rdi), %eax			/* 1, an UPPER half */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.quad 1, 3, 5, 70
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# The variable-control in-lane permute. `vpermilps` permutes within each
# 128-bit half by that half's own control, and never across -- which is
# what makes the 256-bit form exactly two of the 128-bit one rather than a
# new problem. `lower_permilps` already emits the 128-bit sequence; this
# fixture is about calling it twice and moving the halves.
#
# Operand order is control, data, destination, and it is the easy thing to
# get backwards: VEX.vvvv holds the DATA and r/m the CONTROL, which is the
# opposite way round from vpermd. Reversed, it permutes the control by the
# data -- nonsense that still runs.
#
# data     = 5, 2, 3, 4 | 70, 2, 0, 0
# control  = 0, 0, 0, 0 | 0x101, 0x104, 0, 0
#
# **The control values carry rubbish above bit 1 on purpose.** The SDM says
# bits 31:2 of each element are ignored and the compiler really does emit
# controls with junk up there, so 0x101 must select element 1 and 0x104
# element 0. A lowering that skipped the mask would index with 0x101 and
# read somewhere else entirely.
#
# 5 from the low half, then 2 and 70 from the upper half, which is a slot.
PROGRAMS["permil"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vmovups	(%rsi), %ymm0		/* data */
	vmovups	0x20(%rsi), %ymm1	/* control, with rubbish above bit 1 */
	vpermilps %ymm1, %ymm0, %ymm2
	vmovups	%ymm2, (%rdi)
	movl	(%rdi), %eax		/* 5, the low half's own permute */
	addl	16(%rdi), %eax		/* 2, upper half element 0 */
	addl	20(%rdi), %eax		/* 70, upper half element 1 */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 5, 2, 3, 4
	.long 70, 2, 0, 0
	.long 0, 0, 0, 0
	.long 0x101, 0x104, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# One dead general-purpose register, which is what the block pointer costs
# after Finding 247 and half of what it cost before. Six of the seven
# volatile GPRs are live across the site -- set above it, read below it --
# so only r11 is dead, and the old sequence would have refused this outright
# with "fewer than two dead GPRs for the block".
#
# The register the index borrows is therefore a LIVE one, saved into an xmm
# and put back three instructions later. It is the borrowed register's own
# value that a missing restore destroys: the tool takes the lowest volatile
# it did not pick for the block, which is rax, and rax is the accumulator.
#
# **rax holds 40 rather than 1, and that is not arbitrary.** What a missing
# restore leaves in it is the module's TLS index, a small number -- with
# rax = 1 the sabotage scored 76, one away from passing, and it would have
# PASSED outright on a machine whose index happened to be 1. At 40 the
# margin is the whole term and no plausible index can close it.
#
# 40 + 2 + 3 + 4 + 5 + 6 = 60, and 60 + 17 = 77, the 17 from an upper half.
PROGRAMS["onegpr"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	movl	$40, %eax		/* large on purpose: see below */
	movl	$2, %ecx
	movl	$3, %edx
	movl	$4, %r8d
	movl	$5, %r9d
	movl	$6, %r10d
	vbroadcastss (%rsi), %ymm0	/* 56, and it needs the block */
	vmovups	%ymm0, (%rdi)
	addl	%ecx, %eax		/* every one of the six is read here, */
	addl	%edx, %eax		/* so all six were live ACROSS the site */
	addl	%r8d, %eax
	addl	%r9d, %eax
	addl	%r10d, %eax		/* eax = 60 */
	addl	16(%rdi), %eax		/* + 17 from the upper half */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 17, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# NO dead general-purpose register at all, which is 949 of the sites the
# unconditional lowering refuses and 415 of them have what this one has: a
# callee home space. All seven volatiles are set above the site and read
# below it, so every one is live across it and `window_gpr_free` is empty.
#
# The `call` is not decoration -- it is what makes the 32 bytes of home
# space real. Without it the function is a leaf, nothing can be lent, and
# the site is refused.
#
# **The two registers borrowed need only be UNNAMED in the window, not
# dead**, because they are saved and given back. The window here names only
# rsi and rdi, both non-volatile, so the tool takes r11 for the block and
# r10 for the index -- and both hold values the sum needs.
#
# 10 + 1 + 1 + 1 + 1 + 20 + 40 = 74, and 74 + 3 = 77. r10 carries 20 and
# r11 carries 40, so a lost index restore and a lost block restore are
# separately visible and neither is one away from passing: what a missing
# index restore leaves behind is the small TLS index, and a missing block
# restore leaves a whole pointer.
PROGRAMS["nogpr"] = (77, """
	.text
	.globl _start
_start:
	subq	$56, %rsp		/* 32 of home space, and alignment */
	vzeroupper
	call	helper			/* makes the home space real */
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	movl	$10, %eax
	movl	$1, %ecx
	movl	$1, %edx
	movl	$1, %r8d
	movl	$1, %r9d
	movl	$20, %r10d		/* the index borrow takes this one */
	movl	$40, %r11d		/* and the block borrow this one */
	vbroadcastss (%rsi), %ymm0	/* the site: nothing is dead here */
	vmovups	%ymm0, (%rdi)
	addl	%ecx, %eax		/* all seven are read below the site, */
	addl	%edx, %eax		/* which is what makes them live across */
	addl	%r8d, %eax
	addl	%r9d, %eax
	addl	%r10d, %eax
	addl	%r11d, %eax		/* eax = 74 */
	addl	16(%rdi), %eax		/* + 3 from an upper half */
	addq	$56, %rsp
	ret
helper:
	ret
func_end:
	.p2align 5
source:	.long 3, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# NO free vector register, which is 1,455 of the sites the unconditional
# lowering refuses. All six volatile xmm are loaded above the site and read
# below it, so `region_helpers` offers nothing -- Win64 makes only xmm0
# through xmm5 volatile, and every one of them is live here.
#
# The site is a load and a store, and **a 16-byte move needs no vector
# register**: two 8-byte `mov`s through a general-purpose one do the same
# work. That is the difference between this and the arithmetic shapes,
# which have to apply a packed operation and cannot be helped this way.
#
# The loads use legacy `movss` rather than `vmovss` so that holding the
# vector registers busy does not itself create 256-bit work to lower.
#
# **The distance between the load and the store is what makes this reach
# the unconditional lowering at all.** Adjacent, they are a `pair`, which
# takes the site long before `unit` is offered -- the first draft scored 77
# with the unit path never asked, and the second had `pair` span them across
# a swallowed branch and lower one site while `unit` took the other, which
# is incoherent and died at 29. Six instructions apart they are two windows
# of one member each, which is the shape 883 of the 1,455 refused windows
# have.
#
# 6 x 2.0 = 12 proves all six survived, and 65 comes from the upper half,
# which only exists if the move through a GPR carried it. 12 + 65 = 77.
PROGRAMS["noxmm"] = (77, """
	.text
	.globl _start
_start:
	subq	$56, %rsp
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	movss	two(%rip), %xmm0
	movss	two(%rip), %xmm1
	movss	two(%rip), %xmm2
	movss	two(%rip), %xmm3
	movss	two(%rip), %xmm4
	movss	two(%rip), %xmm5
	vmovups	(%rsi), %ymm7		/* the load: no xmm is free, so its */
					/* upper half moves through a GPR */
	addss	%xmm1, %xmm0		/* every volatile xmm is read here, */
	addss	%xmm2, %xmm0		/* which is what makes them live across */
	addss	%xmm3, %xmm0		/* -- and the distance keeps a `pair` */
	addss	%xmm4, %xmm0		/* from spanning the two sites */
	addss	%xmm5, %xmm0
	cvttss2si %xmm0, %eax		/* 12, if all six survived */
	vextractf128 $0x1, %ymm7, %xmm6	/* reads the slot the mover wrote */
	movups	%xmm6, (%rdi)
	addl	(%rdi), %eax		/* + 65, only if the GPR carried it */
	addq	$56, %rsp
	ret
func_end:
	.p2align 4
two:	.float 2.0
	.p2align 5
source:	.long 0, 0, 0, 0
	.long 65, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# The run-borrow defect of Finding 252, kept as its own fixture because a
# control shared with another test is a control that dies when that test is
# reshaped -- which is exactly what happened: `noxmm` grew a `vextractf128`
# to read the slot, stopped being a load-and-store run, and both the fixed
# and the broken tool then answered 29.
#
# Six instructions between the load and the store, all naming volatile xmm,
# so `assign_helpers` borrows a register and the passengers are re-emitted
# between the carry-load and the carry-store. Broken, the run borrows one
# the passengers name and the program computes **10**; fixed, it declines
# the site, the VEX survives and the program dies at **29**.
PROGRAMS["runborrow"] = (77, """
	.text
	.globl _start
_start:
	subq	$56, %rsp
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	movss	two(%rip), %xmm0
	movss	two(%rip), %xmm1
	movss	two(%rip), %xmm2
	movss	two(%rip), %xmm3
	movss	two(%rip), %xmm4
	movss	two(%rip), %xmm5
	vmovups	(%rsi), %ymm7		/* the run's load ... */
	addss	%xmm1, %xmm0		/* ... six passengers, every one of */
	addss	%xmm2, %xmm0		/* which names a volatile xmm ... */
	addss	%xmm3, %xmm0
	addss	%xmm4, %xmm0
	addss	%xmm5, %xmm0
	cvttss2si %xmm0, %eax		/* 12 */
	vmovups	%ymm7, (%rdi)		/* ... and the run's store */
	addl	16(%rdi), %eax		/* + 65 from the upper half */
	addq	$56, %rsp
	ret
func_end:
	.p2align 4
two:	.float 2.0
	.p2align 5
source:	.long 0, 0, 0, 0
	.long 65, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
""")


# A 256-bit register-to-register move, which the shape walk refused as "a
# register-to-register move" along with 57 conversions and a mask extract
# that are nothing of the kind. Only the moves are moves: the low half is
# the same instruction one width down and the upper half is sixteen bytes
# from one slot to another, wanting no vector register of its own.
#
# The answer travels ymm1 -> slot(1) -> slot(2) -> xmm6 -> memory, so a
# move that copied only the low half, or copied the wrong slot, returns 0.
#
# **ymm3 is loaded in between, and that load is the whole test.** A load
# leaves the upper half it just moved sitting in the helper, so a `regmove`
# that WROTE the helper to its destination slot without READING its source
# slot first would still write the right value -- the first draft of this
# fixture scored 77 with exactly that sabotage applied, right by
# coincidence. Loading ymm3 puts 11 in the helper instead, so the missing
# read now scores 11.
PROGRAMS["regmove"] = (77, """
	.text
	.globl _start
_start:
	subq	$56, %rsp
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vmovups	(%rsi), %ymm1		/* slot(1) gets 77 */
	vmovups	0x20(%rsi), %ymm3	/* slot(3) gets 11, and the helper now */
					/* holds 11 rather than 77 */
	vmovups	%ymm1, %ymm2		/* the move: slot(1) -> slot(2) */
	vextractf128 $0x1, %ymm2, %xmm6	/* reads slot(2) */
	movups	%xmm6, (%rdi)
	movl	(%rdi), %eax
	addq	$56, %rsp
	ret
func_end:
	.p2align 5
source:	.long 0, 0, 0, 0
	.long 77, 0, 0, 0
	.long 0, 0, 0, 0
	.long 11, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# NO free vector register at all, and an ARITHMETIC site -- which a
# general-purpose mover cannot serve, because a packed operation has to
# happen in a vector register whatever else is free.
#
# What serves it is xmm6 and xmm7, which this function SAVES in its
# prologue and declares with UWOP_SAVE_XMM128. That declaration is the
# whole precondition: on a fault the unwinder restores those two from this
# function's own slots, so a borrow that clobbers them cannot lose the
# caller's value. Finding 124 refused xmm6-xmm15 outright for want of
# exactly that guarantee; Finding 255 makes it a condition instead.
#
# All six volatile xmm are held live across the site by the movss loads
# above and the addss chain below, so `region_helpers` offers nothing.
#
# 12 from the six volatiles, 3 from xmm6 and 62 from the upper half of the
# vpaddd, which only exists if a borrowed register carried it.
#
# **xmm6 holds 3.0 ACROSS the site, and that is deliberate.** The first
# draft loaded it only in the prologue and never read it again, so a borrow
# that clobbered it without saving would have gone unnoticed -- the fixture
# would have proved the borrow happened and not that it was given back.
PROGRAMS["nonvol"] = (77, """
	.text
	.globl _start
_start:
	subq	$72, %rsp
	movups	%xmm6, 0x20(%rsp)	/* the prologue saves, and the unwind */
	movups	%xmm7, 0x30(%rsp)	/* codes say so -- see SAVES */
prologue_end:
	call	helper			/* makes the home space real */
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	movss	three(%rip), %xmm6	/* LIVE across the site: the borrow */
					/* must give this back */
	movss	two(%rip), %xmm0
	movss	two(%rip), %xmm1
	movss	two(%rip), %xmm2
	movss	two(%rip), %xmm3
	movss	two(%rip), %xmm4
	movss	two(%rip), %xmm5
	vmovups	(%rsi), %ymm8
	vmovups	0x20(%rsi), %ymm9
	vpaddd	%ymm8, %ymm9, %ymm9	/* lanereg: wants TWO vector registers */
	vmovups	%ymm9, (%rdi)
	addss	%xmm1, %xmm0		/* every volatile xmm is read here */
	addss	%xmm2, %xmm0
	addss	%xmm3, %xmm0
	addss	%xmm4, %xmm0
	addss	%xmm5, %xmm0
	addss	%xmm6, %xmm0		/* + 3, only if xmm6 came back */
	cvttss2si %xmm0, %eax		/* 15 */
	addl	16(%rdi), %eax		/* + 62 from the upper half */
	movups	0x20(%rsp), %xmm6
	movups	0x30(%rsp), %xmm7
	addq	$72, %rsp
	ret
helper:
	ret
func_end:
	.p2align 4
two:	.float 2.0
three:	.float 3.0
	.p2align 5
source:	.long 0, 0, 0, 0
	.long 57, 0, 0, 0
	.long 0, 0, 0, 0
	.long 5, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# **The same program with the unwind codes taken away**, and the whole of
# the safety condition expressed as a number. `nonvol` and `nonvolbad` are
# byte-identical code; only `SAVES` differs, so only the unwind data does.
#
# With the codes, the rewriter may borrow xmm6 and returns 77. Without
# them, borrowing would be the Finding 124 hazard -- a fault would have the
# unwinder restore xmm6 from data that does not mention it, losing the
# caller's value -- so the site must be REFUSED and the program dies at 29.
#
# A control for the precondition rather than for the mechanism: it fails if
# the tool ever borrows a register the function does not promise to save.
PROGRAMS["nonvolbad"] = PROGRAMS["nonvol"]


# **An in-lane operation with an immediate, all three narrowings.** Finding
# 271: 108 sites, every one per-lane, and the opcode decides how each is
# narrowed. This exercises all three rather than the common one:
#
#   vpslld $1,%ymm1,%ymm2   the shift group with src != dst, so the low
#                           half needs `movaps S,D` before the operation
#   vpsrld $2,%ymm1,%ymm1   the shift group with src == dst, no move
#   vpshufd $1,%ymm3,%ymm4  ModRM.reg is a register, so it strips straight
#
# 77 is 8 + 16 + 1 + 2 + 30 + 20, one term per half of each site, and every
# term is read. A shift applied to the wrong operand, an immediate dropped
# from one half, or an upper half taken from the wrong slot each change a
# term rather than cancelling: there is no pair here that sums the same
# way round.
# **Four operands with an immediate: `lanereg3` plus a selector.** Finding
# 273. `vshufps $0,%ymm2,%ymm1,%ymm0` takes dst[0] and dst[1] from src1 and
# dst[2] and dst[3] from src2, within each 128-bit lane -- so reading dword
# 0 and dword 2 of each lane separates the two sources AND the two lanes,
# which is four distinct terms from one site.
#
# 77 is 5 + 5 + 11 + 7 + 7 + 42, and **two of the four terms are read twice
# on purpose.** Read once each, swapping the two sources exchanges dst[0]
# with dst[2] WITHIN a lane and the pair sums identically -- measured: the
# sabotage that swaps the slots returned 77 and the fixture said nothing.
# A weight of two on one term per lane is what makes a swap change the
# total, and the first version of this comment claimed that property
# without anybody having checked it.
#
# **The branch is what makes it need the slots**, borrowed from
# `crossregion`: `here` is a branch target, so the region holding the
# shuffle did not define %ymm1 and only a PERMANENT slot carries its upper
# half. Without one the fixture answered 77 anyway -- a contiguous
# load-shuffle-store is a span, and the span keeps the upper half in a
# helper. That version proved nothing about this path.
PROGRAMS["immreg3"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vmovups	(%rsi), %ymm1		/* src1: low 5, high 7 */
	movl	$1, %ecx		/* src2 is low 11, high 42 */
	testl	%ecx, %ecx
	jne	here			/* always taken; `here` is a target */
here:
	vmovups	0x20(%rsi), %ymm2	/* a new region starts here */
	vshufps	$0, %ymm2, %ymm1, %ymm0	/* reads %ymm1, defined outside */
	vmovups	%ymm0, (%rdi)
	movl	(%rdi), %eax		/* dst[0] low  = src1 low  = 5 */
	addl	(%rdi), %eax		/* twice, so a swap cannot cancel */
	addl	8(%rdi), %eax		/* dst[2] low  = src2 low  = 11 */
	addl	16(%rdi), %eax		/* dst[0] high = src1 high = 7 */
	addl	16(%rdi), %eax		/* twice, for the same reason */
	addl	24(%rdi), %eax		/* dst[2] high = src2 high = 42 */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 5, 0, 0, 0
	.long 7, 0, 0, 0
	.long 11, 0, 0, 0
	.long 42, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# **A site that can only widen BACKWARD.** Finding 277. `vpaddd` between
# two ymm is four bytes, a jump needs five, and the instruction after it
# transfers control -- so the forward walk ends under five and the window
# has to start on the instruction before instead, swallowing the site.
#
# `movl $70,%ecx` is that instruction, and it is read afterwards: a window
# that swallowed it without re-emitting it returns 7 rather than 77, which
# separates "the neighbour was carried" from "the site was lowered". The
# upper half supplies the other term, so a slot that is not maintained
# gives 70.
PROGRAMS["backward"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vmovups	(%rsi), %ymm1
	vmovups	0x20(%rsi), %ymm2
	movl	$70, %ecx		/* swallowed by the backward window */
	vpaddd	%ymm1, %ymm2, %ymm2	/* four bytes; forward is blocked */
	jmp	here			/* the next instruction transfers control */
here:
	vmovups	%ymm2, (%rdi)
	movl	16(%rdi), %eax		/* the upper half: 0 + 7 = 7 */
	addl	%ecx, %eax		/* + 70, only if the movl was re-emitted */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 0, 0, 0, 0
	.long 7, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# **A site that can only widen backward, and must not.** The shape is
# `backward`'s with one thing added: a never-taken `jne` names the site,
# so the site's own address is a branch target. A window widening back
# over the instruction before it starts a jump THERE, which buries the
# site's first byte in the middle of that jump -- and anything reaching
# the site by the branch lands inside an instruction.
#
# So `unit_candidate` refuses, the site keeps its VEX form, and the
# program answers 77 along the taken path without ever executing it.
# That is the fixture passing, and it is also what makes it a control:
# run the same tree under `ANTI_AVX_SABOTAGE=backtarget` and the window
# is built, placed, and `verify` reports a direct branch target that no
# longer begins an instruction.
#
# **The site is on dead code deliberately.** A guard whose job is to
# REFUSE leaves the site unlowered, so a fixture that executed it would
# take SIGILL on a host without AVX -- the guard working would look
# exactly like the guard failing. The taken path exercises the slot
# maintenance instead (70 from the low half, 7 from the upper), which is
# what shows the rewrite happened at all.
PROGRAMS["backtarget"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vmovups	(%rsi), %ymm1
	vmovups	0x20(%rsi), %ymm2
	vmovups	%ymm2, (%rdi)
	movl	(%rdi), %eax		/* 70, the low half */
	movl	16(%rdi), %edx		/* 7, the upper half through a slot */
	addl	%edx, %eax		/* 77 */
	xorl	%edx, %edx
	testl	%edx, %edx
	jne	site			/* never taken; names `site` a target */
	addq	$40, %rsp
	ret
	movl	$70, %ecx		/* what a backward window would swallow */
site:
	vpaddd	%ymm1, %ymm2, %ymm2	/* four bytes; forward is blocked */
	jmp	after			/* the next instruction transfers control */
after:
	vmovups	%ymm2, (%rdi)
	movl	$1, %eax
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 70, 0, 0, 0
	.long 7, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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

PROGRAMS["immreg"] = (77, """
	.text
	.globl _start
_start:
	subq	$40, %rsp
	vzeroupper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vmovups	(%rsi), %ymm1		/* low 4, high 8 */
	vpslld	$1, %ymm1, %ymm2	/* src != dst: 8 and 16 */
	vmovups	%ymm2, (%rdi)
	vpsrld	$2, %ymm1, %ymm1	/* src == dst: 1 and 2 */
	vmovups	%ymm1, 0x20(%rdi)
	vmovups	0x20(%rsi), %ymm3
	vpshufd	$1, %ymm3, %ymm4	/* dst[0] = src[1], per lane: 30 and 20 */
	vmovups	%ymm4, 0x40(%rdi)
	movl	(%rdi), %eax		/* 8 */
	addl	16(%rdi), %eax		/* + 16 */
	addl	0x20(%rdi), %eax	/* + 1 */
	addl	0x30(%rdi), %eax	/* + 2 */
	addl	0x40(%rdi), %eax	/* + 30 */
	addl	0x50(%rdi), %eax	/* + 20 = 77 */
	addq	$40, %rsp
	ret
func_end:
	.p2align 5
source:	.long 4, 0, 0, 0
	.long 8, 0, 0, 0
	.long 0, 30, 0, 0
	.long 0, 20, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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



# **What an unwind would actually read.** The non-volatile borrow is safe
# because a fault has the unwinder restore xmm6 from THIS function's own
# UWOP_SAVE_XMM128 slot -- so the one thing that would destroy the
# guarantee is the borrow writing over that slot. The home space the borrow
# uses and the save area are different regions of the frame, but "different
# today" is not a property of the next binary, and one Starfield function
# declares xmm10 saved at offset +0, which is exactly where a callee home
# space begins.
#
# This puts 7.0 in xmm6 BEFORE the declared save, so the slot holds a value
# the test knows, runs an arithmetic site that forces the borrow, and then
# reads the slot back. If the stub wrote into the save area the 7 is gone.
#
# 7 from the save slot and 70 from the upper half of the vpaddd = 77. It
# does not fault, and cannot: a fixture that faults inside a stub needs SEH
# the samples here have no imports for. What this proves is the tool-side
# half -- that the bytes the unwinder would read are still the caller's --
# and `nonvolbad` proves the other half, that the borrow is only taken
# where those bytes exist at all.
PROGRAMS["unwindsave"] = (77, """
	.text
	.globl _start
_start:
	movss	seven(%rip), %xmm6	/* stands in for the caller's value */
	subq	$72, %rsp
	movups	%xmm6, 0x20(%rsp)	/* the DECLARED save: what an unwind */
	movups	%xmm7, 0x30(%rsp)	/* would restore xmm6 from */
prologue_end:
	call	helper
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	movss	two(%rip), %xmm0
	movss	two(%rip), %xmm1
	movss	two(%rip), %xmm2
	movss	two(%rip), %xmm3
	movss	two(%rip), %xmm4
	movss	two(%rip), %xmm5
	vmovups	(%rsi), %ymm8
	vmovups	0x20(%rsi), %ymm9
	vpaddd	%ymm8, %ymm9, %ymm9	/* forces the xmm6/xmm7 borrow */
	vmovups	%ymm9, (%rdi)
	addss	%xmm1, %xmm0		/* holds every volatile xmm live */
	addss	%xmm2, %xmm0
	addss	%xmm3, %xmm0
	addss	%xmm4, %xmm0
	addss	%xmm5, %xmm0
	movss	0x20(%rsp), %xmm10	/* the save slot, read back */
	cvttss2si %xmm10, %eax		/* 7 if the stub left it alone */
	addl	16(%rdi), %eax		/* + 70 from the upper half */
	movups	0x20(%rsp), %xmm6
	movups	0x30(%rsp), %xmm7
	addq	$72, %rsp
	ret
helper:
	ret
func_end:
	.p2align 4
two:	.float 2.0
seven:	.float 7.0
	.p2align 5
source:	.long 0, 0, 0, 0
	.long 65, 0, 0, 0
	.long 0, 0, 0, 0
	.long 5, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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


# `op mem,%ymmS1,%ymmD` -- arithmetic against memory with a destination of
# its own, which is 296 refusals and the largest shape left. SSE has no
# three-operand form, so the low half is `movaps S1,D; op mem,D` and the
# upper half is S1's slot into a helper, the operation against memory plus
# sixteen, and the helper into D's slot. Two different slots, which is the
# whole difference from the `lane` shape beside it.
#
# ymm1 is left UNTOUCHED and read afterwards, because a lowering that wrote
# the result back into the source instead of the destination would still
# give the right answer at %ymm2 and be wrong -- 5 comes back only if the
# source survived.
#
# 12 from the destination's LOW half, 60 from its upper and 5 from the
# source's = 77.
#
# **The low half is read, and the destination is poisoned with 100 first.**
# The first draft read only upper halves, so removing the `movaps S1,D`
# that SSE needs for a three-operand form changed nothing and scored 77 --
# it tested the upper half twice and the copy not at all. It also declared
# 77 while the data summed to 65, the comment having been copied from a
# fixture with six volatile loads this one does not have.
PROGRAMS["memsrc"] = (77, """
	.text
	.globl _start
_start:
	subq	$56, %rsp
	leaq	source(%rip), %rsi
	leaq	sink(%rip), %rdi
	vmovups	0x40(%rsi), %ymm2	/* POISON: 100 in the destination's low */
					/* half, so a missing copy is definite */
	vmovups	0x20(%rsi), %ymm1	/* src1: low 5, upper 5 */
	vpaddd	(%rsi), %ymm1, %ymm2	/* mem,S1,D with D of its own */
	vmovups	%ymm2, (%rdi)
	vmovups	%ymm1, 0x20(%rdi)	/* the source must be unharmed */
	movl	(%rdi), %eax		/* 7 + 5 = 12, the LOW half */
	addl	16(%rdi), %eax		/* + 55 + 5 = 60, the upper half */
	addl	48(%rdi), %eax		/* + 5, the source's own upper half */
	addq	$56, %rsp
	ret
func_end:
	.p2align 5
source:	.long 7, 0, 0, 0
	.long 55, 0, 0, 0
	.long 5, 0, 0, 0
	.long 5, 0, 0, 0
	.long 100, 0, 0, 0
	.long 0, 0, 0, 0
	.p2align 5
sink:	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
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
          symbols=None, saves=(), saves_end=0):
	"""Write a PE whose entry point is the start of `text`.

	`saves` is `[(xmm register, byte offset from rsp)]` for a sample whose
	prologue really does save those registers, and `saves_end` is how far
	into the function the prologue runs. See the `UWOP_SAVE_XMM128` note
	below for why a fixture would want them.
	"""
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
	# **`UWOP_SAVE_XMM128`, which is what makes a non-volatile borrow legal
	# rather than lucky.** The rewriter borrows xmm6-xmm15 only where the
	# enclosing function's own unwind data says it saves the register, so a
	# fixture testing that path has to carry the code -- and carrying it is
	# not decoration: it is the whole precondition. Two slots per save, the
	# register in the info field, the offset in units of sixteen.
	#
	# The prologue length is set to cover them, because a save recorded at
	# an offset past the prologue is a claim the unwinder would reject.
	# Finding 255.
	prologue = 0
	if saves:
		for register, where in saves:
			if where % 16:
				raise SystemExit(f"pe_build.py: xmm save at {where} is not "
				                 f"sixteen-byte aligned")
			codes = struct.pack("<BBH", saves_end, (register << 4) | 8,
			                    where // 16) + codes
			count += 2
		prologue = saves_end
	if handler is None:
		xdata = struct.pack("<BBBB", 1, prologue, count, 0) + codes
	else:
		xdata = struct.pack("<BBBB", 1 | (1 << 3), prologue, count, 0) \
			+ codes + struct.pack("<I", SECTION_ALIGNMENT + handler)

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
	                 FRAMES.get(name, 0), name in READONLY, symbols,
	                 SAVES.get(name, ()), symbols.get("prologue_end", 0))
	print(f"pe_build: {name} -> {output}, {len(text)} bytes of .text, "
	      f"function is {code_size} of them, expected exit code {expected}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
