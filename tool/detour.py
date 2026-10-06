#!/usr/bin/env python3
"""Detours: a stub section, and a jump at every site that will not fit.

tool/patch.py rewrites the sites whose SSE form is no longer than the VEX
one. Everything else that HAS a lowering comes here -- Class C by
construction, and the class A and B sites whose SSE encoding happens to be
one byte longer. Class C is the obvious case -- `vaddss %xmm2,%xmm1,%xmm0` is four bytes
and becomes `movaps` plus `addss`, which is seven -- so the expansion has to
live somewhere else and the site has to jump to it.

**A near jump is five bytes**, so overwriting a five-byte instruction with
one leaves both its start and its end address exactly where they were, and
no address changes meaning. The four-byte register-to-register forms have to
swallow a neighbour to make room, which is safe only where nothing can
branch to the address that ends up inside the window. tool/targets.py
enumerates what can be branched to, including the switch tables that hold
table-relative offsets no relocation records.

**Which neighbour is a choice, and both directions are used.** Widening
forward keeps the window's first byte where the site already is and swallows
the instruction after it, so that instruction is the one that must be
unreachable. Widening backward puts the first byte on the previous
instruction and swallows the site itself. The second reaches 3,237 sites the
first cannot, because a compiler branches to the top of a block far more
often than into the middle of one -- and because the instruction after a
site is frequently a call or a jump, which cannot be swallowed at all.

The stubs go in a new section appended to the image. Adding one is cheap:
the section table has room for eleven more entries, and nothing else in the
file moves.

Two details are easy to get wrong and both are fatal.

  * A RIP-relative operand moved into a stub is now a different distance
    from its target, so its displacement has to be recomputed. Every site
    with a memory operand has one.
  * The jump back has to land on the instruction *after* the original, not
    after the jump that replaced it. They differ whenever the site was
    longer than five bytes.

  plan    <binary> <listing>            what would be detoured
  apply   <binary> <listing> <out>      in-place patches plus detours
  verify  <original> <patched>          the invariants
  census  <binary> <listing> <patched>  what survives, and why
"""

import bisect
import os
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict, deque

HERE = __import__("pathlib").Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lower
import isa_guard
import outside
import patch as inplace
import scratch as scratch_finder
import targets as target_set

# A memory operand based on rsp; group 1 is its displacement if it has one.
RSP_MEMORY = re.compile(r"(-?0x[0-9a-f]+)?\(%rsp\)")
# `rsp` copied into another register. The register is then a pointer into
# this frame, and where it points decides whether the home space is still
# safe -- which is what `taint_offsets` works out rather than assuming.
RSP_COPY = re.compile(r"^%rsp,\s*%(r[a-z0-9]+)$")
# A memory operand and the register it is based on; group 1 is the
# displacement where one is printed.
MEMORY_BASE = re.compile(r"(-?0x[0-9a-f]+)?\(%(r[a-z0-9]+)\)")
# An operand with an index register, whose address cannot be resolved here.
INDEXED_BASE = re.compile(r"\(%(r[a-z0-9]+),")
# An immediate into a register, which is how a frame pointer gets walked.
IMMEDIATE_TO_REGISTER = re.compile(
	r"^\$(-?0x[0-9a-f]+|-?\d+),\s*%(r[a-z0-9]+)$")
# The 32-bit names. A write through one zeroes the upper half, so it
# DESTROYS a frame pointer rather than deriving another -- which makes it a
# kill. An 8- or 16-bit write leaves most of the pointer intact and is not.
WIDE32 = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
NUMBERED_NARROW = re.compile(r"^r\d+[dwb]$")
NARROW_TO_WIDE = {"eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
                  "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
                  "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
                  "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
                  "esi": "rsi", "si": "rsi", "sil": "rsi",
                  "edi": "rdi", "di": "rdi", "dil": "rdi",
                  "ebp": "rbp", "bp": "rbp", "bpl": "rbp"}
IMPLICIT_RAX = {"imul", "mul", "idiv", "div", "cqto", "cltq", "cwtl"}
# **These write no register at all**, only flags, so a copy of `rsp` in what
# looks like their destination operand survives them untouched. Reading that
# operand as a write gave up on 553 functions doing nothing to the pointer.
# Finding 101.
FLAGS_ONLY = {"test", "testb", "testw", "testl", "testq",
              "cmp", "cmpb", "cmpw", "cmpl", "cmpq"}
# **These overwrite their destination without reading it**, so they end a
# pointer's life rather than deriving another from it, exactly as `mov`
# does. `lea` missing from here gave up on 2,959 -- the largest single cause
# by a wide margin, and the reason the first measurement of this analysis
# read as 1,420 sites lost to arithmetic.
OVERWRITES = {"lea", "vpextrq", "vpextrd", "movzbl", "movzwl", "movsbl",
              "movswl", "movslq", "movzbq", "movzwq", "movsbq", "movswq"}


def canonical(name):
	"""The 64-bit register a narrow name writes into."""
	name = name.lstrip("%")
	if name in NARROW_TO_WIDE:
		return NARROW_TO_WIDE[name]
	if NUMBERED_NARROW.match(name):
		return name[:-1]
	return name


def immediate_step(mnemonic, operands, destination):
	"""How far `add`/`sub` of an immediate moves `destination`, or None."""
	if mnemonic not in ("add", "addq", "sub", "subq"):
		return None
	match = IMMEDIATE_TO_REGISTER.match(operands)
	if not match or "%" + match.group(2) != destination:
		return None
	text = match.group(1)
	value = int(text, 16) if "x" in text else int(text)
	if abs(value) > 1 << 31:
		return None
	return -value if mnemonic.startswith("sub") else value


JMP_REL32 = 0xE9
SECTION_NAME = b".avxsse\0"
# CODE | EXECUTE | READ
SECTION_FLAGS = 0x60000020
DATA_NAME = b".avxdata\0"[:8]
# INITIALIZED_DATA | READ | WRITE, and deliberately not EXECUTE.
DATA_FLAGS = 0xC0000040
SECTION_ALIGNMENT = 0x1000


def registers_of(vex, tail):
	"""(destination, first source) register numbers from a VEX encoding."""
	modrm = tail[1]
	destination = (vex["R"] << 3) | ((modrm >> 3) & 7)
	return destination, vex["vvvv"]


def rip_relative(tail):
	"""True if the memory operand is RIP+disp32."""
	modrm = tail[1]
	return ((modrm >> 6) & 3) == 0 and (modrm & 7) == 5


def encode_movaps(destination, source):
	"""movaps source,destination -- 0F 28 /r, with REX where needed."""
	out = bytearray()
	rex = 0x40 | ((destination >> 3) << 2) | (source >> 3)
	if rex != 0x40:
		out.append(rex)
	out += b"\x0f\x28"
	out.append(0xC0 | ((destination & 7) << 3) | (source & 7))
	return bytes(out)


def encode_movdqa(destination, source):
	"""movdqa source,destination -- 66 0F 6F /r, with REX where needed.

	movaps would move the same bits in one byte less. movdqa is used anyway
	because the instructions that need this are integer ones, and Westmere
	charges a bypass delay for a value crossing between the integer and
	floating-point domains.
	"""
	out = bytearray(b"\x66")
	rex = 0x40 | ((destination >> 3) << 2) | (source >> 3)
	if rex != 0x40:
		out.append(rex)
	out += b"\x0f\x6f"
	out.append(0xC0 | ((destination & 7) << 3) | (source & 7))
	return bytes(out)


def lower_vvvv_shift(vex, encoding, operands):
	"""The shift-by-immediate forms, whose destination is in vvvv.

	VEX puts the destination in vvvv and uses modrm.reg as an opcode
	extension, so modrm.rm names the *source*. That is why these were
	refused outright: dropping the VEX prefix leaves an SSE instruction
	whose destination is the source, which writes the wrong register while
	looking entirely reasonable.

	The equal-register case patches in place -- the two encodings are the
	same length, `c5 f1 72 d1 02` against `66 0f 72 d1 02`. What reaches
	here is the other one, which needs the source copied first and the
	shift's rm field pointed at the destination.

	323 sites, and they were invisible: `collect` skipped this whole class
	without counting it, so they were part of the residue project.md could
	not account for.
	"""
	tail = encoding[vex["length"]:]
	if len(tail) < 2 or ((tail[1] >> 6) & 3) != 3:
		return None			# a memory source is not this shape
	registers = [o for o in inplace.split_operands(operands)
	             if not o.startswith("$")]
	if len(registers) != 2:
		return None
	destination = vex["vvvv"]
	source = (vex["B"] << 3) | (tail[1] & 7)
	if destination == source:
		return inplace.sse_encoding(vex, tail)

	body = bytearray(encode_movdqa(destination, source))
	moved = dict(vex, B=destination >> 3)
	pointed = bytes([tail[0], (tail[1] & 0xF8) | (destination & 7)]) + tail[2:]
	operation = inplace.sse_encoding(moved, pointed)
	if operation is None:
		return None
	return bytes(body + operation)


def encode_rr(prefix, opcode, reg, rm, immediate=None):
	"""A register-to-register SSE instruction, with REX only where needed."""
	out = bytearray()
	if prefix is not None:
		out.append(prefix)
	rex = 0x40 | ((reg >> 3) << 2) | (rm >> 3)
	if rex != 0x40:
		out.append(rex)
	out += opcode
	out.append(0xC0 | ((reg & 7) << 3) | (rm & 7))
	if immediate is not None:
		out.append(immediate)
	return bytes(out)


FMA_PATTERN = re.compile(r"^vf(n?)(maddsub|msubadd|madd|msub)(132|213|231)"
                          r"([sp][sd])$")

# The legacy prefix each element type needs.
FMA_PREFIX = {"ps": None, "pd": 0x66, "ss": 0xF3, "sd": 0xF2}

# Stands in for "this operand is the original memory operand".
MEMORY = object()

MOVAPS = b"\x0f\x28"
BLENDVPS = b"\x0f\x38\x14"
BLENDVPD = b"\x0f\x38\x15"


def lower_blendv(vex, tail, mnemonic, scratch):
	"""vblendvps/vblendvpd: SSE takes the mask in an implicit %xmm0.

	Four registers are named -- mask, src2, src1, dst -- and only three fit,
	so the mask has to be moved into %xmm0 and whatever %xmm0 held has to
	survive. Where the destination IS %xmm0 its old value is dead, but it
	still cannot hold the mask and the result at once, so the blend runs in
	the scratch. See project.md Finding 9 for how the naive ordering
	destroys the mask and then the result.
	"""
	if (vex["L"]):
		return None			# 256-bit needs the Y representation
	modrm = tail[1]
	if ((modrm >> 6) & 3) != 3:
		return None			# memory src2; not handled here
	is4 = tail[2] if len(tail) > 2 else None
	if is4 is None:
		return None
	destination = (vex["R"] << 3) | ((modrm >> 3) & 7)
	source2 = (vex["B"] << 3) | (modrm & 7)
	source1 = vex["vvvv"]
	mask = (is4 >> 4) & 0xF
	opcode = BLENDVPS if mnemonic == "vblendvps" else BLENDVPD

	body = bytearray()
	if mask == 0:
		# Cheapest shape: the mask is already where SSE wants it.
		if destination != source1:
			body += encode_rr(None, MOVAPS, destination, source1)
		body += encode_rr(0x66, opcode, destination, source2)
		return bytes(body)

	if scratch is None:
		return None
	if scratch in (destination, source1, source2, mask, 0):
		return None

	if destination == 0:
		# %xmm0 is written by the instruction, so its incoming value is
		# dead -- but it cannot be the blend's destination while it holds
		# the mask, so the blend runs in the scratch and moves back.
		body += encode_rr(None, MOVAPS, scratch, source1)
		body += encode_rr(None, MOVAPS, 0, mask)
		body += encode_rr(0x66, opcode, scratch, source2)
		body += encode_rr(None, MOVAPS, 0, scratch)
		return bytes(body)

	# %xmm0 holds something live. Save it, then rename any operand that
	# referred to it, because the mask is about to overwrite it.
	body += encode_rr(None, MOVAPS, scratch, 0)
	body += encode_rr(None, MOVAPS, 0, mask)
	if source1 == 0:
		source1 = scratch
	if source2 == 0:
		source2 = scratch
	if destination != source1:
		body += encode_rr(None, MOVAPS, destination, source1)
	body += encode_rr(0x66, opcode, destination, source2)
	body += encode_rr(None, MOVAPS, 0, scratch)
	return bytes(body)


def encode_mem(prefix, opcode, reg, vex, tail, address, encoding, at):
	"""An SSE instruction reusing the original instruction's memory operand.

	The modrm reg field is rewritten, because the destination of the piece
	being emitted is rarely the destination the original named. Everything
	from modrm onward -- sib, displacement -- is carried across unchanged
	except for a RIP displacement, which is measured from the end of the
	instruction and so has to be recomputed where the instruction now ends.
	"""
	out = bytearray()
	if prefix is not None:
		out.append(prefix)
	rex = 0x40 | ((reg >> 3) << 2) | (vex["X"] << 1) | vex["B"]
	if rex != 0x40:
		out.append(rex)
	out += opcode
	out.append((tail[1] & 0xC7) | ((reg & 7) << 3))
	out += tail[2:]
	if rip_relative(tail) and len(tail) > 6:
		# The repair below rewrites the LAST four bytes as the
		# displacement, which is only the displacement when nothing
		# follows it. Nothing reaches here with an immediate today --
		# no FMA has one -- and a silent corruption is the wrong thing
		# to leave waiting for the first caller that does. Finding 303.
		return None
	if rip_relative(tail):
		old = struct.unpack_from("<i", out, len(out) - 4)[0]
		target = address + len(encoding) + old
		displacement = target - (at + len(out))
		if not -(1 << 31) <= displacement < (1 << 31):
			return None
		out[len(out) - 4:] = struct.pack("<i", displacement)
	return bytes(out)


# The orderings this emits a SPAN sequence for: plain packed multiply-add,
# no negation and no lane alternation. 139 of the 205 declined 256-bit FMA
# sites are these. `maddsub`/`msubadd` are deliberately excluded and are
# not an oversight -- Finding 4 measured that lowering them with a plain
# multiply-add sequence is a CORRECTNESS bug rather than a precision one,
# because they alternate add and subtract across the lanes, and
# `test/fmaddsub_test.c` exists to demonstrate exactly that. Finding 300.
# **Which operation each form applies to the product**, and the ones a
# span can emit. `madd` and `msub` differ only in an opcode byte;
# `maddsub` is SSE3's `addsubps`, which subtracts on the even lanes and
# adds on the odd ones -- exactly VFMADDSUB, as `lower.py` records
# having confirmed by running it rather than by reading the manual.
#
# `nmadd` is absent because `D = addend - product` cannot accumulate in
# the helper: the product has to exist before the addend is read, so the
# upper half wants two registers where these want one. `msubadd` is
# absent for a reason that is not register pressure -- there is no
# subadd instruction, and negating the addend to reuse `addsubps` is
# WRONG, because the negation is a sign-bit flip and a NaN has a sign
# bit. `lower.py` blends two results instead, which needs a constant.
# Both are recorded rather than forgotten. Findings 4 and 302.
FMA_SPAN_OPS = {"madd": b"\x0f\x58", "msub": b"\x0f\x5c",
                "maddsub": b"\x0f\xd0", "msubadd": None}

# **`msubadd` computes both results and blends**, which is `lower.py`'s
# construction and not a choice. There is no subadd instruction, and the
# obvious move -- negate the addend and reuse `addsubps`, since IEEE 754
# makes `a - b` and `a + (-b)` the same operation -- is WRONG: the
# negation is a sign-bit flip across the register, a NaN has a sign bit,
# and x86 preserves it. `lower.py` measured 291 vectors disagreeing in a
# special-value sweep, every one a NaN, with the addend coming out
# `ffc00000` where the hardware gives `7fc00000`.
#
# Doing the add and the subtract the hardware does makes NaN propagation
# match by construction, and it needs no sign-mask constant -- so the
# rewriter needs no read-only pool for this rule. It costs a second
# scratch, which `TWO_HELPERS` already allocates for `lanereg3`.
#
# `blendps $0xa` takes lanes 1 and 3 from the source: odd lanes from the
# subtract, even from the add, which is VFMSUBADD. Finding 304.
BLEND_OPCODE = {"ps": b"\x0f\x3a\x0c", "pd": b"\x0f\x3a\x0d"}
BLEND_ODD = {"ps": 0x0A, "pd": 0x02}

# The FMA forms a span emits with ONE helper. `msubadd` is not among
# them: its blend needs both results live at once, so it wants the two
# that `TWO_HELPERS` allocates for its shape anyway. Finding 304.
FMA_ONE_HELPER = frozenset(f for f in
                           (f"vf{op}{order}{width}"
                            for op in ("madd", "msub", "maddsub")
                            for order in ("132", "213", "231")
                            for width in ("ps", "pd")))
FMA_SPAN_FORMS = frozenset(f"vf{negated}{operation}{order}{width}"
                           for negated, operation in (("", "madd"),
                                                      ("", "msub"),
                                                      ("", "maddsub"),
                                                      ("", "msubadd"),
                                                      ("n", "madd"))
                           for order in ("132", "213", "231")
                           for width in ("ps", "pd"))

# The two shapes a span can emit one for: the second source in memory,
# and all three operands in registers. They differ only in where the
# multiplicand comes from -- an address either way, since the register
# form's sources are slots. Finding 301.
FMA_SPAN_SHAPES = frozenset(("lanemem", "lanereg3"))


def fma_mem_piece(vex, tail, prefix, opcode, reg, delta, address, encoding,
                  at):
	"""`opcode <the original memory operand, plus delta>,%xmm<reg>`.

	`encode_mem` already reuses the operand bytes and repairs a RIP
	displacement for the move into the stub; the only thing it does not do
	is step the operand along by `delta`, which is what reaches the upper
	half of a 256-bit memory source.

	The two operand kinds take that step differently, which is
	`narrow_piece`'s distinction and not a new one: an ordinary
	displacement is adjusted in the bytes before encoding, while a RIP one
	is measured from the end of the instruction and so is adjusted after,
	on the displacement `encode_mem` has already corrected. Adding `delta`
	to a corrected displacement is right because both are measured to the
	same point. Finding 300.
	"""
	if rip_relative(tail):
		out = encode_mem(prefix, opcode, reg, vex, tail, address, encoding,
		                 at)
		if out is None:
			return None
		old = struct.unpack_from("<i", out, len(out) - 4)[0]
		if not -(1 << 31) <= old + delta < (1 << 31):
			return None
		return out[:-4] + struct.pack("<i", old + delta)
	moved = tail if delta == 0 else inplace.offset_operand(tail, delta)
	if moved is None:
		return None
	return encode_mem(prefix, opcode, reg, vex, moved, address, encoding, at)


def lower_fma(vex, tail, mnemonic, scratch, address=0, encoding=b"", at=0):
	"""The fused multiply-adds. NOT bit-exact: two roundings replace one.

	The 132/213/231 suffix says which operand is the addend, taken from the
	SDM rather than from intuition. In AT&T order the operands print as
	src2, src1, dst:

	    132   dst = dst  * src2 + src1
	    213   dst = src1 * dst  + src2
	    231   dst = src1 * src2 + dst

	The scalar forms carry a trap. VFMADD213SS leaves DEST[127:32]
	**unchanged**, so the result cannot be moved back with a movaps -- that
	would overwrite the upper lanes with whatever the scratch held. movss
	and movsd write only their own width and leave the rest alone, which is
	exactly what is wanted.
	"""
	match = FMA_PATTERN.match(mnemonic)
	if match is None or vex["L"] or scratch is None:
		return None
	negated, operation, order, kind = match.groups()
	modrm = tail[1]
	memory = ((modrm >> 6) & 3) != 3
	destination = (vex["R"] << 3) | ((modrm >> 3) & 7)
	# With a memory operand there is no src2 register; MEMORY stands in for
	# it below and is emitted by reusing the original operand bytes.
	source2 = MEMORY if memory else (vex["B"] << 3) | (modrm & 7)
	source1 = vex["vvvv"]
	if scratch in (destination, source1, source2):
		return None

	if order == "132":
		factors, addend = (destination, source2), source1
	elif order == "213":
		factors, addend = (source1, destination), source2
	else:
		factors, addend = (source1, source2), destination

	prefix = FMA_PREFIX[kind]
	scalar = kind[0] == "s"
	multiply, add, subtract = b"\x0f\x59", b"\x0f\x58", b"\x0f\x5c"

	def move_result(source, target):
		"""Into the destination, without disturbing what has to stay put."""
		if scalar:
			return encode_rr(prefix, b"\x0f\x10", target, source)
		return encode_rr(None, MOVAPS, target, source)

	def operate(opcode, target, operand):
		"""One piece, whether its source is a register or the memory one."""
		if operand is MEMORY:
			return encode_mem(prefix, opcode, target, vex, tail, address,
			                  encoding, at + len(body))
		return encode_rr(prefix, opcode, target, operand)

	body = bytearray()
	if factors[0] is MEMORY:
		# The memory operand can only be read, never be the copy's source.
		return None
	body += encode_rr(None, MOVAPS, scratch, factors[0])
	piece = operate(multiply, scratch, factors[1])
	if piece is None:
		return None
	body += piece

	if operation == "maddsub" and not negated:
		# Even lanes subtract and odd lanes add, which is what addsubps
		# already does -- confirmed on the host, project.md Finding 4.
		if scalar:
			return None
		piece = operate(b"\x0f\xd0", scratch, addend) if addend is MEMORY \
			else encode_rr(0xF2 if kind == "ps" else 0x66, b"\x0f\xd0",
			               scratch, addend)
		if piece is None or addend is MEMORY:
			return None		# addsub needs its own prefix; not worth the case
		body += piece
		body += move_result(scratch, destination)
		return bytes(body)
	if operation == "msubadd":
		# The opposite lane pattern needs both results and a blend, and so
		# a second scratch. Refused rather than approximated.
		return None

	if negated:
		# dst = addend - product.
		if addend is MEMORY:
			return None		# the addend would have to be loaded first
		if addend != destination:
			body += move_result(addend, destination)
		body += encode_rr(prefix, subtract, destination, scratch)
		return bytes(body)

	if operation == "msub":
		# dst = product - addend. Subtraction does not commute, so this
		# cannot be accumulated into the destination.
		piece = operate(subtract, scratch, addend)
		if piece is None:
			return None
		body += piece
		body += move_result(scratch, destination)
		return bytes(body)

	# madd: dst = product + addend.
	if addend == destination:
		body += encode_rr(prefix, add, destination, scratch)
		return bytes(body)
	piece = operate(add, scratch, addend)
	if piece is None:
		return None
	body += piece
	body += move_result(scratch, destination)
	return bytes(body)

# Load one element, then spread it. The load width is the whole point: a
# single pshufd would do the job in one instruction and would read 128 bits
# where vbroadcastss reads 32, so a source four bytes from the end of a
# mapped page would fault where the original did not. The narrow load stays
# narrow and the spread is a separate register-to-register instruction.
#
# vbroadcastsd is the exception, and not by cheating: movddup is SSE3, reads
# exactly 64 bits, and duplicates them -- the whole instruction in one.
BROADCASTS = {
	# mnemonic: (load prefix, load opcode, spread prefix, spread opcode)
	"vbroadcastss": (0xF3, b"\x0f\x10", None, b"\x0f\xc6"),
	"vbroadcastsd": (0xF2, b"\x0f\x12", None, None),
	"vpbroadcastd": (0x66, b"\x0f\x6e", 0x66, b"\x0f\x70"),
}


# The three constants the variable-control permute needs, laid out once at
# the start of the stub section. They must be 16-byte aligned: a non-VEX SSE
# instruction with a memory operand faults on an unaligned address, and the
# section begins on a page boundary so offset zero is aligned by
# construction.
PERMIL_POOL = (
	bytes([3, 0, 0, 0] * 4)					# bits 1:0 of each control element
	+ bytes([0, 0, 0, 0, 4, 4, 4, 4, 8, 8, 8, 8, 12, 12, 12, 12])
	+ bytes([0, 1, 2, 3] * 4)				# step through an element's bytes
)
POOL_MASK3, POOL_BCAST, POOL_STEP = 0, 16, 32


# How a stub gets a scratch register when the liveness scan finds none dead.
# **The default is `home`**, set by the copyright holder after Findings 70 to
# 72. The other three are kept because the measurements they carry are what a
# future reader will want: `stack` cannot be described to an unwinder
# (Finding 68), `pool` cannot be made thread-safe (Finding 46), and `none`
# refuses 1,022 sites the home space can take.
SPILL_NONE, SPILL_STACK, SPILL_POOL = "none", "stack", "pool"
# **The callee home space.** Win64 makes a caller reserve 32 bytes at the
# bottom of its frame for its callees to spill their register arguments into,
# and between calls nobody owns it: the caller does not write it -- the fifth
# argument onward goes at [rsp+32] and up -- and no callee exists yet.
#
# It walks through all three objections at once. Nothing moves `rsp`, so
# there is nothing to describe to an unwinder and Finding 68 does not apply.
# It is the thread's own stack, so Finding 46's race does not apply. And
# `(%rsp)` needs no register to address, so Finding 69 does not apply.
SPILL_HOME = "home"
# **Static TLS**, which is the home space's fallback rather than its rival:
# `--spill=tls` takes the home space wherever it is lendable and reaches for
# a per-thread slot only where it is not. The bytes belong to the rewriter,
# so this is the one backing store here whose failure mode is not silent
# corruption of somebody else's local -- a slot used wrongly loses the
# rewriter's own value. It costs TWO general-purpose registers to address
# (Finding 139) and is worth 753 sites by the liveness Finding 141 measured.
SPILL_TLS = "tls"
# **Every mode that lends the callee home space**, named once because it is
# tested in four places and a mode missing from one of them is invisible.
# `--spill=tls` is home FIRST and a per-thread slot only where the home
# space said no, so everything the home space offers it offers too. Getting
# this wrong cost 351 sites in the first build: `ymm_run`'s borrow and
# `swallowed_borrow` both asked `SPILL == SPILL_HOME` exactly, so turning
# TLS on took the home space away from a run and gave it back to nobody --
# the mode gained its 753 and lost 287 net, which is how it was found.
HOME_SPILLS = (SPILL_HOME, SPILL_TLS)
# **Where the region sits among the 256-bit strategies**, as one of three
# positions that all exist in `collect`: `first` ahead of the pair and the
# run, `middle` after the pair, the run and the span, and `last` after the
# zero store, the zero run, the long halves and the constants too -- with
# nothing below it but the refusal.
#
# It is three places and not a boolean for the reason Finding 166 cost 100
# sites: the first version of this switch deleted one call site and made
# the other conditional, so turning it off disabled the region rather than
# moving it. Every position is a call that is present whichever value is
# set, and `--region-place=` selects between them without editing this
# file -- `--region=` was already taken by `REGION_RULE`, which decides
# what a region may contain rather than where it is offered.
#
# Measured first against middle (Finding 161). First, it takes 865 more
# windows and
# the pair loses 909 and the run 236 -- 1,145 windows changing hands to
# gain SEVEN sites, at 22 KB more stub. A pair lowers a 256-bit copy
# through a register helper and the region routes the same value through
# a memory slot, so those 1,145 copies got slower in order to lower seven
# more sites. Finding 123's rule, met from the winning side: a strategy
# that SUCCEEDS can still take work a better one was doing.
#
# Kept switchable rather than deleted, for the reason `--spill=home` is
# kept beside `--spill=tls`: the two answers are a site count against a
# cost, and the day the region lowers a copy as cheaply as the pair does,
# the switch is already there to re-take the measurement.
#
# Middle against last is Finding 170, and its reason is Finding 169's
# measurement rather than a guess: a region routes a copy through a memory
# slot at 4.27 cycles where a pair does it in registers at 2.20, and the
# zero store -- which sits directly below the region today -- is the
# cheapest thing here at 1.91. A region that wins a site one of those
# would have taken has made the binary slower to lower one more.
REGION_EARLY = "first"
REGION_MID = "middle"
REGION_LATE = "last"
REGION_PLACE = REGION_MID
# **`tls` is the default**, and what it changes from `home` is one thing: a
# site whose function will lend no home space gets sixteen bytes of its own
# thread instead of keeping its VEX. Worth 671 sites in the binary (Finding
# 142), and safe to make the default for a reason none of the other stores
# can give -- the bytes belong to the rewriter, so a slot addressed wrongly
# loses the rewriter's own saved register rather than a local of the
# program's. Every other backing store here fails by corrupting somebody
# else's value in silence.
#
# `--spill=home` stays reachable and is the A/B: `check-spill` runs
# `tlsspill` both ways and requires 29 from one and 121 from the other.
SPILL = SPILL_TLS
HOME_SPACE = 32
# `--rsp=` decides what a copy of `rsp` costs. `blanket` refuses any function
# that makes one, which is what Findings 72 and 73 shipped; `followed` works
# out where the copy points and refuses only what it cannot vouch for. See
# Finding 96 for why the blanket rule was measured to protect no function at
# all, and keep `blanket` reachable: a borrow that corrupts a live local does
# not fault, so comparing two binaries is the only way to test for it.
RSP_BLANKET, RSP_FOLLOWED = "blanket", "followed"
RSP_RULE = RSP_FOLLOWED
# `--escape=` decides what a copy of `rsp` STORED TO MEMORY costs. `allow`
# is Finding 127's rule; `refuse` is what preceded it and what Finding 132
# measures the price of. See `copy_reaches_home`.
ESCAPE_REFUSE, ESCAPE_ALLOW = "refuse", "allow"
ESCAPE_RULE = ESCAPE_ALLOW
# `--shadow=off` takes the caller's shadow away and leaves only the callee
# home space, which is every borrow this tool wrote before Finding 130. It is
# kept reachable for the same reason `--rsp=blanket` is: a borrow at the
# wrong displacement corrupts a live local rather than faulting, so comparing
# two binaries is the only way to test for it -- and `check-pe` does exactly
# that with `shadowspill`, whose site is refused outright when this is off.
SHADOW_OFF, SHADOW_ON = "off", "on"
SHADOW_RULE = SHADOW_ON
# `--fallback=off` takes the per-site stack borrow away, leaving `--spill=tls`
# to decline a site where the home space cannot lend and fewer than two GPRs
# are free -- which is what it did before Finding 204.
#
# **It exists because the fallback broke a control, not for symmetry.**
# `check-spill` proves the caller's shadow is load-bearing by turning it off
# and requiring the site to FAIL; with a stack fallback available the site
# succeeds anyway, so `--shadow=off` stopped isolating the shadow and the
# gate said so. A new mechanism that can rescue a site needs its own switch,
# or every control that isolates a rescue below it quietly stops
# discriminating. Finding 204.
FALLBACK_OFF, FALLBACK_ON = "off", "on"
FALLBACK_RULE = FALLBACK_ON


def encode_rip(prefix, opcode, reg, target, at):
	"""An SSE instruction whose memory operand is RIP-relative."""
	out = bytearray()
	if prefix is not None:
		out.append(prefix)
	rex = 0x40 | ((reg >> 3) << 2)
	if rex != 0x40:
		out.append(rex)
	out += opcode
	out.append(((reg & 7) << 3) | 5)		# mod 00, rm 101 -- RIP + disp32
	displacement = target - (at + len(out) + 4)
	if not -(1 << 31) <= displacement < (1 << 31):
		return None
	out += struct.pack("<i", displacement)
	return bytes(out)


def spill_candidates(registers):
	"""Every register the site does not name, lowest first.

	**One candidate is not enough, and the failure is silent.** SSE
	`blendvps` takes its mask in an implicit `%xmm0`, so `lower_blendv`
	refuses a scratch of 0 -- and 0 is exactly what the first-free rule
	returns whenever the site does not name it, which is 600 of this
	binary's 3,572 `vblendv` instructions. Offering that one register and
	giving up handed those the only register the lowering cannot accept,
	while 2,196 of the 2,210 that need a scratch have one that works.

	So the caller tries them in turn and lets the lowering decide. Nothing
	here claims a register is dead -- that is `find_scratch` -- which is why
	whichever is taken has to be saved first. See Finding 100.
	"""
	used = set()
	for operand in registers:
		used.update(scratch_finder.xmm_numbers(operand))
	return [number for number in VOLATILE_XMM if number not in used]


def borrow_that_lowers(address, encoding, operands, mnemonic, at, pool=0):
	"""The first borrowable register this lowering will actually accept.

	Both borrow paths ask through here rather than each trying a register of
	its own: the site's, and `swallowed_borrow` for a neighbour. One code
	path deciding is the same rule that keeps the collector and the encoder
	agreeing about what can be encoded.
	"""
	registers = [o for o in inplace.split_operands(operands)
	             if not o.startswith("$")]
	for borrowed in spill_candidates(registers):
		if lower_vex(address, encoding, operands, mnemonic, at, borrowed,
		             pool) is not None:
			return borrowed
	return None


def spill_register(registers):
	"""The first register the site does not name, or None.

	Always available: a site has at most four operands and there are sixteen
	registers. Prefer `spill_candidates` where a lowering may refuse one.
	"""
	candidates = spill_candidates(registers)
	return candidates[0] if candidates else None


# **The thread's own TLS array, at `gs:[0x58]`.** The TEB holds
# ThreadLocalStoragePointer there, and the loader gives every module with a
# TLS directory an index into it. Reaching this module's block is therefore
# two dereferences and needs TWO registers: hold the array pointer and the
# index has nowhere to go, hold the index and the array pointer has nowhere
# to go. A segment-prefixed `%gs:0x58(,%r,8)` does not help, because 0x58
# holds a pointer that must be FOLLOWED before it is indexed. Finding 139.
TEB_TLS_POINTER = 0x58

# **A segment-prefixed absolute address needs no register at all**, which
# is the third register-free location Finding 270 said did not exist. It
# said a slot needs the block pointer and `(%rsp)` cannot be described in a
# chained fragment, and that those were the only two. `%gs:disp32` is a
# complete effective address -- no base, no index -- it is per-thread by
# construction, it does not move `rsp`, and there is nothing in it for an
# unwinder to describe. Measured under wine: a write and a read back at
# both 0x28 and 0x7c8 return 77 on every run.
#
# Sixteen bytes of it replace what the callee home space was doing, which
# takes the block's two borrows off the caller entirely.
#
# **What it does NOT settle is whose bytes those are**, and that is why
# there is no default. Every offset in the TEB belongs to somebody:
# `TlsSlots` is `TlsAlloc`'s to hand out, `ArbitraryUserPointer` is read by
# some `NtCreateFile` paths, and the OpenGL reserved block is free only in
# a process that never loads legacy GL. A stub cannot preserve what it
# borrows here -- preserving it means reading it first, into the register
# it has not got -- so the bytes have to be genuinely unowned rather than
# merely quiet. Until that is settled for a real process this carries a
# measurement and nothing else, exactly as `--spill=stack` does for the
# stack borrow it is not allowed to take. Finding 280.
# **`auto` is the default from 2026-09-29, on the copyright holder's
# instruction.** Worth 688 sites: 2,337 without it against 1,649 with,
# both re-measured on the same tool the day it was taken. The gap had
# been widening -- 341 when Finding 297 raised it -- because every item
# since depends on the slot machinery the TEB route feeds. `--teb-
# scratch=off` is the A/B. Finding 309.
TEB_SCRATCH = "auto"
TEB_SCRATCH_BYTES = 16

# **`auto` asks the process for the bytes instead of naming them.** The
# paragraph above is the whole difficulty with a fixed offset: nothing
# establishes that sixteen bytes of somebody else's TEB are free, and a
# stub cannot preserve what it cannot read. `TlsAlloc` removes the
# question by handing out bytes that ARE ours -- slot k lives at
# `%gs:0x1480+8k`, which is still a complete effective address needing no
# base and no index, so the property that made mode "teb" worth having
# survives. Measured on this image: the first call returns 5 and the
# register-free range holds 64. Findings 296 and 297.
#
# The slot numbers come from the loader, so the displacement is written
# as a placeholder and filled in by the same TLS callback that fills the
# index. Two slots, and the low byte is zero so that the second is
# literally `TEB_PLACEHOLDER + 8` -- the emitter already computes
# `offset` and `offset + 8`, and this keeps that arithmetic honest
# instead of special-casing it.
TEB_PLACEHOLDER = 0x5B5B5B00


def teb_scratch_offset():
	"""The disp32 a TEB save should carry, placeholder or literal."""
	return TEB_PLACEHOLDER if TEB_SCRATCH == "auto" else TEB_SCRATCH

# **The TLS index as a constant, written in at load time.** The block
# pointer needs two registers only because the index lives in memory, and
# mode True exists solely to park that second register in an xmm. With the
# index folded into a displacement the chain is one register and two
# instructions:
#
#     movq %gs:0x58,%block
#     movq <index * 8>(%block),%block
#
# The loader assigns the index, so the displacement cannot be known when
# the image is written. It is emitted as `INDEX_PLACEHOLDER` and a TLS
# callback fills it in at DLL_PROCESS_ATTACH, which is sound because the
# loader writes `*AddressOfIndex` before calling one -- measured, Finding
# 291, with a sentinel that would have shown the opposite.
#
# **The placeholder is found by scanning the finished blob**, rather than
# by threading an offset up through every caller of `encode_tls_base`. That
# is only safe with a count to check it against: `INDEX_CONST_SITES` is
# incremented per emission and the scan must find exactly that many, or the
# build refuses. A marker search with no denominator is how a patch table
# ends up short. Finding 293.
# **The default since 2026-09-20**, on the copyright holder's instruction:
# 2,889 VEX left becomes 2,687, and 24,551 stubs lose an instruction and a
# dependent load from their prologue. `--index-const=off` stays reachable
# as the A/B, the way `--shadow-regs=off` does. Finding 295.
INDEX_CONST = True
def run_configuration():
	"""The flags a roll file's header must carry beside the image.

	**Naming the image is not enough and Finding 240's rule said it was.**
	The same binary measured with and without `--teb-scratch=auto`
	produces frontiers of 2,337 and 1,649, and both files opened
	`# Starfield-unpacked.exe`. A `frontier` run on the default silently
	replaced the auto build's rows, and the two were then joined against
	each other: 244 readers were reported in a class the auto build has
	72 of. Nothing in either header could have said so -- only the count
	gave it away, and only because the two happen to differ by enough to
	notice. Finding 308.

	**Naming the flags is not enough either, and this is the harder case.**
	Two rolls were produced from the same image, the same flags and the
	same total of 996 surviving sites, with 31 and 57 sites in one bucket.
	Their headers were BYTE-IDENTICAL, because what differed was the tool:
	one was written before an experiment was reverted and one after. Every
	guard that exists passed, and the join built on them put 26 sites in a
	class their own run does not have.

	So the header carries a fingerprint of the tool's own sources. It
	changes whenever any of them changes, which is the point -- a snapshot
	taken across an edit is meant to stop comparing equal. Hashing the
	files rather than asking git is deliberate: these trees are edited for
	hours between commits, so `HEAD` is the same for every roll in a
	session and a dirty flag only says that something changed, not what.
	Finding 316.
	"""
	return (f"shadow-regs={SHADOW_REGS_RULE}"
	        f" teb-scratch={TEB_SCRATCH}"
	        f" index-const={'on' if INDEX_CONST else 'off'}"
	        f" spill={SPILL}"
	        f" tool={tool_fingerprint()}")


_FINGERPRINT = None


def tool_fingerprint():
	"""Twelve hex digits over the sources this run is made of.

	Computed once. Every `.py` beside this file is read in sorted order, so
	the digest covers the collector, the patcher, the lowering tables and
	the scratch finder alike -- a change in any of them can move a bucket.
	An unreadable file is folded in by name rather than skipped, because a
	fingerprint that quietly ignores what it cannot read is one that agrees
	across the change it was written to catch.
	"""
	global _FINGERPRINT
	if _FINGERPRINT is None:
		import hashlib
		from pathlib import Path
		digest = hashlib.sha256()
		for source in sorted(Path(__file__).parent.glob("*.py")):
			digest.update(source.name.encode())
			try:
				digest.update(source.read_bytes())
			except OSError:
				digest.update(b"<unreadable>")
		_FINGERPRINT = digest.hexdigest()[:12]
	return _FINGERPRINT


INDEX_PLACEHOLDER = 0x5A5A5A5A
INDEX_CONST_SITES = 0
INDEX_CONST_CALLBACK = False

# rax, rcx, rdx and r8-r11 by number, which is what an encoding wants.
GPR_NUMBERS = {"rax": 0, "rcx": 1, "rdx": 2,
               "r8": 8, "r9": 9, "r10": 10, "r11": 11}


def encode_tls_base(block, index, index_va, at, stash=None):
	"""Put this module's TLS block in `block`, using `index` as scratch.

	    movq %gs:0x58,%block
	    mov  tls_index(%rip),%indexd
	    movq (%block,%index,8),%block

	`at` is where the sequence starts, because the middle instruction is
	rip-relative and a displacement is measured from the END of it.

	Both registers are clobbered and neither is put back. That is the whole
	reason this needs `gpr_live_out` rather than a save: Finding 69 met a
	circularity in which saving a general-purpose register needed a
	register to address the place it went, and Finding 141 broke it by
	finding registers that were already dead.

	**The circularity was never complete, and this comment used to say it
	was.** `(%rsp)` needs no register (Finding 249, the callee home space)
	and neither does `%gs:disp32`, which is a whole effective address with
	no base and no index (Finding 280, mode "teb"). What is scarce is
	eight bytes that are OURS to write, not a register to address them
	with -- three different answers to that, and the register was never
	the question.

	**`stash` breaks the circularity for the second register**, and it is an
	xmm rather than memory precisely because memory is what needed a
	register in the first place:

	    movq %index,%stash
	    ... the three above ...
	    movq %stash,%index

	`movq` between a GPR and an xmm touches no memory and **sets no flags**,
	which is the property that matters here: the instructions this replaces
	are SSE ones that write no flags either, so a stub may not either --
	something may have compared above the site and be about to branch below
	it. That is why the sequence above is all `mov` and why an `add` or a
	`shl` cannot be used to fold the index in.

	Only `block` need then be dead, halving what a site must supply. And the
	stash costs no register of its own: it is released three instructions
	later, before the body begins, so the caller passes a helper it is about
	to use anyway. Finding 247.
	"""
	if INDEX_CONST and stash is None:
		# **Two instructions and one register.** `mov disp32(%block),%block`
		# is REX.W with mod 10, and no block register can be `rsp` or
		# `r12` -- the two that would need a SIB byte -- because they are
		# drawn from VOLATILE_GPRS. Finding 293.
		global INDEX_CONST_SITES
		INDEX_CONST_SITES += 1
		out = bytearray()
		out.append(0x65)					# %gs
		out.append(0x48 | (0x04 if block >= 8 else 0))
		out += b"\x8b"
		out.append(((block & 7) << 3) | 4)			# mod 00, rm 100
		out.append(0x25)					# no base/index
		out += struct.pack("<I", TEB_TLS_POINTER)
		out.append(0x48 | (0x04 if block >= 8 else 0)
		           | (0x01 if block >= 8 else 0))	# REX.W, R, B
		out += b"\x8b"
		out.append(0x80 | ((block & 7) << 3) | (block & 7))	# mod 10
		out += struct.pack("<I", INDEX_PLACEHOLDER)
		return bytes(out)
	out = bytearray()
	if stash is not None:
		# movq %index,%stash -- 66 REX.W 0F 6E /r, reg is the xmm.
		out += b"\x66"
		out.append(0x48 | (0x04 if stash >= 8 else 0)
		           | (0x01 if index >= 8 else 0))
		out += b"\x0f\x6e"
		out.append(0xC0 | ((stash & 7) << 3) | (index & 7))
	out.append(0x65)						# %gs
	out.append(0x48 | (0x04 if block >= 8 else 0))		# REX.W, REX.R
	out += b"\x8b"
	out.append(((block & 7) << 3) | 4)			# mod 00, rm 100 SIB
	out.append(0x25)					# no base, no index
	out += struct.pack("<I", TEB_TLS_POINTER)

	middle = bytearray()
	if index >= 8:
		middle.append(0x44)					# REX.R
	middle += b"\x8b"
	middle.append(((index & 7) << 3) | 5)			# mod 00, rm 101 rip
	# A 32-bit load zero-extends, so the index arrives in all 64 bits and
	# the scale-8 index below is a whole register. `movl` is a byte shorter
	# than `movq` and this sequence is emitted at every site that uses it.
	following = at + len(out) + len(middle) + 4
	middle += struct.pack("<i", index_va - following)
	out += middle

	out.append(0x48 | (0x04 if block >= 8 else 0)
	           | (0x02 if index >= 8 else 0)
	           | (0x01 if block >= 8 else 0))		# REX.W R X B
	out += b"\x8b"
	out.append(((block & 7) << 3) | 4)			# mod 00, rm 100 SIB
	out.append(0xC0 | ((index & 7) << 3) | (block & 7))	# scale 8
	if stash is not None:
		# movq %stash,%index -- 66 REX.W 0F 7E /r, reg is the xmm.
		out += b"\x66"
		out.append(0x48 | (0x04 if stash >= 8 else 0)
		           | (0x01 if index >= 8 else 0))
		out += b"\x0f\x7e"
		out.append(0xC0 | ((stash & 7) << 3) | (index & 7))
	return bytes(out)


def encode_gpr_teb(register, save, offset):
	"""Save or restore a general-purpose register at `%gs:offset`.

	    65 48 89 04 25 <disp32>    movq %reg,%gs:offset
	    65 48 8b 04 25 <disp32>    movq %gs:offset,%reg

	Mod 00 with rm 100 selects a SIB byte, and a SIB of 0x25 is base 101
	index 100 -- no base, no index, disp32. That is what makes the address
	need no register, and the disp32 is not optional: there is no shorter
	form of an absolute address, so a near offset costs the same nine bytes
	as a far one.

	`movq` and not `movl`, because a block pointer is 64 bits and the
	register being borrowed may hold anything. It sets no flags, which is
	the same requirement `encode_tls_base` is written to. Finding 280.
	"""
	out = bytearray()
	out.append(0x65)					# %gs
	out.append(0x48 | (0x04 if register >= 8 else 0))	# REX.W, REX.R
	out.append(0x8B if not save else 0x89)
	out.append(((register & 7) << 3) | 4)			# mod 00, rm 100 SIB
	out.append(0x25)					# no base, no index
	out += struct.pack("<I", offset)
	return bytes(out)


def encode_gpr_home(register, save, offset):
	"""Save or restore a general-purpose register at `offset(%rsp)`.

	**The circularity Finding 69 named was never quite the whole truth.**
	It says there is nowhere to save a general-purpose register that does
	not need a register to address it -- and `(%rsp)` needs none. What is
	actually scarce is not an addressing register but eight bytes of stack
	that are ours to write: below `rsp` is nothing (Win64 has no red zone)
	and above it is the caller's business, so the only place is the callee
	home space the caller reserved, which `window_borrow` finds.

	Where the caller reserved none, `encode_gpr_teb` is the same argument
	in the TEB: also no register to address it, and also a question of
	whose bytes they are rather than how to reach them. Finding 280.

	Always a disp32. The home space sits at a frame's own displacement and
	a disp8 form would be right only in a fixture. Finding 249.
	"""
	return encode_gpr_at(register, save, None, offset)


def window_gpr_unnamed(home, start, window):
	"""Volatile GPRs no instruction in the window NAMES, as numbers.

	Weaker than `window_gpr_free` on purpose, and the difference is the
	whole of Finding 249. That one wants a register DEAD, because it
	clobbers one and never puts it back; a register that is saved and
	restored may be live, and all that matters is that nothing inside the
	window reads or writes it while the borrow stands.
	"""
	if home is None:
		return frozenset()
	_starts, _ranges, _usable, state = home
	plain = state["plain"]
	named = set()
	at = bisect.bisect_left(plain, (start,))
	while at < len(plain) and plain[at][0] < start + window:
		named |= gprs_named(plain[at][3] or "")
		at += 1
	return frozenset(GPR_NUMBERS[name]
	                 for name in frozenset(VOLATILE_GPRS) - named)


def encode_tls_spill(borrowed, save, block, offset):
	"""Save or restore a borrowed xmm in the TLS slot at `offset(%block)`.

	`movups` for `encode_spill`'s reason: nothing guarantees the block is
	16-byte aligned beyond what the directory's own alignment asks for, and
	an aligned move would fault on exactly the sites hardest to reproduce.

	Always a disp32. The block runs to twelve kilobytes here and the slot
	sits past the end of the module's own template, so a disp8 form would
	be wrong for every real offset and right only in a fixture.
	"""
	out = bytearray()
	rex = 0x40 | (0x04 if borrowed >= 8 else 0) | (0x01 if block >= 8 else 0)
	if rex != 0x40:
		out.append(rex)
	out += b"\x0f\x11" if save else b"\x0f\x10"
	out.append(0x80 | ((borrowed & 7) << 3) | (block & 7))	# mod 10, disp32
	out += struct.pack("<i", offset)
	return bytes(out)


def encode_spill(borrowed, save, at, spill_base, slot, base):
	"""Save or restore a borrowed register. `save` picks the direction.

	**`movups`, not `movaps`.** Win64 guarantees `rsp` is 16-byte aligned at
	a call boundary and says nothing about an arbitrary instruction in the
	middle of a function, so an aligned move here would fault on exactly the
	sites that are hardest to reproduce.

	**`slot` is which sixteen bytes, and it used to be nowhere.** Every save
	emitted `(%rsp)` -- no displacement, whatever the register -- and a run
	that borrows two helpers saves both to the same sixteen bytes and
	restores both from them, so the first register comes back holding the
	second's value. It assembles, it verifies, the census is clean, and the
	program computes with a register the caller owns. There are two slots
	because the home space is 32 bytes; `build_stub` refuses a third rather
	than reaching past what the ABI reserved. Finding 118.

	`base` is which home space. Zero is the one this function reserves for
	its own callees, at `(%rsp)`; anything else is the shadow its caller
	reserved for it, a whole frame higher. See `borrow_offset`.

	**Neither `slot` nor `base` has a default, and that is the whole point.**
	Both arrived as optional parameters and both were then missed at a call
	site -- `slot` in Finding 118, where two borrows shared sixteen bytes,
	and `base` at two of the three `emit_swallowed` calls, where a
	swallowed neighbour saved itself into a leaf's own frame while the site
	beside it used the shadow. Each was silent, each assembled, each
	verified, and each corrupted a local. A missing argument is a
	`TypeError` now.
	"""
	opcode = b"\x0f\x11" if save else b"\x0f\x10"
	if SPILL == SPILL_POOL:
		return encode_rip(None, opcode, borrowed, spill_base + slot * SLOT,
		                  at)
	if base < 0:
		return None
	# The home space and the stack spill address the same place -- `(%rsp)`
	# -- and differ only in whether `rsp` was moved to make room first. The
	# home space needs no room made.
	out = bytearray()
	if borrowed >= 8:
		out.append(0x44)			# REX.R
	out += opcode
	offset = base + slot * SLOT
	if not offset:
		out.append(((borrowed & 7) << 3) | 4)	# mod 00, rm 100 -- SIB
		out.append(0x24)
	elif -128 <= offset < 128:
		out.append(0x40 | ((borrowed & 7) << 3) | 4)	# mod 01, disp8
		out.append(0x24)			# base rsp, no index
		out.append(offset & 0xFF)
	else:
		# The caller's shadow sits a whole frame above `rsp`, and MSVC
		# frames run to thousands of bytes. 257 of the 417 sites the shadow
		# unblocks need this form; a disp8 would have wrapped them into
		# somebody else's locals without a word.
		out.append(0x80 | ((borrowed & 7) << 3) | 4)	# mod 10, disp32
		out.append(0x24)
		out += struct.pack("<i", offset)
	return bytes(out)


# One saved register, and how many of them the home space holds.
SLOT = 16

# **What the image says its TLS block is aligned to, which decides whether a
# slot may be an arithmetic OPERAND.** A legacy SSE packed operation faults on
# an unaligned m128, so `mulps <slot>,%xmm` is safe only where the block base
# and the slot offset are both multiples of `SLOT`. The offset is, by
# construction -- `tls_slot` rounds to the directory's alignment and slots are
# `SLOT` apart. The BASE is the loader's, and the only thing that binds it is
# the alignment the TLS directory declares.
#
# Starfield declares 16 (`Characteristics 0x00500000`), so its 400 slot-operand
# stubs are sound. The FIXTURES declared 1 and passed anyway, which is the part
# worth the global: they were relying on the allocator returning aligned memory,
# so the thing meant to prove the mechanism could not fail for the reason the
# mechanism can. They declare 16 now.
#
# Set by `tls_slot`, the one place that reads the field. It starts as None and
# the predicate refuses on None, so an emitter reached before any plan was made
# declines rather than emitting arithmetic against an alignment nobody measured
# -- the safe direction, and deliberate.
TLS_BLOCK_ALIGNMENT = None


def slot_arithmetic_safe():
	"""True if a slot may be the memory operand of a packed operation."""
	return TLS_BLOCK_ALIGNMENT is not None and TLS_BLOCK_ALIGNMENT >= SLOT

# **Only a volatile register may be borrowed, and this used to be luck.**
# Win64 makes xmm0-xmm5 volatile and xmm6-xmm15 the callee's to preserve. A
# borrow saves and restores, so within the stub either kind is fine -- and a
# borrow bracket cannot contain a call, because `ymm_run` breaks on every
# control transfer and `swallowed_borrow` brackets one instruction. The only
# way out of a live bracket is a FAULT, and there the unwinder restores
# xmm6-xmm15 from the primary's `UWOP_SAVE_XMM128` codes, which a primary
# that never used the register does not have. The caller's value is sitting
# in the home space at that moment and is lost.
#
# `spill_candidates` returned `range(16)`, lowest first, so it reached a
# nonvolatile register only when every volatile one was named -- and
# measured over the whole binary, that never happens: of 29,712 saves, xmm0
# takes 16,474, xmm1 10,611, xmm2 1,940, xmm3 640, xmm4 36, xmm5 11, and
# **xmm6 to xmm15 take none**. So the restriction costs nothing here and
# turns safe-by-accident into safe-by-construction. A binary that needs one
# gets a named refusal rather than a silent risk. Finding 124.
VOLATILE_XMM = tuple(range(6))

# sub $16,%rsp and add $16,%rsp, which the pool spill does not need.
def block_off_xmm(block, mover, home, instructions, index, address,
                  window, lent, home_used):
	"""Rebuild a mode True block as one needing no xmm, or None.

	Mode True stands the block pointer up by stashing a live index register
	in an xmm for three instructions. Where no xmm is going to be available
	-- or where one is, but only as a stash in a slot the pointer setup
	would destroy first -- the mode has to become one that wants none:
	"home", which borrows the callee home space. Where the caller lent
	none there is nowhere left: a stub cannot allocate its own, because a
	chained fragment's UWOP_ALLOC_SMALL is not applied and the handler
	gets an establisher frame sixteen bytes out. Findings 49, 67, 68 and
	270, and `unwindspill` measures it at 99 on every run.

	**One implementation, because there are two callers and Finding 261 is
	what two copies of a derivation cost.** The xmm borrow asks before
	choosing a stash, and the guard after it asks again for the sites the
	borrow left unserved.

	`mover` is excluded by name: it was chosen against the OLD block's two
	registers, so nothing else stops the rebuild handing the same one to
	the pointer -- the stub would save it, load the block over it, and
	restore rubbish. Findings 265, 268 and 269.
	"""
	unnamed = [n for n in sorted(window_gpr_unnamed(home, address, window),
	                             reverse=True) if n != mover]
	if len(unnamed) < 2:
		return None
	if lent is None or home_used + 2 * 8 > HOME_SPACE \
			or (TEB_SCRATCH is not None and CODE_SABOTAGE in FORCE_TEB):
		# **The TEB takes what the caller did not lend.** Mode "teb" is
		# mode "home" with a segment-prefixed absolute address instead of
		# `offset(%rsp)`, so it consumes no home space and the caller
		# need not have reserved any. Finding 280.
		if TEB_SCRATCH is None:
			return None
		return ((unnamed[0], unnamed[1], block[2], "teb",
		         teb_scratch_offset()), home_used)
	return ((unnamed[0], unnamed[1], block[2], "home", lent + home_used),
	        home_used + 2 * 8)


STACK_OPEN = bytes([0x48, 0x83, 0xEC, 0x10])
STACK_CLOSE = bytes([0x48, 0x83, 0xC4, 0x10])


def encode_pslld_immediate(destination, amount):
	"""pslld $imm,xmm -- the destination is in r/m and reg is the extension."""
	out = bytearray([0x66])
	rex = 0x40 | (destination >> 3)
	if rex != 0x40:
		out.append(rex)
	out += b"\x0f\x72"
	out.append(0xC0 | (6 << 3) | (destination & 7))
	out.append(amount)
	return bytes(out)


def lower_permilps(vex, tail, operands, scratch, at, pool,
                   clobber_control=False):
	"""vpermilps, both forms.

	The immediate form is a shufps and needs nothing. The variable form has
	no SSE instruction, and `project.md` calls for a helper -- but a call
	inside a stub pushes a return address, which moves rsp in code with no
	.pdata, and that is the same broken-unwind trade rejected for spilling.
	Stub space is free, so the sequence is inlined instead.

	SSSE3's pshufb is already a variable-control permute; it just works on
	bytes. Turning four element selectors into sixteen byte selectors is
	four instructions and three constants -- see src/permil.c, where the
	same sequence is exhaustively tested.

	Operand order is control, data, dst: the VEX vvvv field holds the DATA
	and r/m the CONTROL, which is the opposite of vpermd.

	**`clobber_control` lets the scratch BE the control register**, which
	the guard below otherwise refuses. It is safe exactly when the caller
	owns the control -- the sequence reads it once, in the first `movaps`,
	and everything after works on the scratch. For a 128-bit site the
	control is a live architectural register and the refusal is right; for
	the upper half of a 256-bit one it is a copy this lowering just loaded
	out of a slot, and destroying it costs nothing. That is what lets the
	256-bit form need two spare registers rather than three. Finding 246.
	"""
	if vex["L"]:
		return None			# 256-bit needs the Y representation
	modrm = tail[1]
	if ((modrm >> 6) & 3) != 3:
		return None			# memory operand; not handled here
	destination = (vex["R"] << 3) | ((modrm >> 3) & 7)
	control = (vex["B"] << 3) | (modrm & 7)
	data = vex["vvvv"]

	if any(o.startswith("$") for o in inplace.split_operands(operands)):
		# Immediate control: a single-source four-element permute, which is
		# exactly shufps with both operands the same register.
		immediate = tail[2] if len(tail) > 2 else None
		if immediate is None:
			return None
		body = bytearray()
		if destination != control:
			body += encode_rr(None, MOVAPS, destination, control)
		body += encode_rr(None, b"\x0f\xc6", destination, destination,
		                  immediate)
		return bytes(body)

	if scratch is None or scratch in (destination, data):
		return None
	if scratch == control and not clobber_control:
		return None

	body = bytearray()
	body += encode_rr(None, MOVAPS, scratch, control)
	for offset, prefix, opcode in (
			(POOL_MASK3, 0x66, b"\x0f\xdb"),		# pand  -- bits 1:0
			(None, None, None),						# pslld $2, below
			(POOL_BCAST, 0x66, b"\x0f\x38\x00"),	# pshufb -- replicate
			(POOL_STEP, 0x66, b"\x0f\xfc")):		# paddb  -- 0,1,2,3
		if offset is None:
			body += encode_pslld_immediate(scratch, 2)
			continue
		piece = encode_rip(prefix, opcode, scratch, pool + offset,
		                   at + len(body))
		if piece is None:
			return None
		body += piece
	if destination != data:
		body += encode_rr(None, MOVAPS, destination, data)
	body += encode_rr(0x66, b"\x0f\x38\x00", destination, scratch)
	return bytes(body)


def lower_broadcast(vex, tail, mnemonic, encoding, address, at):
	"""vbroadcastss / vbroadcastsd / vpbroadcastd. Needs no scratch."""
	if vex["L"]:
		return None			# 256-bit needs the Y representation
	load_prefix, load_opcode, spread_prefix, spread_opcode = \
		BROADCASTS[mnemonic]
	modrm = tail[1]
	destination = (vex["R"] << 3) | ((modrm >> 3) & 7)

	body = bytearray()
	if ((modrm >> 6) & 3) == 3:
		# The AVX2 register form. There is nothing to load; the value has
		# to reach the destination before it can be spread across it.
		source = (vex["B"] << 3) | (modrm & 7)
		if spread_opcode is None:
			return None		# movddup from a register is a different shape
		if destination != source:
			body += encode_rr(None, MOVAPS, destination, source)
	else:
		load = bytearray()
		if load_prefix is not None:
			load.append(load_prefix)
		rex = 0x40 | (vex["R"] << 2) | (vex["X"] << 1) | vex["B"]
		if rex != 0x40:
			load.append(rex)
		load += load_opcode
		load += tail[1:]
		if rip_relative(tail):
			# Relative to the end of the instruction, and the instruction
			# has moved. There is no immediate on a broadcast, so the
			# displacement is the last four bytes.
			old = struct.unpack_from("<i", load, len(load) - 4)[0]
			target = address + len(encoding) + old
			displacement = target - (at + len(load))
			if not -(1 << 31) <= displacement < (1 << 31):
				return None
			load[len(load) - 4:] = struct.pack("<i", displacement)
		body += load

	if spread_opcode is not None:
		# shufps $0 / pshufd $0: every lane takes element zero.
		body += encode_rr(spread_prefix, spread_opcode, destination,
		                  destination, 0x00)
	return bytes(body)


SEQUENCE_MNEMONICS = frozenset((
	"vblendvps", "vblendvpd", "vpermilps",
)) | frozenset(BROADCASTS)


def encode_jump(from_end, to_address):
	"""jmp rel32, whose displacement is measured from the end of the jump."""
	return bytes([JMP_REL32]) + struct.pack("<i", to_address - from_end)


def lower_vex(address, encoding, operands, mnemonic, at, scratch=None,
              pool=0, reasons=None):
	"""Lower one VEX instruction for execution at `at`. Bytes, or None.

	Used for the Class C site itself and for a swallowed instruction that
	turns out to be VEX too -- which most of them are, since VEX code comes
	in runs. Copying such an instruction into a stub unchanged would leave
	AVX in the output, which is the one thing the whole exercise is for.
	Inside a stub there is room, so it is lowered rather than refused.
	"""
	vex = inplace.decode_vex(encoding)
	if vex is None:
		if reasons is not None:
			reasons["lower: not a VEX encoding"] += 1
		return None
	# **Only mnemonics with a direct SSE form.** Stripping a VEX prefix is
	# a lowering only for those; for anything else it produces bytes that
	# are not an instruction. vbroadcastss is the one that got through
	# here: 0F 38 18 exists only under VEX, so `66 0f 38 18` decodes to
	# nothing at all and the disassembler desynchronises from there.
	# Class D, F and H need real sequences and belong in their own tools.
	if mnemonic in inplace.DESTINATION_IN_VVVV:
		# **The opcode tells the two forms apart, and the name cannot.**
		# `patch.py` says so where it excludes this group wholesale: "the
		# shift group mixes NDD immediate forms with NDS register forms
		# under one mnemonic, so telling them apart needs the opcode
		# rather than the name". Routing on the mnemonic sent BOTH to a
		# lowering written for one of them, and the variable form
		# refused -- 22 sites in Starfield, every one an ordinary
		# three-operand shape, and 21 of them surviving in the frontier.
		# Routing on the opcode released exactly those 21.
		#
		#     c5 e1 f3 c8   vpsllq %xmm0,%xmm3,%xmm1   opcode f3, NDS
		#     c5 f1 73 f1 02   vpsllq $0x2,%xmm1,%xmm1  opcode 73, NDD
		#
		# `0F 71/72/73` is the immediate group, where ModRM.reg is an
		# opcode extension and `vvvv` carries the destination. Anything
		# else in this set is the variable-count form, whose destination
		# is where every other three-operand instruction keeps it, and
		# it goes down the ordinary path. Finding 311.
		shift_tail = encoding[vex["length"]:]
		if shift_tail and shift_tail[0] in (0x71, 0x72, 0x73):
			out = lower_vvvv_shift(vex, encoding, operands)
			if out is None and reasons is not None:
				reasons["lower: the vvvv shift would not lower"] += 1
			return out
	if not inplace.has_direct_sse_form(mnemonic):
		if mnemonic in SEQUENCE_MNEMONICS or FMA_PATTERN.match(mnemonic):
			tail = encoding[vex["length"]:]
			if len(tail) < 2:
				if reasons is not None:
					reasons["lower: a sequence with no modrm"] += 1
				return None
			if mnemonic.startswith("vblendv"):
				out = lower_blendv(vex, tail, mnemonic, scratch)
				if out is None and reasons is not None:
					reasons["lower: vblendv would not lower"] += 1
				return out
			if mnemonic in BROADCASTS:
				out = lower_broadcast(vex, tail, mnemonic, encoding,
				                      address, at)
				if out is None and reasons is not None:
					reasons["lower: the broadcast would not lower"] += 1
				return out
			if mnemonic == "vpermilps":
				out = lower_permilps(vex, tail, operands, scratch, at, pool)
				if out is None and reasons is not None:
					reasons["lower: vpermilps would not lower"] += 1
				return out
			out = lower_fma(vex, tail, mnemonic, scratch, address,
			                encoding, at)
			if out is None and reasons is not None:
				reasons["lower: the FMA would not lower"] += 1
			return out
		if reasons is not None:
			reasons["lower: no direct SSE form and not a sequence"] += 1
		return None
	tail = encoding[vex["length"]:]
	if len(tail) < 2:
		if reasons is not None:
			reasons["lower: no modrm"] += 1
		return None
	fields = inplace.split_operands(operands)
	registers = [o for o in fields if not o.startswith("$")]
	has_immediate = len(registers) != len(fields)

	body = bytearray()
	if len(registers) == 3 and registers[-1] != registers[-2]:
		destination, source = registers_of(vex, tail)
		if ((tail[1] >> 6) & 3) == 3 and registers[0] == registers[-1]:
			# **src2 and the destination are the same register.** The movaps
			# below overwrites the destination with src1, which destroys
			# src2 before the operation reads it. For a commutative
			# operation that gives the wrong operand; for a subtract it
			# gives a constant. `vsubss %xmm0,%xmm1,%xmm0` lowered without
			# this check becomes `movaps %xmm1,%xmm0; subss %xmm0,%xmm0`,
			# which is always exactly zero, and nothing about the output
			# looks wrong -- it assembles, it disassembles, it carries no
			# VEX, and every structural check passes.
			#
			# Swapping the operands would fix the commutative cases and
			# quietly break the rest. Even where the arithmetic commutes the
			# NaN propagation does not: x86 picks which source NaN survives
			# by operand order, which is the same trap the fmsubadd negation
			# fell into (src/fmaddsub.c, 291 disagreeing vectors, all NaN).
			#
			# So src2 is preserved in a scratch and the operand order is
			# kept exactly as the VEX form had it.
			source2 = (vex["B"] << 3) | (tail[1] & 7)
			if scratch is None or scratch in (destination, source, source2):
				if reasons is not None:
					reasons["lower: the aliased form has no usable scratch"] += 1
				return None
			body += encode_movaps(scratch, source2)
			body += encode_movaps(destination, source)
			vex = dict(vex, B=scratch >> 3)
			tail = bytes([tail[0], (tail[1] & 0xF8) | (scratch & 7)]) \
				+ tail[2:]
		else:
			body += encode_movaps(destination, source)
	elif len(registers) == 3:
		pass				# destination already holds the first source
	elif len(registers) not in (1, 2):
		if reasons is not None:
			reasons["lower: a four-operand form"] += 1
		return None			# four-operand forms are not Class A/B/C
	# One operand sets nothing up: `vldmxcsr` and `vstmxcsr` name a memory
	# operand and no register, so `sse_encoding` below is the whole lowering.
	# Admitting the shape in `collect` without admitting it here turned a
	# counted decline into a stub that could never build, under a reason
	# naming a four-operand form. Finding 111.

	operation = inplace.sse_encoding(vex, tail)
	if operation is None:
		if reasons is not None:
			# `sse_encoding` refuses two different things and they mean
			# opposite amounts of work: an unsupported opcode map is an
			# encoding gap, while VEX.L is a 256-bit instruction that no Y
			# strategy claimed -- it needs the register model, not a table
			# entry. Naming them together hid which. Finding 89.
			reasons["lower: 256-bit, no Y strategy took it" if vex["L"]
			        else "lower: no SSE encoding for the opcode"] += 1
		return None

	if rip_relative(tail):
		# Relative to the end of the instruction, and the instruction has
		# moved. The field sits four bytes from the end, or five when an
		# immediate follows it.
		offset = len(operation) - 4 - (1 if has_immediate else 0)
		if offset < 0:
			if reasons is not None:
				reasons["lower: the RIP field is not where expected"] += 1
			return None
		old = struct.unpack_from("<i", operation, offset)[0]
		target = address + len(encoding) + old
		new_end = at + len(body) + len(operation)
		displacement = target - new_end
		if not -(1 << 31) <= displacement < (1 << 31):
			if reasons is not None:
				reasons["lower: the RIP displacement will not reach"] += 1
			return None
		operation = (operation[:offset]
		             + struct.pack("<i", displacement)
		             + operation[offset + 4:])
	body += operation
	return bytes(body)


def prologue_frame(data, unwind_at, start, depth=0):
	"""Bytes the prologue takes off `rsp`, from the unwind codes, or None.

	The borrow writes `[rsp+0..31]` as `rsp` stands inside the body, so
	knowing where the body's `rsp` sits relative to the entry value is what
	turns a copy's offset into an address. A chained fragment shares its
	primary's frame, so the chain is followed and the sizes add.
	"""
	if depth > 4 or start not in unwind_at:
		return None
	off, base = unwind_at[start]
	flags, _prologue, count, frame = data[off:off + 4]
	if frame & 0xF:
		return None			# a frame register: rsp is not the base
	total, i, codes = 0, 0, off + 4
	while i < count:
		packed = data[codes + i * 2 + 1]
		op, info = packed & 0xF, packed >> 4
		if op == 0:			# UWOP_PUSH_NONVOL
			total += 8
			i += 1
		elif op == 1:			# UWOP_ALLOC_LARGE
			if info == 0:
				total += struct.unpack_from(
					"<H", data, codes + (i + 1) * 2)[0] * 8
				i += 2
			else:
				total += struct.unpack_from(
					"<I", data, codes + (i + 1) * 2)[0]
				i += 3
		elif op == 2:			# UWOP_ALLOC_SMALL
			total += info * 8 + 8
			i += 1
		elif op == 3:			# UWOP_SET_FPREG
			return None
		elif op in (4, 8):
			i += 2
		elif op in (5, 9):
			i += 3
		else:
			i += 1
	if flags >> 3 & 4:			# UNW_FLAG_CHAININFO
		aligned = (count + (count & 1)) * 2
		parent = struct.unpack_from("<I", data, codes + aligned)[0]
		outer = prologue_frame(data, unwind_at, base + parent, depth + 1)
		if outer is None:
			return None
		total += outer
	return total


# **The caller's shadow: the other 32 bytes, and the ones a leaf has.**
# Win64 makes the CALLER allocate 32 bytes for the callee to spill its
# register parameters into, above the pushed return address. It is always
# allocated, whatever the callee's arity, and the callee may use it for
# anything -- so it is a second borrowable region, and unlike the one
# `home_space_map` lends it does not require the function to call anything.
#
# That matters because a leaf can lend nothing today. `home_space_map` needs
# `calls[i]`, since the 32 bytes it lends are the ones this function reserves
# for ITS callees and a leaf reserves none. `no home space to borrow` is the
# largest named cause anywhere in the residue -- 1,916 of the 3,533 surviving
# 128-bit sites -- and it is mostly scalar float arithmetic whose destination
# aliases its second source.
#
# Entry-relative, the return address is at `[0,8)` and the shadow at `[8,40)`.
# `copy_reaches_home`'s own docstring has named both regions since Finding 96
# and said only the callee one was at risk; this is the other half of that
# sentence.
CALLER_SHADOW = (8, 8 + HOME_SPACE)


def rsp_depths(rows, frame, after_prologue):
	"""Where `rsp` stands at each address, entry-relative, or a refusal.

	Returns `({address: depth or None}, body_depth)`, or `(None, reason)`.

	The shadow is addressed from `rsp`, so lending it needs `rsp`'s VALUE at
	the save -- not merely, as the callee home space needs, the promise that
	it has not moved since the prologue. The first attempt asked for the
	weaker-looking property "nothing moves `rsp` after the prologue" and
	refused 184,724 of 260,729 functions, because that is not a property
	about frames at all: it is "the function has an epilogue".

	**The model checks itself at every `ret`.** A return is reached with the
	frame fully unwound, so the depth there must be exactly zero; a function
	whose returns do not balance is one whose frame this has misread, and it
	lends nothing. That check is the whole reason this is allowed to walk
	linearly through code with branches in it.

	The other half of that permission is the branch rule. A branch carries
	its depth to a target the walk reaches by falling into it, so a branch
	taken anywhere but at the body depth or at a fully unwound frame would
	make its target's depth a guess. Refuse the function rather than guess.

	An unknown depth is block-local rather than fatal. MSVC restores a large
	frame with `mov %r11,%rsp`, which no walk can follow, and that is an
	epilogue every site in the function precedes -- 1,122 starved sites sat
	behind one. The unknown ends at the terminator, since the block after it
	is entered by a branch and every branch source was just checked.
	"""
	body, depth, seen = -frame, 0, {}
	for address, mnemonic, operands in rows:
		seen[address] = depth
		if mnemonic.startswith(("j", "loop")) and depth not in (body, 0):
			return None, "a branch leaves at an unmodelled depth"
		if mnemonic in ("ret", "retq"):
			if depth is not None and depth != 0:
				return None, "a return does not balance the frame"
			depth = body
			continue
		if mnemonic in ("push", "pushq"):
			depth = None if depth is None else depth - 8
		elif mnemonic in ("pop", "popq"):
			depth = None if depth is None else depth + 8
		elif RSP_WRITTEN.search(operands or "") \
				and not RSP_COPY.match(operands or ""):
			step = immediate_step(mnemonic, operands, "%rsp")
			depth = None if step is None or depth is None else depth + step
		elif mnemonic in ("jmp", "jmpq"):
			depth = body
	if after_prologue is None and any(seen.values()):
		# No unwind data at all. The ABI permits that only for a leaf that
		# never moves `rsp`, so the frame was taken as zero above -- and
		# this is where the code is asked whether it agrees.
		return None, "no unwind data and rsp moves"
	return seen, body


# `--region=` decides what a direct reference to a home space costs.
# `whole` refuses the function for one anywhere in it, which is what
# Findings 72 to 130 shipped; `live` asks whether the reference can still be
# reached from the site. Keep `whole` reachable: a borrow that clobbers a
# local the function still reads does not fault, so comparing two binaries is
# the only way to test for it. See Finding 131.
REGION_WHOLE, REGION_LIVE = "whole", "live"
REGION_RULE = REGION_LIVE


# The volatile general-purpose registers of the Win64 ABI. A stub may borrow
# only a volatile register, for Finding 123's reason: a non-volatile one owes
# its caller the value back, and the stub section has no unwind codes to say
# where it was put.
VOLATILE_GPRS = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")

# The four that carry integer arguments, in order. Nothing here knows a
# callee's arity, so a call reads all four.
ARGUMENT_GPRS = frozenset(("rcx", "rdx", "r8", "r9"))

# What a `ret` hands back. `rdx` is here for the 128-bit return, which is
# rare and costs only `rdx`, a register this analysis was never going to
# free anyway.
RETURN_GPRS = frozenset(("rax", "rdx"))

# Every spelling of every one of them, because a read of `%r8b` is a read of
# `%r8` and a scan keyed on the 64-bit name alone would not see it. The
# high-byte forms alias bits 15:8 of the first three.
GPR_SPELLINGS = {}
for _wide, _parts in (
		("rax", ("rax", "eax", "ax", "al", "ah")),
		("rcx", ("rcx", "ecx", "cx", "cl", "ch")),
		("rdx", ("rdx", "edx", "dx", "dl", "dh")),
		("r8", ("r8", "r8d", "r8w", "r8b")),
		("r9", ("r9", "r9d", "r9w", "r9b")),
		("r10", ("r10", "r10d", "r10w", "r10b")),
		("r11", ("r11", "r11d", "r11w", "r11b"))):
	for _part in _parts:
		GPR_SPELLINGS[_part] = _wide

# The spellings whose write reaches all 64 bits: a 32-bit write zero-extends,
# an 8- or 16-bit one leaves the rest of the register alone and is therefore
# not a kill. Written out rather than derived -- the first version took the
# names beginning with "r", which is every 64-bit name and also `r10b` and
# `r10w`, so an 8-bit write killed the whole register. The selftest case for
# the narrow write is what caught it.
GPR_FULL_WRITE = frozenset((
	"rax", "rcx", "rdx", "r8", "r9", "r10", "r11",
	"eax", "ecx", "edx", "r8d", "r9d", "r10d", "r11d"))

# Mnemonics whose last operand is written and not also read. Deliberately
# three: `add %rax,%r11` writes r11 and reads it too, and the cost of
# getting that wrong is a borrow over a live value.
GPR_WRITERS = frozenset(("mov", "movabs", "lea"))

_GPR_TOKEN = re.compile(r"%(\w+)")


def gprs_named(operands):
	"""The volatile GPRs any spelling in `operands` names."""
	if not operands:
		return frozenset()
	found = set()
	for token in _GPR_TOKEN.findall(operands):
		wide = GPR_SPELLINGS.get(token)
		if wide is not None:
			found.add(wide)
	return frozenset(found)


def gpr_effect(mnemonic, operands):
	"""`(read, written)` volatile GPRs for one instruction.

	**Every mention is a read and almost nothing is a write.** That is the
	direction that costs sites rather than the one that corrupts a program:
	a register wrongly called live loses a borrow, one wrongly called dead
	destroys a value while it is still wanted, and nothing downstream would
	look wrong.

	**A call reads the four argument registers and writes NOTHING**, which
	is the decision in this function worth arguing about. The ABI makes all
	seven volatile, so the obvious rule is that a call clobbers every one of
	them and kills its liveness -- and this binary refutes that twice over.
	Its `__chkstk` at 0x14365d930 saves `r10` and `r11` to the stack on
	entry and restores them before returning, so it preserves the two
	registers the ABI most clearly lets it destroy; and its callers rely on
	that kind of thing, because the frame-allocation sequence is

	    mov  $0x99e0,%eax
	    call 0x14365d930
	    sub  %rax,%rsp

	where `rax` is live ACROSS the call. A rule that killed the volatiles at
	a call would have called `rax` dead at the `mov` and let a borrow take
	the frame size. **What the ABI permits a callee to do is not what this
	program relies on it not doing**, and only the second is safe to assume.
	"""
	named = gprs_named(operands)
	if mnemonic.startswith("call"):
		return (named | ARGUMENT_GPRS, frozenset())
	if mnemonic.startswith("ret"):
		return (RETURN_GPRS, frozenset())
	if mnemonic in GPR_WRITERS:
		fields = inplace.split_operands(operands or "")
		destination = fields[-1] if fields else ""
		if len(fields) == 2 and destination.startswith("%") \
				and "(" not in destination:
			written = GPR_SPELLINGS.get(destination[1:])
			if written is not None \
					and destination[1:] in GPR_FULL_WRITE:
				# The source still reads whatever it names, including this
				# register: `mov (%r11),%r11` writes r11 and reads it.
				return (gprs_named(fields[0]), frozenset((written,)))
	return (named, frozenset())


# **The vector registers a stub may borrow.** Win64 makes xmm0-xmm5
# volatile and xmm6-xmm15 the callee's to preserve, and Finding 123 settled
# that only a volatile one may be taken: the stub section has no unwind
# codes to say where a non-volatile register was put, so a fault inside the
# bracket loses the caller's value.
VOLATILE_XMM = (0, 1, 2, 3, 4, 5)

# The four that carry floating-point arguments. A call reads as many as the
# callee takes and nothing here knows how many.
ARGUMENT_XMM = frozenset((0, 1, 2, 3))

# What a `ret` hands back.
RETURN_XMM = frozenset((0,))

# Moves whose last operand is written and not also read, which is what makes
# a write a KILL rather than another read. Deliberately the plain moves:
# `addps %xmm1,%xmm0` writes xmm0 and reads it too, and the cost of getting
# that wrong is a helper taken over a live value.
XMM_WRITERS = frozenset("""
	movaps movups movapd movupd movdqa movdqu
	vmovaps vmovups vmovapd vmovupd vmovdqa vmovdqu
""".split())


def xmm_effect(mnemonic, operands):
	"""`(read, written)` volatile xmm registers for one instruction.

	`gpr_effect`'s counterpart, and the same conservatism for the same
	reason: every mention is a read, and almost nothing is a write. A
	register wrongly called live costs a site; one wrongly called dead
	destroys a value while something still wants it, and nothing
	downstream looks wrong.

	**A call reads the argument registers and writes nothing**, which is
	`gpr_effect`'s decision and rests on the same evidence -- this binary's
	`__chkstk` preserves registers the ABI lets it destroy, so what the ABI
	permits a callee to do is not what the program relies on it not doing.

	`%ymm3` and `%xmm3` are the same register here. A helper holds sixteen
	bytes, and a mention of either name means something is using them.
	"""
	named = frozenset(n for n in scratch_finder.xmm_numbers(operands)
	                  if n in VOLATILE_XMM)
	if mnemonic.startswith("call"):
		return (named | ARGUMENT_XMM, frozenset())
	if mnemonic.startswith("ret"):
		return (RETURN_XMM, frozenset())
	if mnemonic in XMM_WRITERS:
		fields = inplace.split_operands(operands or "")
		destination = fields[-1] if fields else ""
		if len(fields) == 2 and destination.startswith("%xmm") \
				and "(" not in destination:
			written = scratch_finder.xmm_numbers(destination)
			if len(written) == 1 and written[0] in VOLATILE_XMM:
				# The source still reads what it names, this register
				# included: `movaps (%rax,%xmm0),%xmm0` is not a shape that
				# occurs, but `movaps %xmm0,%xmm0` is legal and reads it.
				return (frozenset(n for n in
				                  scratch_finder.xmm_numbers(fields[0])
				                  if n in VOLATILE_XMM),
				        frozenset((written[0],)))
	return (named, frozenset())


def xmm_live_out(plain, first, last, inside_targets, exit_live=None):
	"""`{position: frozenset}` -- volatile xmm live AFTER each position.

	The question `function_scope` answers for a whole function, asked at a
	place instead. That rule -- free everywhere because the function names
	it nowhere -- reaches only `FUNCTION_SCRATCH`, which is xmm4 and xmm5,
	and Finding 148 measured what it costs: 2,782 of the 3,355 sites a
	call-free region could represent are refused for want of one xmm free
	across the region, because over a stretch of up to 192 instructions
	almost no register is named nowhere.

	**Inside a call-free region the argument registers are candidates
	too.** xmm0-xmm3 are read by a call and a region contains none, so what
	disqualifies them is only a real use -- and the call that ENDS the
	region is a position like any other, where `xmm_effect` reads them.
	Nothing special is needed to get that right, which is the point of
	asking liveness rather than asking a rule.
	"""
	return register_live_out(plain, first, last, inside_targets, xmm_effect,
	                         frozenset(VOLATILE_XMM), exit_live)


def gpr_function_scope(plain, ranges):
	"""Per function, the volatile GPRs it provably never touches.

	`scratch.function_scope`'s argument, applied to general-purpose
	registers instead of to xmm: if a range never NAMES `r10`, nothing in
	it reads `r10`; no callee can expect it, because it is not an argument
	register; and no caller can expect it, because it is volatile. So it is
	free at every point in the range.

	The escape rule is the same blunt one, and is why this exists here only
	as a baseline. Any jump whose target is outside the range, any indirect
	jump, and any range not ending in a control transfer disqualifies the
	whole range -- because a `.pdata` entry is not always a whole function,
	and the other half of a split one is entered with registers live. Real
	tail calls are lost with it.

	Finding 139 priced static TLS at 67 sites with this argument and said
	in the same sentence that 500 more were refused only by its bluntness.
	`gpr_live_out` asks the question at a place instead, and `gpr_survey`
	prints the two side by side.
	"""
	starts = [start for start, _end in ranges]
	mentioned = [set() for _ in ranges]
	escapes = [False] * len(ranges)
	last_mnemonic = [None] * len(ranges)
	for address, _encoding, mnemonic, operands in plain:
		i = bisect.bisect_right(starts, address) - 1
		if i < 0 or address >= ranges[i][1]:
			continue
		mentioned[i].update(gprs_named(operands or ""))
		if mnemonic.startswith("call"):
			mentioned[i].update(ARGUMENT_GPRS)
		last_mnemonic[i] = mnemonic
		if not mnemonic.startswith(("j", "loop")):
			continue
		target = None
		field = (operands or "").split()[0] if operands else ""
		if field.startswith("0x"):
			try:
				target = int(field, 16)
			except ValueError:
				target = None
		if target is None or not ranges[i][0] <= target < ranges[i][1]:
			escapes[i] = True
	for i, mnemonic in enumerate(last_mnemonic):
		if mnemonic is None or not (mnemonic.startswith(("ret", "jmp", "ud"))
		                            or mnemonic == "int3"):
			escapes[i] = True
	free = [frozenset() if escapes[i]
	        else frozenset(r for r in VOLATILE_GPRS if r not in mentioned[i])
	        for i in range(len(ranges))]
	return starts, free


def gpr_live_out(plain, first, last, inside_targets):
	"""`{position: frozenset}` -- the volatile GPRs live AFTER each position.

	Backward liveness over one function range, the general-purpose answer to
	the question Findings 131 and 134 answered for a home space: not "does
	this function touch the register" but "can anything that reads it still
	run". `function_scope` asks the whole-function form and refuses a range
	for any way out of it, which loses every real tail call deliberately;
	a borrow bracket holds one instruction and contains no control transfer
	at all, so what it needs is a register dead AT A PLACE.

	**Where control leaves in a way this cannot follow, everything is
	live.** A jump out of the range is a tail call and reads the argument
	registers; an indirect branch may be one; a fall-through off the end
	arrives somewhere this never looked. Each of those is seeded with all
	seven rather than with the four a tail call would really read, because
	the reason they are here is that the destination is unknown -- and a
	set chosen from a guess about an unknown destination is a guess.

	A `ret` is not one of those. It is modelled exactly: the caller reads
	the return value and nothing else, so `r10` and `r11` are dead at
	every one.
	"""
	return register_live_out(plain, first, last, inside_targets, gpr_effect,
	                         frozenset(VOLATILE_GPRS))


def register_live_out(plain, first, last, inside_targets, effect, everything,
                      exit_live=None):
	"""`{position: frozenset}` -- which registers are live AFTER each one.

	The backward fixpoint itself, shared by every register family that asks
	it. What differs between families is `effect` -- what an instruction
	reads and writes -- and `everything`, the set that is live where control
	goes somewhere this cannot follow. The WALK is the same question in
	both cases, and it is written once so the two cannot disagree about a
	back edge.
	"""
	successors, unresolved, leaving = control_successors(
		plain, first, last, inside_targets)
	# **What is live where control leaves the range.** Everything, unless
	# the caller knows better -- and over a CALL-FREE REGION it does: a
	# region ends at a call, and the ABI says every volatile register is
	# dead there, which is the same fact that makes a region a unit at all.
	#
	# The default is not conservatism for its own sake. `gpr_live_out` runs
	# over whole `.pdata` functions, which end in `ret` and are modelled
	# exactly; a range ending anywhere else genuinely does not know what
	# follows. Measured before this was a parameter: seeding a region's
	# terminating call as unknown floods every position backward with every
	# register, and per-position liveness answered FEWER free registers
	# than the whole-function rule it was meant to beat -- 81 against 573.
	if exit_live is None:
		exit_live = everything
	effects = {}
	for position in range(first, last):
		_a, _e, mnemonic, operands = plain[position]
		effects[position] = effect(mnemonic, operands or "")

	# Seeded once: what is live on the way OUT of a position, before any
	# successor has been accounted for.
	base = {}
	for position in range(first, last):
		out = set()
		if position in unresolved or position in leaving:
			out |= exit_live
		base[position] = out

	live_in, live_out = {}, {}
	for position in range(first, last):
		live_out[position] = frozenset(base[position])
		read, written = effects[position]
		live_in[position] = read | (live_out[position] - written)

	# **Predecessors are built rather than searched for.** The first draft
	# rescanned every position of the range to find who pointed at the one
	# it had just changed, which is quadratic in the function's length --
	# and the ranges here run to thousands of instructions.
	predecessors = {}
	for position, edges in successors.items():
		for edge in edges:
			if first <= edge < last:
				predecessors.setdefault(edge, []).append(position)

	work = list(range(first, last))
	in_work = set(work)
	while work:
		position = work.pop()
		in_work.discard(position)
		out = set(base[position])
		for edge in successors.get(position, ()):
			if first <= edge < last:
				out |= live_in[edge]
		if out == live_out[position]:
			continue
		live_out[position] = frozenset(out)
		read, written = effects[position]
		fresh = read | (live_out[position] - written)
		if fresh == live_in[position]:
			continue
		live_in[position] = fresh
		for earlier in predecessors.get(position, ()):
			if earlier not in in_work:
				work.append(earlier)
				in_work.add(earlier)
	return live_out


def control_successors(plain, first, last, inside_targets):
	"""`(successors, unresolved, leaving)` over the positions `[first, last)`.

	The control-flow graph of one function range, shared by every analysis
	that walks one. The EDGES are the same question whoever asks -- where
	can control go from here -- so they are built once; what differs
	between callers is what an edge MEANS, and that is left to them.

	  * `unresolved` is the positions whose control this cannot model at
	    all: a fall-through off the end of the range, and a branch into
	    the middle of an instruction. Every caller has to treat one as
	    reaching whatever it is afraid of.
	  * `leaving` is the positions from which control can go OUTSIDE the
	    range while the program carries on -- a jump to another `.pdata`
	    entry, or an indirect one. `readers_reachable` may ignore it,
	    because a home space belongs to a frame that a departure abandons.
	    `gpr_live_out` may not: a jump out of a range is a tail call, and
	    a tail call reads the argument registers.

	A `ret` is neither. It is an exit this models exactly, and what is
	live across one is the caller's business rather than an unknown.
	"""
	successors, unresolved, leaving = {}, set(), set()
	for position in range(first, last):
		_address, _encoding, mnemonic, operands = plain[position]
		operands = operands or ""
		if mnemonic.startswith("ret"):
			successors[position] = ()
			continue
		following = position + 1
		if mnemonic.startswith(("j", "loop")):
			target, first_field = None, operands.split()[0] if operands else ""
			if first_field.startswith("0x"):
				try:
					target = int(first_field, 16)
				except ValueError:
					target = None
			if target is None:
				# Indirect. It can only land where something can be
				# branched to, and this function's share of that set is
				# `inside_targets` -- but it can also be a call through a
				# pointer that never comes back here.
				successors[position] = inside_targets
				leaving.add(position)
				continue
			inside = plain[first][0] <= target < plain[last - 1][0] + 1 \
				if last > first else False
			edges = []
			if inside:
				at = bisect.bisect_left(plain, (target,), first, last)
				if at < last and plain[at][0] == target:
					edges.append(at)
				else:
					# A branch into the middle of an instruction is not
					# something this can model. Refuse to model the rest.
					unresolved.add(position)
			else:
				leaving.add(position)
			# A conditional falls through as well; an unconditional does
			# not, and one leaving the range takes its edge with it.
			if not mnemonic.startswith("jmp"):
				if following < last:
					edges.append(following)
				else:
					unresolved.add(position)
			successors[position] = tuple(edges)
			continue
		# Everything else falls through, `call` included: it comes back.
		if following < last:
			successors[position] = (following,)
		else:
			# Off the end of the range with no terminator. Where control
			# goes is the range's business and the range may be wrong.
			unresolved.add(position)
			successors[position] = ()
	return successors, unresolved, leaving


def readers_reachable(plain, first, last, refs, inside_targets):
	"""Positions in `[first, last)` from which some position in `refs` can
	still be reached. `refs` must not be empty.

	**Why reachability and not a bracket.** A borrow writes the register
	into the region and reads it back; it never puts the region's own
	contents back, and there is nowhere to put them back from. So the
	region is destroyed from the site onward, and the question a site has
	to answer is not "does this function touch the region" -- which refuses
	507 of 577 sites for nothing -- but "can anything that reads it still
	run". Finding 131.

	One fixpoint per function, then a lookup per site, rather than a walk
	per site: the reference set is small and fixed while the sites asking
	about it are many.

	**An indirect branch goes to `inside_targets` and nowhere else.** That
	is `targets.py`'s set restricted to this function -- switch tables,
	relocations, addresses taken by `lea` -- and it is the same set the
	whole detour scheme already trusts to say where a window may not
	swallow an instruction. Seeding an indirect branch as reaching every
	position instead is sound and useless: a function with a switch table
	then refuses its whole body, which in this binary is most of the large
	ones.

	**Every other edge this cannot resolve reaches everything.** A
	fall-through off the end of the range, or a branch into the middle of
	an instruction, means control could arrive at a reader by a route not
	modelled, so the position is seeded as though it did. That is the
	direction that costs sites rather than the one that corrupts a frame.
	"""
	successors, unresolved, _leaving = control_successors(
		plain, first, last, inside_targets)

	predecessors = {}
	for position, edges in successors.items():
		for edge in edges:
			predecessors.setdefault(edge, []).append(position)

	reaching = set(refs) | unresolved
	work = list(reaching)
	while work:
		position = work.pop()
		for earlier in predecessors.get(position, ()):
			if earlier not in reaching:
				reaching.add(earlier)
				work.append(earlier)
	return reaching


def copy_reaches_home(rows, frame, region=None, hazards=None):
	"""True if a copy of `rsp` could reach a home space, or cannot be
	followed. Refusing is the answer to every doubt.

	`hazards` turns two of the refusals from a verdict about the function
	into a list of ADDRESSES, which the caller can then ask reachability
	about exactly as it does a direct operand -- see `region_readers` and
	Finding 131. Left out, everything behaves as before.

	**Only two of the six refusals are positional**, and the split is the
	whole of what makes this safe. A dereference through a tracked copy
	that lands in the region, and an indexed access through one, each
	happen AT a place: if the site cannot reach that place, the borrow does
	not disturb it. The other four are not about a place at all -- a copy
	pushed or escaping into the region leaves this text entirely, a copy
	taken at an unknown depth was never located, and arithmetic that cannot
	be followed poisons every later dereference through that register
	rather than one. Those stay verdicts about the function.

	`region` is the entry-relative half-open range at risk, and it exists
	because there are two of them. Left out, it is the callee home space
	this function reserves, which is what every caller wanted until the
	shadow borrow arrived; `CALLER_SHADOW` asks the same question of the 32
	bytes this function's own caller reserved. One walk, two regions --
	rather than a second copy of a hundred lines that would drift.

	**There are two home spaces and only one is at risk.** The 32 bytes this
	function's caller reserved sit above the return address; the 32 it
	reserves for its own callees sit at the bottom of its frame, and the
	borrow writes only the second. MSVC's `mov %rsp,%rax` prologue exists to
	reach the FIRST one after the pushes have moved `rsp`, so the copy that
	triggered the blanket refusal normally points a whole frame away from
	the region at risk. Finding 96 measured the difference: of 2,464 starved
	sites whose function copies `rsp`, not one reaches the region through
	the copy, and 846 can be proved not to.

	So the copy's value is tracked as an offset from the entry `rsp`, the
	frame comes from the unwind codes, and a dereference at `d` through a
	copy holding `k` lands in the region exactly when `k + d` falls in
	`[-frame, -frame+32)`.

	**What it refuses, and each is a case it cannot see the end of:** an
	unknown frame; a copy taken where `rsp` has moved by an unknown amount;
	an indexed access or an indexed `lea` through a copy; arithmetic on a
	copy that is not an immediate; a narrow write, which mangles a pointer
	without destroying it; and a copy stored to memory or pushed, where it
	leaves this function's text entirely. A 32-bit write is a kill rather
	than a derivation, since it zeroes the upper half and what is left
	cannot address a stack.

	The escape case is refused although no borrow window can contain a call
	-- the swallowed bracket admits nothing between its save and restore,
	and `ymm_run` breaks on every control transfer -- so nothing could
	dereference an escaped pointer while the borrow is live. That argument
	is sound and is deliberately not leaned on: it is second-order, resting
	on a property asserted in two docstrings rather than enforced by a
	check, and it is worth 113 sites.
	"""
	if region is None:
		if frame is None:
			return True
		region = (-frame, -frame + HOME_SPACE)
	low, high = region
	# `taint` is a pointer whose offset from the entry `rsp` is known.
	# **`unlocated` is one that is still stack-derived and no longer
	# placed** -- arithmetic that could not be followed, a conditional
	# move, anything that reads a tracked register and writes another by a
	# route this cannot model. Losing the offset used to refuse the
	# function; it refuses a DEREFERENCE now, wherever the pointer points,
	# and nothing at all if the pointer is overwritten first. Finding 136.
	taint, unlocated, depth = {}, set(), 0
	for address, mnemonic, operands in rows:
		operands = operands or ""
		fields = inplace.split_operands(operands) if operands else []
		if mnemonic in ("push", "pushq"):
			if canonical(operands) in taint \
					or canonical(operands) in unlocated:
				return True		# the copy leaves this text
			depth = None if depth is None else depth - 8
		elif mnemonic in ("pop", "popq"):
			depth = None if depth is None else depth + 8
		elif RSP_WRITTEN.search(operands) and not RSP_COPY.match(operands):
			step = immediate_step(mnemonic, operands, "%rsp")
			depth = None if step is None or depth is None else depth + step
		# Any dereference through a copy, including the address a `lea`
		# forms: taking the address of the region is refused exactly as a
		# write to it is.
		for match in MEMORY_BASE.finditer(operands):
			if match.group(2) in unlocated:
				# Nothing can be said about where this lands, which is the
				# same answer as landing inside.
				if hazards is None:
					return True
				hazards.append(address)
			elif match.group(2) in taint:
				text = match.group(1)
				landing = taint[match.group(2)] + \
					(int(text, 16) if text else 0)
				if low <= landing < high:
					if hazards is None:
						return True
					hazards.append(address)
		match = INDEXED_BASE.search(operands)
		if match and (match.group(1) in taint
		              or match.group(1) in unlocated):
			if hazards is None:
				return True
			hazards.append(address)
		if RSP_COPY.match(operands):
			if depth is None:
				return True
			taint[RSP_COPY.match(operands).group(1)] = depth
			unlocated.discard(RSP_COPY.match(operands).group(1))
			continue
		if mnemonic == "lea" and len(fields) == 2 \
				and fields[1].startswith("%"):
			match = MEMORY_BASE.fullmatch(fields[0])
			if match and match.group(2) in unlocated:
				taint.pop(canonical(fields[1]), None)
				unlocated.add(canonical(fields[1]))
				continue
			if match and match.group(2) in taint:
				text = match.group(1)
				taint[canonical(fields[1])] = taint[match.group(2)] + \
					(int(text, 16) if text else 0)
				unlocated.discard(canonical(fields[1]))
				continue
		if len(fields) == 2 and fields[0].startswith("%") \
				and canonical(fields[0]) in unlocated and "(" in fields[1]:
			# An unlocated pointer leaving the text cannot be checked
			# against the region, because there is nothing to check.
			return True
		if len(fields) == 2 and fields[0].startswith("%") \
				and canonical(fields[0]) in taint and "(" in fields[1]:
			# **The copy is stored to memory, and what it is worth
			# depends on where it points.**
			#
			# Finding 127 allowed this outright, on the argument that an
			# escaped pointer cannot be dereferenced WHILE the borrow is
			# live, because nothing runs between the save and the restore.
			# That much is true and is enforced rather than asserted. The
			# sentence it rested on is not: "after the restore the region
			# holds what it held before". It does not. The restore reads
			# the region INTO the register, so the region keeps the
			# borrowed value and the damage outlives the bracket the
			# argument was about. Finding 132.
			#
			# What is true, and is checked here rather than measured once:
			# **the pointer that leaves does not point into the region.**
			# Measured over a whole collect, 4,950 escapes and not one of
			# them did -- the nearest were 31 pointing below it and 513
			# within 64 bytes above -- so this costs nothing today and
			# stops the case that would matter.
			#
			# **What it does not cover is a consumer that adds a
			# displacement**, and that is named rather than hidden. The two
			# ways a pointer INTO the region is formed are both refused
			# already: a `lea` into it refuses the whole function, which is
			# what covers the varargs idiom -- `va_list` points at exactly
			# this memory -- and arithmetic walking a copy into it is
			# refused by this walk. `--escape=refuse` declines the case
			# entirely and costs 455 sites, measured on the binary.
			#
			# The WRITE is still checked either way. Where the pointer is
			# stored is a dereference like any other and the loop above
			# refuses it if it lands in the region.
			if ESCAPE_RULE == ESCAPE_REFUSE \
					or low <= taint[canonical(fields[0])] < high:
				return True
			continue
		# **A tainted value moving into another register moves with it,
		# and this walk did not follow it.** `mov %rsp,%rax` then
		# `mov %rax,%rbx` left `%rbx` untracked, so a write through `%rbx`
		# into the region was invisible and the function was lent -- and
		# `add %rax,%rbx` was worse, since it makes `%rbx` a stack pointer
		# at an offset nothing here can name. Both were allowed. The
		# tracking only ever followed a pointer's ARITHMETIC, never its
		# migration. Finding 135.
		#
		# A plain 64-bit `mov` carries the offset exactly and is followed.
		# Anything else that reads a tainted register and writes a
		# different one is refused, because the result is stack-derived and
		# unlocated -- which is the same answer this already gives to
		# arithmetic it cannot follow.
		#
		# A NARROW destination is neither: a 32-bit write zeroes the upper
		# half, so what lands there cannot address a stack at all. That is
		# the existing kill rule, read from the other side.
		if len(fields) >= 2 and fields[-1].startswith("%") \
				and mnemonic not in FLAGS_ONLY:
			destination = fields[-1].lstrip("%")
			wide = canonical(destination)
			carried = [canonical(f) for f in fields[:-1]
			           if f.startswith("%")
			           and (canonical(f) in taint or canonical(f) in unlocated)]
			if carried and wide not in carried:
				if destination in WIDE32 \
						or NUMBERED_NARROW.match(destination):
					pass
				elif len(fields) == 2 and len(carried) == 1 \
						and carried[0] in taint \
						and mnemonic in ("mov", "movq"):
					taint[wide] = taint[carried[0]]
					unlocated.discard(wide)
					continue
				else:
					# Stack-derived and unplaced. Refusing here is what
					# Finding 135 did; a dereference through it refuses
					# now, and an overwrite ends it. Finding 136.
					taint.pop(wide, None)
					unlocated.add(wide)
					continue
		if fields and fields[-1].startswith("%") \
				and mnemonic not in FLAGS_ONLY:
			name = fields[-1].lstrip("%")
			wide = canonical(name)
			overwritten = (mnemonic.startswith("mov")
			               or mnemonic in ("pop", "popq")
			               or mnemonic in OVERWRITES
			               or name in WIDE32 or NUMBERED_NARROW.match(name))
			if wide in unlocated:
				# Whatever writes it either destroys the pointer or leaves
				# it exactly as unplaceable, and only the first matters.
				if overwritten:
					unlocated.discard(wide)
			elif wide not in taint:
				taint.pop(wide, None)
			elif overwritten:
				del taint[wide]		# overwritten, or zero-extended away
			else:
				step = immediate_step(mnemonic, operands, fields[-1])
				if step is None:
					del taint[wide]
					unlocated.add(wide)
				else:
					taint[wide] += step
		if mnemonic in IMPLICIT_RAX:
			taint.pop("rax", None)
			taint.pop("rdx", None)
	return False


def saved_xmm_map(binary):
	"""`{function start: frozenset of non-volatile xmm it saves}`.

	**This is what makes a non-volatile borrow safe rather than lucky.**
	Finding 124 restricted borrowing to xmm0-xmm5 because the only way out
	of a live borrow bracket is a FAULT, and there the unwinder restores
	xmm6-xmm15 from the primary's `UWOP_SAVE_XMM128` codes -- which a
	function that never used the register does not have, so the caller's
	value, sitting in a home-space slot at that moment, is lost.

	A function that DOES save the register has the opposite property: the
	unwinder restores the caller's value from the function's own slot,
	whatever a borrow left in the register or in the home space. So the
	borrow is safe exactly where this map says the function saves it, and
	the restriction becomes a condition rather than a blanket. Finding 255.

	Read straight from `.pdata` and the `UNWIND_INFO` it points at, because
	that is the same data the unwinder itself will read. `UWOP_SAVE_XMM128`
	is opcode 8 with a two-slot node; the `_FAR` form is 9 with three. The
	register is the info field.
	"""
	with open(binary, "rb") as image:
		data = image.read()
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	opt = pe + 24
	magic = struct.unpack_from("<H", data, opt)[0]
	dirs = opt + (112 if magic == 0x20B else 96)
	at_rva, size = struct.unpack_from("<II", data, dirs + 3 * 8)
	base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B \
		else struct.unpack_from("<I", data, opt + 28)[0]
	sections = struct.unpack_from("<H", data, pe + 6)[0]
	table = opt + struct.unpack_from("<H", data, pe + 20)[0]

	def offset_of(rva):
		for i in range(sections):
			entry = table + i * 40
			va, virtual = struct.unpack_from("<II", data, entry + 12)
			raw, pointer = struct.unpack_from("<II", data, entry + 16)
			if va <= rva < va + max(virtual, raw):
				return pointer + (rva - va)
		return None

	at = offset_of(at_rva)
	out = {}
	if at is None:
		return out
	for i in range(size // 12):
		begin, end, unwind = struct.unpack_from("<III", data, at + i * 12)
		if end <= begin:
			continue
		off = offset_of(unwind)
		if off is None or off + 4 > len(data):
			continue
		count = data[off + 2]
		codes, j, found = off + 4, 0, {}
		while j < count and codes + j * 2 + 1 < len(data):
			packed = data[codes + j * 2 + 1]
			op, info = packed & 0xF, packed >> 4
			if op == 8:				# UWOP_SAVE_XMM128
				where = struct.unpack_from(
					"<H", data, codes + (j + 1) * 2)[0] * 16
				found[info] = where
				j += 2
			elif op == 9:				# UWOP_SAVE_XMM128_FAR
				where = struct.unpack_from(
					"<I", data, codes + (j + 1) * 2)[0]
				found[info] = where
				j += 3
			elif op == 1:				# UWOP_ALLOC_LARGE
				j += 2 if info else 3
			elif op in (4, 6, 10):			# SAVE_NONVOL, EPILOG, ...
				j += 2
			elif op == 5:				# SAVE_NONVOL_FAR
				j += 3
			else:
				j += 1
		if found:
			# **The OFFSET is kept, not just the register.** A borrow that
			# wrote over the function's own save slot would corrupt the
			# very bytes the unwinder restores from -- the guarantee this
			# whole condition rests on, destroyed by the thing relying on
			# it. `unit_candidate` checks the home-space slot against
			# these. Finding 256.
			out[base + begin] = {r: w for r, w in found.items() if r >= 6}
	return {a: r for a, r in out.items() if r}


def home_space_map(binary, plain, ranges, blocked):
	"""Which functions can lend their callee home space to a stub.

	Three conditions, and each is read off the binary rather than assumed:

	  * the function **contains a call**, so the 32 bytes exist at all;
	  * it **never addresses `[rsp+0..31]` itself**, so no local of its own
	    lives there -- true of all but 295 of the starved sites, the region
	    really is dead;
	  * its unwind info sets **no frame register**, which is what says `rsp`
	    is constant through the body. A function with a dynamic allocation
	    uses a frame pointer and is marked `UWOP_SET_FPREG`; there are 127
	    such functions in the whole binary.

	An exception does not disturb it: the kernel pushes its context record
	BELOW `rsp`, and `[rsp+0..31]` is at and above it.
	"""
	data = open(binary, "rb").read()
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
	rva, size = struct.unpack_from("<II", data, pe + 24 + 112 + 3 * 8)
	at = rva_to_offset(data, rva) if rva and size else None
	fixed_frame = set()
	unwind_at, prologue_end = {}, {}
	if at is not None:
		for i in range(size // 12):
			begin, end, unwind = struct.unpack_from("<III", data, at + i * 12)
			if end <= begin:
				continue
			off = rva_to_offset(data, unwind)
			if off is None or off + 4 > len(data):
				continue
			unwind_at[base + begin] = (off, base)
			prologue_end[base + begin] = base + begin + data[off + 1]
			if not data[off + 3] & 0xF:		# no frame register
				fixed_frame.add(base + begin)

	starts = [start for start, _end in ranges]
	calls = [False] * len(ranges)
	# **Which addresses reference the region, not merely whether one does.**
	# A direct operand used to refuse the whole function; it names a
	# position now, and `borrow_offset` asks whether that position is still
	# reachable from the site. See `readers_reachable` and Finding 131.
	direct = {}
	# A `lea` stays a whole-function refusal, and the difference is the
	# point. A direct operand is a read or a write AT a place; a `lea` forms
	# a POINTER, which can be stored, passed, and dereferenced somewhere no
	# reachability over this function's own instructions can see.
	pointed = set()
	copies = set()
	for address, _encoding, mnemonic, operands in plain:
		i = bisect.bisect_right(starts, address) - 1
		if i < 0 or address >= ranges[i][1]:
			continue
		if mnemonic in ("call", "callq"):
			calls[i] = True
		for match in RSP_MEMORY.finditer(operands):
			text = match.group(1)
			if 0 <= (int(text, 16) if text else 0) < HOME_SPACE:
				if mnemonic == "lea":
					pointed.add(i)
				else:
					direct.setdefault(i, []).append(address)
		# **A copy of `rsp` is noted, and where it points decides.** The
		# blanket refusal this replaces was measured to protect no function
		# in the binary -- see Finding 96 and `copy_reaches_home` -- and
		# `--rsp=blanket` restores it for comparison. It is followed
		# lazily: only a function holding a starved site is ever asked.
		if RSP_COPY.match(operands):
			copies.add(i)

	# Both regions are worked out per function, on demand, because only the
	# few hundred functions holding a starved site are ever asked and each
	# walk wants that function's whole instruction list. `plain` is in
	# address order, so a function's rows are found by bisection.
	state = {"plain": plain, "unwind": unwind_at, "prologue": prologue_end,
	         "data": data, "cache": {}, "home_cache": {},
	         "direct": direct, "copies": copies, "blocked": blocked,
	         "gpr_cache": {}}
	return (starts, ranges,
	        [calls[i] and i not in pointed and ranges[i][0] in fixed_frame
	         for i in range(len(ranges))],
	        state)


def function_rows(state, ranges, i, with_address=True):
	"""One function's instructions, by bisection into `plain`."""
	start, end = ranges[i]
	plain, rows = state["plain"], []
	for position in range(bisect.bisect_left(plain, (start,)), len(plain)):
		address, _encoding, mnemonic, operands = plain[position]
		if address >= end:
			break
		rows.append((address, mnemonic, operands or "") if with_address
		            else (mnemonic, operands or ""))
	return rows


def region_readers(state, ranges, i, refs):
	"""Addresses from which one of `refs` can still be reached, memoised
	per function. An empty `refs` gives an empty answer.
	"""
	if not refs:
		return frozenset()
	plain = state["plain"]
	start, end = ranges[i]
	first = bisect.bisect_left(plain, (start,))
	last = bisect.bisect_left(plain, (end,), first)
	blocked = state["blocked"]
	inside = tuple(position for position in range(first, last)
	               if plain[position][0] in blocked)
	wanted = {bisect.bisect_left(plain, (address,), first, last)
	          for address in refs}
	reaching = readers_reachable(plain, first, last, wanted, inside)
	return frozenset(plain[position][0] for position in reaching)


def home_readers(home, i):
	"""Where the callee home space is still live in function `i`, or None
	if the function cannot lend it at all.

	The `rsp` copy is followed here rather than in `home_space_map` so that
	only a function actually asked about pays for it -- and so that a
	direct reference no longer excuses the walk, now that a direct
	reference is not a refusal by itself.

	Two kinds of reader end up in the same set: an operand that names the
	region, and a dereference through a copy of `rsp` that lands in it.
	Both happen at an address, so both are answered by reachability rather
	than by refusing the function. See `copy_reaches_home`'s `hazards`.
	"""
	_starts, ranges, _usable, state = home
	if i in state["home_cache"]:
		return state["home_cache"][i]
	copied = []
	if i in state["copies"]:
		if RSP_RULE == RSP_BLANKET:
			return state["home_cache"].setdefault(i, None)
		hazards = [] if REGION_RULE == REGION_LIVE else None
		if copy_reaches_home(function_rows(state, ranges, i),
		                     prologue_frame(state["data"], state["unwind"],
		                                    ranges[i][0]),
		                     hazards=hazards):
			return state["home_cache"].setdefault(i, None)
		# A dereference through a tracked copy is a reader at a place, like
		# a direct operand, and is asked the same question. Finding 134.
		copied = hazards or []
	refs = list(state["direct"].get(i, ())) + copied
	if refs and REGION_RULE == REGION_WHOLE:
		return state["home_cache"].setdefault(i, None)
	return state["home_cache"].setdefault(
		i, region_readers(state, ranges, i, refs))


def region_references(rows, depths, region):
	"""`(addresses referencing `region`, whether a pointer was formed)`.

	`region` is entry-relative and `depths` says where `rsp` stands at each
	address, so an operand `k(%rsp)` at depth `d` lands at **`d + k`** --
	the same arithmetic `copy_reaches_home` calls `landing`, and the one
	`borrow_offset` inverts to place a save.

	**Subtracting instead is right at depth zero and wrong below it.** That
	is where MSVC's prologue spills its register parameters, so the common
	case agreed, every fixture passed, and the check read the wrong 32
	bytes for a day -- missing exactly the functions that write their
	shadow through a settled `rsp`. `REFERENCE_CASES` is what tests it now.

	An unknown depth counts as a reference: it is the one case where
	nothing can be said about where the operand lands, which is the same
	answer as landing inside.

	A `lea` is reported separately because it forms a POINTER, which can be
	stored and dereferenced where no reachability over this function's own
	instructions could see it. That stays a whole-function refusal while a
	direct reference does not. Finding 131.
	"""
	low, high = region
	refs, pointed = [], False
	for address, mnemonic, operands in rows:
		here = depths.get(address)
		for match in RSP_MEMORY.finditer(operands or ""):
			text = match.group(1)
			landing = None if here is None \
				else here + (int(text, 16) if text else 0)
			if landing is None or low <= landing < high:
				if mnemonic == "lea":
					pointed = True
				else:
					refs.append(address)
	return refs, pointed


def shadow_depths(home, i):
	"""`({address: depth}, addresses where the shadow is still read)` for
	function `i`, or None if it can lend nothing. Memoised; see
	`rsp_depths`, `CALLER_SHADOW` and `region_readers`.

	Three questions, and the first two are the ones `home_space_map` also
	asks of the other region -- does the function reference it, and can a
	copy of `rsp` reach it. The third is what the shadow costs: `rsp` must
	have a known value at the site, since the shadow is addressed across a
	whole frame rather than from its bottom.

	A direct reference no longer refuses the function, only the positions
	from which it is still reachable. A `lea` still refuses outright,
	because a pointer leaves what this can see. Finding 131.
	"""
	_starts, ranges, _usable, state = home
	if i in state["cache"]:
		return state["cache"][i]
	start, end = ranges[i]
	plain, data = state["plain"], state["data"]
	# **Only a function `.pdata` describes may lend its shadow**, which is
	# the same restriction the callee home space has always had -- that one
	# tests `ranges[i][0] in fixed_frame`, and `fixed_frame` is built from
	# `.pdata` alone.
	#
	# The reason is that "entry `rsp`" has to mean something. A range
	# `outside.py` recovered is admitted on being bracketed by `int3` and
	# **entered by a call OR A JUMP**, and a range entered by a jump is not
	# a function entry at all: `rsp` there stands wherever the jumping code
	# left it, so the shadow is not 8 bytes above the walk's zero and the
	# save lands in somebody's live locals. `.pdata` is the binary's own
	# statement that a range is a function, and it is the only one worth
	# having here.
	#
	# It costs 3 of the 2,153 starved sites, measured. `rsp_depths` can
	# still model a frameless leaf and is tested doing so; what it cannot do
	# is tell a leaf from the tail of somebody else's function.
	if start not in state["unwind"]:
		return state["cache"].setdefault(i, None)
	frame = prologue_frame(data, state["unwind"], start)
	if frame is None:
		return state["cache"].setdefault(i, None)	# a frame register
	rows = function_rows(state, ranges, i)
	seen, _body = rsp_depths(rows, frame, state["prologue"].get(start))
	if seen is None:
		return state["cache"].setdefault(i, None)
	refs, pointed = region_references(rows, seen, CALLER_SHADOW)
	if pointed:
		return state["cache"].setdefault(i, None)
	hazards = [] if REGION_RULE == REGION_LIVE else None
	if any(RSP_COPY.match(operands) for _a, _m, operands in rows) \
			and copy_reaches_home(rows, None, CALLER_SHADOW,
			                      hazards=hazards):
		return state["cache"].setdefault(i, None)
	# A hazard through a copy is a reader like a direct operand is, and is
	# asked the same question. Finding 134.
	refs = list(refs) + list(hazards or [])
	if refs and REGION_RULE == REGION_WHOLE:
		return state["cache"].setdefault(i, None)
	return state["cache"].setdefault(
		i, (seen, region_readers(state, ranges, i, refs)))


def borrow_offset(home, address):
	"""Where a borrow at `address` writes, as a displacement from `rsp`, or
	None if this function will lend nothing.

	Zero is the callee home space at `(%rsp)`, which is what every borrow
	used before the shadow existed and is returned unchanged. Anything else
	is the caller's shadow, a whole frame higher up.
	"""
	if home is None:
		return None
	starts, ranges, _usable, _state = home
	i = bisect.bisect_right(starts, address) - 1
	if i < 0 or address >= ranges[i][1]:
		return None
	if home_space_free(home, address):
		readers = home_readers(home, i)
		if readers is not None and address not in readers:
			return 0
	if SHADOW_RULE == SHADOW_OFF:
		return None
	found = shadow_depths(home, i)
	if found is None:
		return None
	seen, readers = found
	if address in readers:
		return None		# the shadow is still read from here
	depth = seen.get(address)
	return None if depth is None else CALLER_SHADOW[0] - depth


def gpr_free_at(home, address):
	"""The volatile GPRs dead across a borrow at `address`, as numbers.

	`borrow_offset`'s counterpart for `--spill=tls`, and the same shape: a
	question about a place, memoised per function because the walk wants
	the whole function and only a few hundred are ever asked.

	The site's own operands are excluded. A lowering reaching memory
	through `(%rax,%rcx,4)` needs both registers while the stub runs, and
	the liveness answer is about what happens AFTER the instruction.
	"""
	if home is None:
		return frozenset()
	_starts, ranges, _usable, state = home
	starts = _starts
	i = bisect.bisect_right(starts, address) - 1
	if i < 0 or address >= ranges[i][1]:
		return frozenset()
	plain = state["plain"]
	if i not in state["gpr_cache"]:
		start, end = ranges[i]
		first = bisect.bisect_left(plain, (start,))
		last = bisect.bisect_left(plain, (end,), first)
		blocked = state["blocked"]
		inside = tuple(position for position in range(first, last)
		               if plain[position][0] in blocked)
		state["gpr_cache"][i] = (first, last,
		                         gpr_live_out(plain, first, last, inside))
	first, last, live = state["gpr_cache"][i]
	at = bisect.bisect_left(plain, (address,), first, last)
	if at >= last or plain[at][0] != address:
		return frozenset()
	free = frozenset(VOLATILE_GPRS) - live[at] \
		- gprs_named(plain[at][3] or "")
	return frozenset(GPR_NUMBERS[name] for name in free)


def window_gpr_free(home, start, window):
	"""`gpr_free_at` for every instruction a window covers.

	A stub writes its addressing sequence once and the borrowed register
	stays clobbered until the restore, so a register has to be dead at
	EVERY instruction in the window and named by none of them -- the same
	argument `window_borrow` makes about a displacement, for the same
	reason. A widened window that took this from the site alone would
	clobber a register the swallowed neighbour still wanted.
	"""
	if home is None:
		return frozenset()
	_starts, _ranges, _usable, state = home
	plain = state["plain"]
	free = None
	at = bisect.bisect_left(plain, (start,))
	while at < len(plain) and plain[at][0] < start + window:
		here = gpr_free_at(home, plain[at][0]) \
			- frozenset(GPR_NUMBERS[name]
			            for name in gprs_named(plain[at][3] or ""))
		free = here if free is None else (free & here)
		if not free:
			return frozenset()
		at += 1
	return free if free is not None else frozenset()


def window_borrow(home, start, window):
	"""`borrow_offset` for a whole window, or None if it is not one number.

	A stub's save and its restore are written once, so the displacement has
	to be right for every instruction the window covers. The callee home
	space is at `(%rsp)` throughout by construction -- the function it
	belongs to does not move `rsp` at all -- while the shadow's displacement
	moves with `rsp`, so a window holding a `push` would restore from
	somewhere the save never wrote. Finding 130.
	"""
	offset = borrow_offset(home, start)
	if offset in (None, 0):
		return offset
	starts, ranges, _usable, state = home
	i = bisect.bisect_right(starts, start) - 1
	seen = shadow_depths(home, i)[0]
	plain = state["plain"]
	here = seen.get(start)
	for position in range(bisect.bisect_left(plain, (start,)), len(plain)):
		address = plain[position][0]
		if address >= start + window:
			break
		if seen.get(address) != here:
			return None
	return offset


def home_space_free(home, address):
	"""True if the function containing `address` can lend its home space."""
	if home is None:
		return False
	starts, ranges, usable = home[0], home[1], home[2]
	i = bisect.bisect_right(starts, address) - 1
	if i < 0 or address >= ranges[i][1]:
		return False
	return usable[i]


def swallowed_borrow(plain, address, encoding, operands, mnemonic, home):
	"""A register a swallowed instruction may borrow, or None.

	`swallowed_scratch` returns None when nothing is dead at the neighbour's
	position, and `lower_vex` then refuses an aliased `dst == src2` form
	because the `movaps` setting up the destination would destroy `src2`
	first. 795 sites are refused that way -- the largest part of what is
	left in the refused bucket. Finding 91.

	The site already has an answer for exactly this: borrow a live register
	and give it back through the callee home space, which is dead by the ABI.
	This offers the same to a neighbour.

	**The bracket is tight, which is what makes the window's length
	irrelevant.** `encode_spill` writes the save immediately before this one
	instruction's lowering and the restore immediately after, so nothing --
	no call, no push, no adjustment of `rsp` -- can come between them. Finding
	92 asked whether the borrow survives a window and measured that it would
	for all 795, their windows being eight to ten bytes; the answer that
	matters is that it never spans one. A borrow written to span a window
	would be correct today and wrong the first time a `zero_run` or a
	swallowed `call` widened one, with nothing to say so.

	The site's own spill block and this one cannot overlap either: `preceding`
	is emitted before it and `displaced` after.
	"""
	if SPILL not in HOME_SPILLS or borrow_offset(home, address) is None:
		return None
	fields = inplace.split_operands(operands)
	registers = [o for o in fields if not o.startswith("$")]
	return borrow_that_lowers(address, encoding, operands, mnemonic, address,
	                          address)


def swallowed_scratch(plain, position, address, encoding, operands, mnemonic,
                      scope):
	"""A scratch for an instruction a window is about to swallow, or None.

	The trial lowering comes first and the liveness scan only if it fails, so
	the cost lands on the ~2,400 neighbours that need one rather than on
	every neighbour a window ever takes. `find_scratch` is a path-enumerating
	scan and is far and away the expensive half.
	"""
	if encoding[:1] not in (b"\xc4", b"\xc5"):
		return None
	if lower_vex(address, encoding, operands, mnemonic, address) is not None:
		return None			# lowers without one
	return scratch_finder.find_scratch(plain, position, scope=scope)


# A relative branch cannot be MOVED, only re-aimed. `jmp rel8` reaches 128
# bytes and a stub is twelve kilobytes away, so the displacement is not
# adjustable -- the instruction has to be re-emitted in a wider form pointing
# at the same absolute address. A stub is freely sized, so growing two bytes
# into five costs nothing there.
#
# Conditional forms are deliberately absent. There are three such sites in the
# binary, each needing its own opcode from a sixteen-entry table, and a table
# written for three sites is a table nobody checks. They stay refused.
BRANCH_REEMIT = {"jmp": b"\xe9", "jmpq": b"\xe9", "call": b"\xe8",
                 "callq": b"\xe8"}

# The conditional forms, `0f 80+cc rel32`. Finding 86 left these out on the
# grounds that a sixteen-entry table written for three sites is one nobody
# checks -- true of the three sites FORWARD of a window. Backwards there are
# 194, across six conditions, and the table earns its place.
#
# **`jrcxz`, `loop`, `loope` and `loopne` are deliberately absent.** They exist
# only in a rel8 form, so there is nothing to widen them into, and a lookup
# that missed that would emit a jump to somewhere arbitrary. Anything not in
# this table is refused.
CONDITION_CODES = {
	"jo": 0x0, "jno": 0x1, "jb": 0x2, "jnae": 0x2, "jc": 0x2,
	"jae": 0x3, "jnb": 0x3, "jnc": 0x3, "je": 0x4, "jz": 0x4,
	"jne": 0x5, "jnz": 0x5, "jbe": 0x6, "jna": 0x6, "ja": 0x7, "jnbe": 0x7,
	"js": 0x8, "jns": 0x9, "jp": 0xA, "jpe": 0xA, "jnp": 0xB, "jpo": 0xB,
	"jl": 0xC, "jnge": 0xC, "jge": 0xD, "jnl": 0xD,
	"jle": 0xE, "jng": 0xE, "jg": 0xF, "jnle": 0xF,
}


def swallowable_transfer(encoding, mnemonic, operands, comment, address):
	"""True if a window may widen over this control transfer.

	**A stub containing an unconditional transfer simply does not come back**,
	and its trailing jump home becomes dead code -- which is correct rather
	than merely harmless. A `call` is fine too: it returns into the stub and
	falls into that jump. What is refused is a CONDITIONAL branch, where the
	fall-through edge would have to become the jump home and both edges be
	right at once, and where there are three sites in the whole binary.

	Measured over the 427 sites this refusal was costing: 367 `jmp rel8`, 22
	`jmp rel32`, 20 `call rel32`, 13 `ret`, 2 indirect calls and 3 conditional.
	Every one of them would give a window of at least the five bytes a detour
	needs. Finding 86.

	The test is `moved_branch` itself where it applies, so the collector can
	only accept what the encoder can actually emit -- the alternative is a
	candidate that fails in `build_stub` with no reason recorded, which is the
	shape Finding 45 had to diagnose by hand.
	"""
	# **A conditional is swallowable in both directions**, which Finding 86
	# did not use and Finding 87 does. Forward: the stub holds the lowered
	# site, then the re-emitted branch, then the jump home -- taken goes to
	# the original target, not taken falls into the jump home, which is where
	# the fall-through went anyway. Backward: the stub holds the re-emitted
	# branch, then the lowered site, then the jump home -- and a conditional
	# is the one transfer that DOES fall through into the site, which is what
	# the backward path's refusal was really about.
	#
	# **Ask the encoder that will actually be used**, rather than a
	# reimplementation of its rules. The first version tested `moved_branch`
	# directly and answered yes for an indirect branch through memory, which
	# `moved_instruction` routes to `relocate` instead -- and `relocate`
	# refuses it. A collector that accepts what the encoder rejects produces a
	# candidate that dies in `build_stub` with no reason recorded, which is
	# the failure Finding 45 had to diagnose by hand.
	#
	# **Probe from the branch's own address, not from zero.** The stub's
	# address is unknown here and only affects whether a rel32 reaches; from
	# zero every target in this image overflows, and the first version of this
	# answered "not swallowable" for all 402 sites it was written to take.
	# Reaching is not in doubt for the real `at`: the stub section sits a few
	# megabytes past a 58 MB `.text`, well inside rel32's range.
	return moved_instruction((address, encoding, comment, operands, mnemonic),
	                         address) is not None


def moved_branch(moved, mnemonic, operands, comment, address, at):
	"""A swallowed branch, re-emitted at `at` aimed where it always went.

	`ret` carries no displacement and copies across untouched. An indirect
	branch through memory is a RIP-relative operand, which `relocate` already
	handles, so it is not this function's business. What is left is the
	relative forms, and for them the absolute target is what objdump has
	already resolved: the operand text for a direct branch is the target.

	Returns None for anything it cannot encode, which is the answer that
	keeps the caller refusing rather than guessing.
	"""
	if mnemonic.startswith("ret"):
		return bytes(moved)
	opcode = BRANCH_REEMIT.get(mnemonic)
	if opcode is None:
		code = CONDITION_CODES.get(mnemonic)
		if code is None:
			return None		# jrcxz, loop and friends have no rel32 form
		opcode = bytes((0x0F, 0x80 + code))
	target = None
	first = operands.split()[0] if operands else ""
	if first.startswith("0x"):
		try:
			target = int(first, 16)
		except ValueError:
			target = None
	elif comment is not None and "*" in operands:
		return None		# indirect: relocate's business, not this one
	if target is None:
		return None
	# rel32 is measured from the END of the instruction, which is five bytes
	# for `e9`/`e8` and SIX for the two-byte conditional opcode. Getting that
	# wrong lands every conditional one byte short of its target.
	delta = target - (at + len(opcode) + 4)
	if not -0x80000000 <= delta <= 0x7FFFFFFF:
		return None
	return opcode + struct.pack("<i", delta)


def moved_instruction(entry, at, pool=0, reasons=None):
	"""One swallowed instruction, re-encoded to execute at `at`.

	The sixth field is a scratch register for the swallowed instruction, and
	it is there because leaving it out refused 2,437 stubs. **A swallowed
	instruction is a lowering like any other and can need a scratch of its
	own** -- a `vblendvps`, an FMA, a Class C whose src2 is its destination
	-- and this asked for none, so the whole window was refused whenever the
	neighbour it swallowed happened to be one of those. The refusal was
	invisible: `build_stub` returns None with no reason, so no counter ever
	named it, and it took walking the three steps by hand to see which one
	failed.

	Its scratch is dead at ITS position rather than at the site's, which is
	the right question and is also what makes two lowerings in one stub safe.
	The site's scratch is dead at the site, so nothing after it -- including
	this instruction -- reads it; this one's is dead here, so nothing after
	reads it either.
	"""
	address, moved, comment, moved_operands, moved_mnemonic = entry[:5]
	scratch = entry[5] if len(entry) > 5 else None
	# **EVEX is recognised and left alone, and a window that swallows one
	# has not left it alone.** `isa_guard` requires every EVEX instruction
	# in `.text` to be byte-identical: 179 of them are unreachable on a
	# pre-AVX host only because a runtime CPUID test says so, and the
	# rewriter's job at 512 bits is to recognise them and stop. A window
	# widened over one copies it into the stub verbatim and writes a jump
	# and padding over the original, which is not leaving it alone however
	# faithful the copy.
	#
	# Nothing refused it before because no window had ever reached one.
	# Finding 271's immediate form moved the placement enough that a
	# four-byte `vpaddd` at 0x1434d8eaf widened forward over the six-byte
	# `vpdpbusd` at 0x1434d8eb3, and `isa_guard` caught it -- which is the
	# gate doing exactly what it was written for. Refusing here costs the
	# window and keeps the bytes. Finding 272.
	if moved and moved[0] == 0x62:
		if reasons is not None:
			reasons["a swallowed instruction is EVEX"] += 1
		return None
	if moved and moved[0] in (0xC4, 0xC5):
		# The swallowed instruction is VEX as well. Lower it here rather
		# than carry it across.
		#
		# Its own refusals are collected separately and re-labelled, so that
		# "the neighbour would not lower, because it is 256-bit" does not
		# arrive in the same bucket as the site saying the same thing.
		# Finding 91.
		inner = Counter() if reasons is not None else None
		out = lower_vex(address, moved, moved_operands, moved_mnemonic, at,
		                scratch, pool, inner)
		if out is None and reasons is not None:
			# **Only the GENERIC refusal is re-worded.** The first
			# version tested the width alone and ran before the re-label,
			# so it swallowed `the FMA would not lower` and `no direct SSE
			# form and not a sequence` as well -- three of the 39 traded a
			# reason that names the family for one that names only the
			# width. That is the same loss of precision this item reverted
			# a whole change over, reintroduced by the fix for it, and the
			# roll is what showed it: 36 + 2 + 1 became 39.
			generic = "lower: 256-bit, no Y strategy took it"
			told = 0
			if inner and generic in inner:
				# **Name the condition, not the symptom.** Re-labelling
				# `lower_vex`'s own words gave `moved: 256-bit, no Y
				# strategy took it`, which says a Y strategy declined the
				# window -- and the window's strategy is `unit`, which is a
				# Y strategy and took it. What actually happened is that a
				# SWALLOWED neighbour is 256-bit, and `lower_vex` is the
				# only thing offered one: the span emission lowers 256-bit
				# and a carried instruction never reaches it, because it
				# rides in `preceding` rather than as a member.
				#
				# All 39 of Starfield's refused stubs are this, and the
				# borrowed wording cost two wrong narrowings -- first that a
				# member had no span shape (33 of 36 windows have one for
				# every member), then that the window was built as `plain`
				# (all 39 are `unit`). A reason that describes the caller's
				# situation rather than the callee's is worth more than one
				# that is merely true. Finding 315.
				count = inner.pop(generic)
				reasons["moved: the swallowed neighbour is 256-bit, and "
				        "only the span emission lowers one"] += count
				told += 1
			# **A tally, not an `else`.** Popping the generic reason can
			# leave `inner` empty, and an `else` on it then fired a second,
			# spurious `the VEX neighbour would not lower` for the very
			# refusals just recorded -- 39 reasons over 39 stubs would have
			# become 78. The fallback exists for a `lower_vex` that refused
			# and said nothing, which is a third case and wants counting
			# rather than inferring from emptiness.
			for why, count in list(inner.items()) if inner else ():
				reasons["moved: " + why.replace("lower: ", "")] += count
				told += 1
			if not told:
				reasons["moved: the VEX neighbour would not lower"] += 1
		return out
	# A relative branch is re-aimed rather than relocated: its displacement
	# is measured from itself, not from RIP as an operand, so `relocate`
	# would copy it verbatim and send it 12 KB wrong. See `moved_branch`.
	if moved_mnemonic.startswith(CONTROL_PREFIXES) \
			and "(%rip)" not in moved_operands:
		out = moved_branch(moved, moved_mnemonic, moved_operands, comment,
		                   address, at)
		if out is None and reasons is not None:
			reasons["moved: the branch shape cannot be re-aimed"] += 1
		return out
	# objdump comments a resolved target for several shapes, so the comment
	# only means a RIP displacement when the operand says (%rip). Anything
	# else copies across untouched.
	rip = comment if "(%rip)" in moved_operands else None
	out = relocate(moved, address, at, rip)
	if out is None and reasons is not None:
		reasons["moved: the displacement will not relocate"] += 1
	return out


YMM_MOVES = frozenset("vmovups vmovaps vmovdqu vmovdqa vmovupd vmovapd".split())

# **The two instructions that write an upper half without naming a register.**
# `vzeroupper` clears bits [255:128] of every ymm and `vzeroall` clears all of
# them, and neither has an operand -- so any scan that decides what wrote a
# register by reading operand text walks straight past both. There are 19,253
# `vzeroupper` in this `.text` and no `vzeroall`.
#
# `reaching_definition`'s comment named `vzeroall` as the one instruction with
# this property and said there were none, which is true of `vzeroall` and was
# never the point. Finding 111.
UPPER_HALF_KILLERS = frozenset(("vzeroupper", "vzeroall"))


def rip_operand(tail):
	"""True if this memory operand is RIP-relative.

	`mod` 00 with `rm` 101 is RIP+disp32 in 64-bit mode, and there is no SIB
	byte in that form -- which is what makes the displacement findable
	without decoding the rest of the instruction.
	"""
	return len(tail) >= 2 and not ((tail[1] >> 6) & 3) and (tail[1] & 7) == 5


def rip_target(tail, address, length):
	"""The absolute address a RIP-relative operand names, or None.

	Read off the encoding rather than off objdump's comment, so the
	arithmetic has one source rather than two that can disagree. The
	displacement is measured from the END of the instruction, which is the
	whole reason moving one is not the same problem as adjusting a
	displacement in place.
	"""
	# **An immediate after the displacement changes nothing here.** This
	# demanded a tail of exactly six bytes and refused anything longer,
	# which reads as caution and is arithmetic that does not apply: the
	# displacement is measured from the END of the instruction, and
	# `length` is already the whole instruction including its immediate.
	# `rip_operand` has established mod 00 with rm 101, so there is no
	# SIB and the displacement is exactly `tail[2:6]` whatever follows
	# it.
	#
	# What the refusal was actually protecting is the RECONSTRUCTION,
	# which is `narrow_piece`'s and rebuilt the tail as opcode, modrm and
	# a new displacement -- dropping the immediate. That is fixed where
	# it lives. Ten `vcmpltps <rip>,%ymm,%ymm` sites were declined here,
	# all of them holding a compare predicate in an imm8. Finding 303.
	if not rip_operand(tail) or len(tail) < 6:
		return None
	return address + length + struct.unpack_from("<i", tail, 2)[0]


# Mnemonics with NO legacy encoding, which therefore must never be narrowed
# by clearing `VEX.L` and re-emitting. `sse_encoding` will do it anyway and
# produce bytes that decode to nothing: `vbroadcastss` came out as
# `66 0f 38 18`, which objdump calls `(bad)`, in a stub that `verify` passed
# because its rule is "no VEX in the stub" and an invalid instruction is not
# VEX either.
#
# **The plain path never had this problem**, because it goes through
# `lower.py`, which carries an explicit rule per shape -- a broadcast is
# `movss` plus `shufps $0`, not a prefix strip -- and refuses what it has no
# rule for. The span and region path narrows the instruction directly, which
# is right for `vaddps` and wrong for anything the ISA only ever encoded
# under VEX.
#
# Starfield's 93 region sites happen to contain none of these, so nothing
# has shipped wrong; the defect was found by the first fixture ever written
# for the region strategy, on its first run. Finding 205.
# **The FMA3 family, which the operand-count classifier cannot see.**
# `vfmadd231ps %ymm1,%ymm2,%ymm8` has three register fields exactly like
# `vaddps`, so `span_operand_shape` calls it "a register second source, D
# of its own" -- a member of SPAN_EMITTABLE -- and the emitter narrows it
# to `movaps %ymm2,%ymm8` followed by the opcode with VEX.L cleared. That
# is wrong twice over, and neither fault is visible in the field count
# which was the only thing separating these from ordinary arithmetic.
# There is no legacy encoding: the strip produces `66 0f 38 b6`, which
# decodes to nothing. And an FMA's destination is also an accumulator
# SOURCE, so the `movaps` that sets it up destroys a live operand -- this
# would still be wrong if the encoding existed.
#
# It is latent rather than new. `span` and `region` reach the same
# classifier and would emit the same bytes; they placed few enough
# windows that no FMA had yet fallen into one. Offering the unconditional
# lowering first put 18,279 windows through that path and 20 byte
# sequences in the stub decoded to nothing. Finding 258.
#
# Derived rather than typed: sixty mnemonics is too many to list without
# getting one wrong, and a name missing from the set is a silent wrong
# encoding rather than an error.
FMA_FORMS = frozenset(
	f"vf{negated}m{operation}{order}{width}"
	for negated in ("", "n")
	for operation in ("add", "sub")
	for order in ("132", "213", "231")
	for width in ("ps", "pd", "ss", "sd")
) | frozenset(
	f"vfm{operation}{order}{width}"
	for operation in ("addsub", "subadd")
	for order in ("132", "213", "231")
	for width in ("ps", "pd")
)

NO_LEGACY_FORM = frozenset((
	"vbroadcastss", "vbroadcastsd", "vbroadcastf128", "vbroadcasti128",
	"vpbroadcastb", "vpbroadcastw", "vpbroadcastd", "vpbroadcastq",
	"vextractf128", "vextracti128", "vinsertf128", "vinserti128",
	"vperm2f128", "vperm2i128", "vpermd", "vpermq", "vpermps", "vpermpd",
	"vpermilps", "vpermilpd", "vmaskmovps", "vmaskmovpd", "vpmaskmovd",
	"vpmaskmovq", "vzeroupper", "vzeroall", "vgatherdps", "vgatherqps",
	"vgatherdpd", "vgatherqpd", "vpgatherdd", "vpgatherqd", "vpgatherdq",
	"vpgatherqq", "vtestps", "vtestpd", "vcvtph2ps", "vcvtps2ph",
)) | FMA_FORMS


def commuted_piece(vex, tail):
	"""The SSE form of `op %ymmD,%ymmS,%ymmD`, sources exchanged, or None.

	`narrow_piece` drops the VEX prefix and keeps the ModRM, which is right
	exactly when VEX.vvvv already names the destination -- the SSE form has
	no place to put a second source, so the one in `vvvv` is thrown away.
	Where the destination is the OTHER source, throwing it away turns
	`vmulps %ymm1,%ymm0,%ymm1` into `mulps %xmm1,%xmm1`, which squares.

	So the source in `vvvv` is written into ModRM.rm instead, and REX.B
	follows it. Only valid where exchanging the sources does not change the
	result: see `COMMUTATIVE_YMM`, which is what the caller gates on.

	Register to register only. A memory source cannot be in `vvvv`, so the
	shape this serves never has one. Finding 284.
	"""
	if len(tail) < 2 or (tail[1] & 0xC0) != 0xC0:
		return None
	source = vex["vvvv"]
	modrm = (tail[1] & 0xF8) | (source & 7)
	narrow = dict(vex, L=0, B=1 if source >= 8 else 0)
	return inplace.sse_encoding(narrow, tail[:1] + bytes([modrm]) + tail[2:])


def narrow_piece(vex, tail, delta, address, length, at):
	"""One 128-bit half of a 256-bit memory operand, `delta` bytes along.

	**There are two ways to move an operand, and which applies is a property
	of the operand rather than a choice.** An ordinary displacement is
	adjusted in place by `patch.offset_operand`. A RIP-relative one cannot
	be: its displacement is measured from the end of the instruction, so it
	has to absorb both the `+delta` and the move into the stub -- and that
	second correction depends on where inside the stub this piece lands,
	which is what `at` is for.

	Finding 38 refused these rather than conflating the two corrections, and
	Finding 43 combines them. It is possible because the target is
	computable from the original encoding, and it is worth 649 sites.
	"""
	narrow = dict(vex, L=0)
	if not rip_operand(tail):
		moved = tail if delta == 0 else inplace.offset_operand(tail, delta)
		if moved is None:
			return None
		return inplace.sse_encoding(narrow, moved)
	target = rip_target(tail, address, length)
	if target is None:
		return None
	# The encoding's length does not depend on the displacement's value -- a
	# RIP operand is always disp32 -- so it can be measured before the
	# displacement that needs it has been worked out.
	probe = inplace.sse_encoding(narrow, tail)
	if probe is None:
		return None
	value = (target + delta) - (at + len(probe))
	if not -(1 << 31) <= value < (1 << 31):
		return None
	# Opcode, modrm, the corrected displacement -- and whatever followed
	# it, which for a compare is the predicate byte. Rebuilding only the
	# first six bytes silently produced `cmpps` with no predicate.
	return inplace.sse_encoding(narrow, tail[:2] + struct.pack("<i", value)
	                            + tail[6:])


def splat_pair(site, following):
	"""(vex, tail, address, length) for a splat's store, or None.

	**`vinsertf128 $1,%xmmN,%ymmN,%ymmN` puts the low half into the high
	half**, so afterwards both halves of the ymm are the same sixteen bytes.
	MSVC emits it to broadcast a 128-bit constant across a 256-bit field,
	and the store that follows writes the value twice.

	That is the shape `lower_ymm_zero_store` already emits: two 128-bit
	stores of one register at deltas 0 and 16. It was written for an
	all-zero ymm, where both halves are zero and the same xmm serves for
	each -- and the reason it serves a splat too is the same reason, one
	step weaker. The bytes are identical; only what makes them correct
	differs.

	89 splats in this binary, 41 of them followed immediately by a store of
	the register. The other 48 feed arithmetic and want the register
	representation rather than this. Finding 108.
	"""
	address, encoding, mnemonic, operands, _c = site
	if mnemonic not in ("vinsertf128", "vinserti128"):
		return None
	fields = inplace.split_operands(operands)
	if len(fields) != 4:
		return None
	immediate, source, keep, destination = fields
	if immediate != "$0x1" or keep != destination:
		return None
	if not source.startswith("%xmm") or not destination.startswith("%ymm"):
		return None
	if source[len("%xmm"):] != destination[len("%ymm"):]:
		return None			# the high half must come from the low one
	store_address, store, store_mnemonic, store_operands, _d = following
	move = wide_move(store, store_mnemonic, store_operands)
	if move is None or move[0] != "store" or move[1] != destination:
		return None
	store_vex = inplace.decode_vex(store)
	if store_vex is None or not store_vex["L"]:
		return None
	return (store_vex, store[store_vex["length"]:], store_address, len(store))


# **Operations that are the same operation on each 128-bit lane**, so doing
# one of them twice reproduces the 256-bit form exactly. The requirement is
# about LANES and not about elements: a bitwise op combines corresponding
# bits, an add combines corresponding elements, `vpblendw` selects by an
# immediate and `vphsubd` combines NEIGHBOURS -- and all four qualify,
# because AVX defines even the horizontal forms per 128-bit lane. What
# disqualifies a form is reaching across the lane boundary (`vperm2f128`,
# `vpermq`, `vpermpd`) or otherwise depending on the other half.
#
# **This comment used to say "nothing horizontal is here" and give
# `vhaddps` as the example**, while `vphsubd` sat in the set three lines
# below it. Finding 122 caught that: the exclusion was safe by
# conservatism and wrong by its stated reason, and a reason that does not
# hold is worse than none, because the next person extends the set by
# applying it.
#
# **Every one of these is executed, not reasoned.** `make check-lanes` runs
# the 256-bit form under qemu against the two 128-bit halves natively and
# requires them to agree bit for bit; it rebuilds each split wrong twice --
# halves swapped, low half used for both -- and requires BOTH sabotages to
# be rejected, so a verdict reached on inputs too symmetric to discriminate
# is a failure rather than a pass; and it fails if this set gains a mnemonic
# the harness does not execute, so the list and the evidence cannot drift
# apart.
#
# `vpsadbw`, `vphsubd` and `vpblendw` were held out of it deliberately: they
# are lane-wise by the manual and occur 5, 1 and 2 times, which is too rare
# for `check-pe` to catch a misreading. The oracle settled them, so they are
# in. Finding 122.
#
# **The last nine arrived when the set gained a second reader.** Finding 122
# settled twelve further mnemonics as lane-wise under execution and took
# none of them, for a reason that was right at the time: `splat_operation`
# was the only thing reading this set, none of the twelve appears in a
# splat triple here, and a set is a liability rather than an asset until
# something reads it. `ymm_span` -- written six days later -- is that second
# reader, and a 256-bit form it does not recognise closes the span it is
# walking. `make spans` now ranks what closes them, and these are the
# entries that ranked. Finding 140.
#
# A mnemonic missing from this set costs a site; one wrongly on it costs
# correctness, which is `scratch.py`'s FULL_WRITE rule and the reason it is
# not open-ended.
LANE_WISE = frozenset("""
	vandps vandpd vandnps vandnpd vorps vorpd vxorps vxorpd
	vaddps vaddpd vsubps vsubpd vmulps vmulpd vdivps vdivpd
	vminps vminpd vmaxps vmaxpd
	vpand vpandn vpor vpxor
	vpaddb vpaddw vpaddd vpaddq vpsubb vpsubw vpsubd vpsubq
	vpsadbw vphsubd vpblendw
	vshufps vaddsubps vpmulld vpmuludq vpcmpeqb vpcmpeqw vpsubusw
	vpshufb vpmaddwd
""".split())


def splat_operation(site, following, third):
	"""(operation, store) if a lane-wise op on a splat is stored, or None.

	**A splat's two halves are the same sixteen bytes**, so an operation
	whose only ymm source is the splat register can be done once per half
	with no helper register at all: move the splat's xmm into the
	destination, apply the operation to the half of memory that belongs
	there, store that half. Twice, high half first, so the destination ends
	holding the low sixteen -- the same order and the same reason as
	`lower_ymm_pair`.

	Each condition is a way the trick fails rather than a tidiness rule:

	  * the operation must be lane-wise, or two 128-bit instructions are not
	    the 256-bit one;
	  * its other source must be memory, because a second ymm source has an
	    upper half nobody knows -- that is the register representation, not
	    this;
	  * its destination must not be the splat register, or computing the
	    high half destroys the value the low half needs;
	  * the store must be of that destination and must follow at once, so
	    that nothing between them can be reordered across a half.

	19 of these in the binary, 17 `vandps` and 2 `vmulps`, and all three
	instructions of each are refused today: the insert for having no store
	after it, the operation for being arithmetic, the store for having no
	known upper half. Finding 114.
	"""
	address, encoding, mnemonic, operands, _c = site
	fields = inplace.split_operands(operands)
	if mnemonic not in ("vinsertf128", "vinserti128") or len(fields) != 4:
		return None
	immediate, source, keep, held = fields
	if immediate != "$0x1" or keep != held:
		return None
	if not source.startswith("%xmm") or not held.startswith("%ymm"):
		return None
	if source[len("%xmm"):] != held[len("%ymm"):]:
		return None
	if following[0] != address + len(encoding):
		return None

	op_address, op_encoding, op_mnemonic, op_operands, _d = following
	if op_mnemonic not in LANE_WISE \
			or not inplace.has_direct_sse_form(op_mnemonic):
		return None
	parts = inplace.split_operands(op_operands)
	if len(parts) != 3 or parts[1] != held or "(" not in parts[0]:
		return None
	destination = parts[2]
	if not destination.startswith("%ymm") or destination == held:
		return None
	op_vex = inplace.decode_vex(op_encoding)
	if op_vex is None or not op_vex["L"]:
		return None

	store_address, store, store_mnemonic, store_operands, _e = third
	if store_address != op_address + len(op_encoding):
		return None
	move = wide_move(store, store_mnemonic, store_operands)
	if move is None or move[0] != "store" or move[1] != destination:
		return None
	store_vex = inplace.decode_vex(store)
	return ((op_vex, op_encoding[op_vex["length"]:], op_address,
	         len(op_encoding)),
	        (store_vex, store[store_vex["length"]:], store_address,
	         len(store)))


def ymm_pair(site, following):
	"""(load, store) if these two are a 256-bit copy through one ymm.

	The Y1 case Finding 2 measured, and the only 256-bit shape that needs no
	shadow state: a 32-byte load into a ymm and an immediate 32-byte store
	out of it. 7,395 adjacent pairs, 7,142 of them vmovups to vmovups.

	Each half is returned with its own address and length, because a
	RIP-relative operand's displacement can only be recomputed from those.
	"""
	(load_address, load, load_mnemonic, load_operands, _c) = site
	(store_address, store, store_mnemonic, store_operands, _d) = following
	if load_mnemonic not in YMM_MOVES or store_mnemonic not in YMM_MOVES:
		return None
	load_vex, store_vex = inplace.decode_vex(load), inplace.decode_vex(store)
	if not load_vex or not store_vex or not load_vex["L"] or not store_vex["L"]:
		return None
	# Memory into a ymm, then that same ymm back out to memory.
	source, _, destination = load_operands.rpartition(",")
	held, _, target = store_operands.partition(",")
	if not destination.startswith("%ymm") or destination != held:
		return None
	if "(" not in source or "(" not in target:
		return None
	return ((load_vex, load[load_vex["length"]:], load_address, len(load)),
	        (store_vex, store[store_vex["length"]:], store_address, len(store)))


def lower_ymm_pair(pair, at):
	"""Four 128-bit moves for one 256-bit copy. **High half first.**

	The order is the whole trick, and it is what makes this need no scratch
	register. Doing the high half first leaves the ymm's own xmm holding the
	LOW sixteen bytes when the sequence ends -- which is exactly what the
	lower half of that ymm holds in the original. So every later 128-bit
	read of the register is still correct, and only a read of the upper half
	would differ. That is the Y2 case by definition, and Finding 7 measured
	it at 574 sites of 13,097.

	Reversing these two pairs of lines would leave the high half in the
	register and quietly corrupt every later use of it.

	`at` is where the first of the four will execute, which only a
	RIP-relative operand needs -- each piece's displacement is measured from
	its own end, so they are emitted one at a time rather than in a batch.
	"""
	load, store = pair
	body = bytearray()
	for half, delta in ((load, 16), (store, 16), (load, 0), (store, 0)):
		vex, tail, address, length = half
		piece = narrow_piece(vex, tail, delta, address, length,
		                     at + len(body))
		if piece is None:
			return None
		body += piece
	return bytes(body)


def lower_splat_operation(operation, store, at):
	"""Six instructions for a splat, an operation on it, and a store.

	Two per half: the splat's xmm into the destination, the operation
	against the half of memory that belongs there, and the store of it. The
	insert itself emits nothing -- the value it built is already in the
	register the lowered program keeps -- and the splat's own xmm is never
	written, so it is still there for the second half.

	**High half first**, which is what leaves the destination holding the low
	sixteen when the sequence ends. See `lower_ymm_pair`, where the order is
	the whole trick for the same reason.
	"""
	op_vex, op_tail, op_address, op_length = operation
	destination, source = registers_of(op_vex, op_tail)
	body = bytearray()
	for delta in (16, 0):
		body += encode_movaps(destination, source)
		piece = narrow_piece(op_vex, op_tail, delta, op_address, op_length,
		                     at + len(body))
		if piece is None:
			return None
		body += piece
		piece = narrow_piece(store[0], store[1], delta, store[2], store[3],
		                     at + len(body))
		if piece is None:
			return None
		body += piece
	return bytes(body)


def lower_ymm_zero_store(vex, tail, address, length, at):
	"""Two 128-bit stores for one 256-bit store of an all-zero register.

	No scratch, no shadow, and no second register: the value being stored is
	zero in both halves, so the same xmm serves for each.
	"""
	low_half = narrow_piece(vex, tail, 0, address, length, at)
	if low_half is None:
		return None
	high_half = narrow_piece(vex, tail, 16, address, length,
	                         at + len(low_half))
	if high_half is None:
		return None
	return low_half + high_half


def store_run(instructions, index, blocked, holds, limit=16):
	"""Consecutive 256-bit stores the caller can vouch for, as one window.

	**Short zero stores compete with each other for padding.** A 256-bit
	store with no displacement encodes in four bytes and a `jmp rel32` needs
	five, so its window has to widen over a neighbour -- and where the
	neighbour is another zero store, it widens over a site that wanted the
	same trick. The first one wins, the second's window overlaps a committed
	one and is skipped, and MSVC emits these in threes and fours because that
	is what clearing a structure looks like.

	Measured: of 9,795 stores of a provably zero register, 327 survive, 325
	of them four bytes long, and 323 are lost after the collector rather than
	refused by it. The site Starfield stopped at was the first of three in a
	row. Finding 81.

	Taking the group as one window removes the competition: nothing has to
	widen, because the run is already longer than five bytes, and each store
	lowers into the same stub. `limit` bounds the group; there is no reason
	for a long one and an unbounded walk here would be a new way to be slow.

	Returns (positions, last position) with at least two members, or None.
	`holds` decides whether a store's value is known at its own position --
	passed in rather than called here so this stays a scan, and so that the
	same grouping serves a constant as well as a zero. Nothing above is
	about which value it is: the competition for padding is a property of
	four-byte stores standing next to each other. Finding 109.
	"""
	members, at = [index], None
	address, encoding, _m, _o, _c = instructions[index]
	at = address + len(encoding)
	for step in range(1, limit):
		position = index + step
		if position >= len(instructions):
			break
		next_address, bits, name, text, _cc = instructions[position]
		if next_address != at or next_address in blocked:
			break
		if name.startswith(CONTROL_PREFIXES):
			break
		what = wide_move(bits, name, text)
		if what is None or what[0] != "store":
			break
		if not holds(position, what[1]):
			break
		members.append(position)
		at = next_address + len(bits)
	if len(members) < 2:
		return None
	return members, members[-1]


def lower_constant_run(entries, at):
	"""Every store in the run, four 128-bit moves each, into one stub.

	Each member carries its own load, so a run may mix constants and mix
	registers -- what makes it a run is that the stores are adjacent, not
	that they say the same thing.
	"""
	body = bytearray()
	for load, store in entries:
		piece = lower_ymm_pair((load, store), at + len(body))
		if piece is None:
			return None
		body += piece
	return bytes(body)


def lower_zero_run(entries, at):
	"""Every store in the run, two 128-bit stores each, into one stub."""
	body = bytearray()
	for vex, tail, address, length in entries:
		piece = lower_ymm_zero_store(vex, tail, address, length,
		                             at + len(body))
		if piece is None:
			return None
		body += piece
	return bytes(body)


def conditional_branch(mnemonic):
	"""True for a branch that can fall through to the next instruction.

	`loop` and `loopne` qualify too and are left out: they are rare here, and
	a list that stays short is one that can be checked by reading it.
	"""
	return mnemonic.startswith("j") and mnemonic not in ("jmp", "jmpq")


def retarget(vex, tail, register):
	"""`vex` and `tail` with the modrm.reg field pointing at `register`.

	Which is how the same load becomes a load into a different xmm: the
	memory operand and the opcode are untouched and only the destination
	moves.
	"""
	return (dict(vex, R=register >> 3),
	        bytes([tail[0], (tail[1] & 0xC7) | ((register & 7) << 3)])
	        + tail[2:])


def wide_move(encoding, mnemonic, operands):
	"""("load"|"store", %ymmN) if this is a 256-bit move to or from memory."""
	vex = inplace.decode_vex(encoding)
	if vex is None or not vex["L"] or mnemonic not in YMM_MOVES:
		return None
	fields = inplace.split_operands(operands)
	if len(fields) != 2:
		return None
	if fields[1].startswith("%ymm") and "(" in fields[0]:
		return ("load", fields[1])
	if fields[0].startswith("%ymm") and "(" in fields[1]:
		return ("store", fields[0])
	return None


YMM_BROADCASTS = frozenset("""
	vbroadcastss vbroadcastsd
	vpbroadcastb vpbroadcastw vpbroadcastd vpbroadcastq
""".split())


def wide_copy(encoding, mnemonic, operands):
	"""(%ymmS, %ymmD) if this is a 256-bit register-to-register move.

	`wide_move` answers only where one operand is memory, because that is
	all `ymm_run` ever needed: a run is a load, some work, a store. A copy
	has neither operand in memory, so it fell through every branch of
	`ymm_span` into the catch-all that reports "a 256-bit form that is not
	lane-wise" -- an instruction with no lane structure at all, filed under
	a label about lane structure. 24 of them here. Finding 140.
	"""
	vex = inplace.decode_vex(encoding)
	if vex is None or not vex["L"] or mnemonic not in YMM_MOVES:
		return None
	fields = inplace.split_operands(operands)
	if len(fields) != 2 or not all(f.startswith("%ymm") for f in fields):
		return None
	return (canonical_ymm(fields[0]), canonical_ymm(fields[1]))


def wide_broadcast(encoding, mnemonic, operands):
	"""%ymmD if this fills a 256-bit register from one, else None.

	**A broadcast's two lanes are the same sixteen bytes**, which makes it
	the one 256-bit definition whose upper half costs a span nothing to
	know: it does not have to be carried from anywhere, it is the low half
	repeated. So the source is deliberately NOT required to be tracked --
	it is an xmm, and an xmm is a register SSE can already reach.

	The register form only, which is AVX2. The memory-source form is the
	Class D splat, lowered elsewhere, and it never reaches a span walk
	because `lower_splat` has already claimed it.
	"""
	vex = inplace.decode_vex(encoding)
	if vex is None or not vex["L"] or mnemonic not in YMM_BROADCASTS:
		return None
	fields = inplace.split_operands(operands)
	if len(fields) != 2 or not fields[0].startswith("%xmm") \
			or not fields[1].startswith("%ymm"):
		return None
	return canonical_ymm(fields[1])


def note(why, reason):
	"""Record a decline reason where the caller asked for one."""
	if why is not None:
		why.append(reason)


def extract_upper(encoding, mnemonic, operands, tracked):
	"""Where an extract's result lands, if a run can carry it, else None.

	`vextractf128 $0x1,%ymmS,%xmmD` takes the upper half of a 256-bit value
	into an xmm. It is cross-lane by definition -- which is exactly why it
	becomes trivial once a run is holding that half in a helper: the lanes
	have already been separated, and the whole instruction is
	`movaps H(S),%xmmD`.

	Returns the destination spelled as a **ymm**, because that is what
	`held_open` has to guard. The original zeroes bits [255:128] of the
	destination, as every VEX.128 write does, and a `movaps` does not -- so
	a later 256-bit read of it would see a stale half, and the run's
	existing `upper_half_read_later` check is what stops that.

	Refused where the destination is itself tracked: writing its xmm would
	destroy the low half the run still owes a store, and nothing downstream
	would look wrong. Refused for `$0x0`, which takes the LOW half; there
	are none in this binary, so it is a unit case rather than an execution
	one. 375 register-form extracts here, every one of them `$0x1`.
	Finding 117.
	"""
	if mnemonic not in ("vextractf128", "vextracti128"):
		return None
	vex = inplace.decode_vex(encoding)
	if vex is None or not vex["L"]:
		return None
	fields = inplace.split_operands(operands)
	if len(fields) != 3 or fields[0] != "$0x1":
		return None
	source, destination = fields[1], fields[2]
	if source not in tracked or not destination.startswith("%xmm"):
		return None
	held = "%ymm" + destination[len("%xmm"):]
	return None if held in tracked else held


def ymm_run(instructions, index, blocked, limit=48, why=None):
	"""A stretch of 256-bit copies whose halves all lie inside it.

	Finding 39 refused the gapped copy because the four-move lowering
	**interleaves** the load and the store, so anything between them is
	reordered across one half or the other and proving that safe needs alias
	analysis. It named the way out -- load both halves before storing either,
	which needs a second register -- and stopped there.

	Holding the upper half in a second register does not merely make it
	possible; it makes the problem go away. Both loads happen where the load
	was and both stores where the store was, so **nothing in between moves at
	all**:

	    movups (%rsi),%xmm0        movups 0x10(%rsi),%xmm7
	    ... untouched ...
	    movups %xmm0,(%rdi)        movups %xmm7,0x10(%rdi)

	A run generalises that to the interleaved case, which is what MSVC emits
	for a block bigger than 32 bytes: load, load, store, store. Each open ymm
	gets a helper of its own, which is register allocation on a very small
	scale. Measured: 9,577 runs, of which 9,200 hold a single pair and 377
	hold between two and ten.

	A register stays tracked across as many stores as follow, since one
	source copied to two destinations stores the same ymm twice and the
	upper half is in a helper either way. `assign_helpers` already keys on
	the LAST store per register, so it needed no change for that.

	Returns (members, last position), members being (kind, position, register)
	with kind one of `load`, `store`, `plain`. The whole run goes into ONE
	stub, which is what keeps it an ordinary window rather than several that
	must all commit or none -- 98% of the single-pair spans fitted in one
	window, and that number chose the design.
	"""
	address, encoding, mnemonic, operands, _comment = instructions[index]
	first = wide_move(encoding, mnemonic, operands)
	if first is None:
		note(why, "256-bit: arithmetic rather than a copy")
		return None
	if first[0] != "load":
		note(why, "256-bit: a store whose load was not taken")
		return None
	tracked = {first[1]}
	members, at, last_store = [], address + len(encoding), None
	stopped = "the run reached its limit"
	for step in range(1, limit + 1):
		position = index + step
		if position >= len(instructions):
			break
		next_address, bits, name, text, _c = instructions[position]
		if next_address != at:
			stopped = "a gap in the listing"
			break
		if next_address in blocked:
			stopped = "a branch target inside the run"
			break
		if name.startswith(CONTROL_PREFIXES):
			stopped = "a control transfer"
			break
		what = wide_move(bits, name, text)
		vex = inplace.decode_vex(bits)
		if what is not None and what[0] == "store" and what[1] in tracked:
			# **A store does not end the value's life.** One source copied
			# to two destinations stores the same ymm twice, and closing on
			# the first store refused 1,019 pairs for reading an upper half
			# that is sitting in a helper register. The register stays
			# tracked and the run simply grows.
			members.append(("store", position, what[1]))
			last_store = len(members)
			at = next_address + len(bits)
			continue
		if what is not None and what[0] == "load" and what[1] not in tracked:
			# **A reload is refused, and it took three measurements to be
			# sure.** `lifetimes` has been ready for one since Finding 77
			# rekeyed it on position, and letting the walk carry on is this
			# condition. It measured at minus four sites, then -- after
			# Finding 125 stopped a failed strategy declining its site --
			# at plus fifty-one by `detour-plan`. Both were `plan` numbers.
			#
			# The BUILT binary went the other way: 8,899 VEX to 8,948, with
			# 44 more stubs refused and 404 more skipped for overlap. A run
			# that carries on through a reload is a longer run, and a longer
			# window collides with neighbours that would each have been
			# placed -- which is the lesson `zero_run`'s caller already
			# carries, arriving here from a strategy rather than from a
			# grouping. `plan` does not model `place_stubs` and cannot see
			# it. Finding 126.
			tracked.add(what[1])
			members.append(("load", position, what[1]))
			at = next_address + len(bits)
			continue
		if vex is not None and vex["L"]:
			pulled = extract_upper(bits, name, text, tracked)
			if pulled is not None:
				# It reads a helper and owns none. See `extract_upper`.
				members.append(("extract", position, pulled))
				at = next_address + len(bits)
				continue
			stopped = "256-bit arithmetic on the value"
			break			# a 256-bit instruction that is not a copy half
		if any(r in text or "%xmm" + r[len("%ymm"):] in text
		       for r in tracked):
			stopped = "the value is touched"
			break			# the value is touched other than by a store
		members.append(("plain", position, None))
		at = next_address + len(bits)

	if last_store is None:
		note(why, "256-bit: no store before " + stopped)
		return None
	# Trim whatever followed the last store: it is not part of the copy and
	# carrying it would only widen the window.
	members = members[:last_store]
	loaded = {first[1]} | {r for kind, _p, r in members if kind == "load"}
	stored = {r for kind, _p, r in members if kind == "store"}
	if loaded - stored:
		# **The whole run goes, and completed stores go with it.** A second
		# value loaded inside the run whose own store lies past where the
		# walk stopped takes the run down. 61 sites, the frontier
		# 0x14004E230 among them, where the stranded value is a `.rdata`
		# constant stored fifty instructions later. Finding 99 measured the
		# way out and rejected it.
		note(why, "256-bit: loaded and never stored before " + stopped)
		return None		# a register loaded and never stored has no use
	return members, members[-1][1]


def run_prefixes(held, members):
	"""Every valid truncation of a run, longest first.

	**`assign_helpers` is asked for the span reaching the run's LAST store,
	and only that one.** A long span is harder to give a register to than a
	short one -- `free_across` wants a register dead from the load all the
	way to the last store -- so a run refused for want of a helper may well
	have a prefix that is not, and the prefix stores real bytes either way.
	The run simply ends earlier and whatever followed detours on its own
	account.

	A truncation has to satisfy `ymm_run`'s own two conditions applied to
	less of the walk: it ends at a store, because a run's product is a
	store; and it leaves nothing loaded and unstored, or a value the run
	took responsibility for goes nowhere.

	Longest first, so a run that needs no truncation is unaffected and the
	first prefix offered is exactly what `ymm_run` returned. Finding 116.
	"""
	for end in range(len(members), 0, -1):
		if members[end - 1][0] != "store":
			continue
		prefix = members[:end]
		loaded = {held} | {r for kind, _p, r in prefix if kind == "load"}
		stored = {r for kind, _p, r in prefix if kind == "store"}
		if loaded - stored:
			continue
		yield prefix, prefix[-1][1]


def free_across(plain, positions, definition, until, site_registers):
	"""Registers dead at `definition` that nothing touches before `until`.

	Two questions and both have to hold. `dead_from` answers the first, the
	same way `find_scratch` asks it. The second is what makes this different
	from a scratch: a scratch may be clobbered the moment the stub ends,
	while this one has to carry a value across everything in between.
	"""
	usable = set(scratch_finder.dead_from(plain, definition + 1,
	                                      frozenset(site_registers), 60,
	                                      positions, set(),
	                                      [scratch_finder.BUDGET]))
	for position in range(definition + 1, until):
		text = plain[position][3]
		for number in list(usable):
			if f"%xmm{number}" in text or f"%ymm{number}" in text:
				usable.discard(number)
		if not usable:
			break
	return usable


def lifetimes(index, members, start):
	"""Every (register, load position, store positions) the run holds open.

	**A lifetime, not a register, is what needs a helper.** The two are the
	same thing only while a run ends the moment anything touches a tracked
	register, which is what `ymm_run` does today -- so one register can be
	loaded once, stored, and that is the whole of it. The moment a run can
	survive its low half being clobbered and pick the register up again, one
	register carries two values that share nothing and overlap nowhere.

	Keying on the register is a silent-wrongness bug in that world rather
	than a missed optimisation. The old version kept the LAST load and the
	LAST store per register, so a register loaded twice would have both
	lifetimes assigned one helper, and the earlier lifetime's store would
	read a helper the later lifetime had not loaded yet -- it would assemble,
	verify, and store the wrong 16 bytes. Finding 77.

	Returns them in load order, or None if a store arrives for a register
	that is not open, which no caller should be able to produce.
	"""
	out, open_at = [], {start: (index, [])}
	for kind, position, register in members:
		if kind == "load":
			if register in open_at:
				load_at, stores = open_at.pop(register)
				out.append((register, load_at, stores))
			open_at[register] = (position, [])
		elif kind == "store":
			if register not in open_at:
				return None
			open_at[register][1].append(position)
	for register, (load_at, stores) in open_at.items():
		out.append((register, load_at, stores))
	return sorted(out, key=lambda span: span[1])


RSP_WRITTEN = re.compile(r",\s*%rsp\s*$")


def span_keeps_rsp(instructions, first, last):
	"""True if nothing between `first` and `last` moves the stack pointer.

	**The guard the run borrow needs, and the reason it is different from the
	swallowed one.** Finding 93 brackets a single lowering, so nothing can
	come between the save and the restore whatever the window holds. A run's
	helper carries the upper half from the load to the store, so the bracket
	encloses the whole span -- and a `push` or a `sub $n,%rsp` inside it
	leaves the save and the restore addressing different memory, so the
	restore returns whatever the push wrote. A silently wrong register, not a
	crash.

	A call cannot be inside a run at all: `ymm_run` breaks on every control
	transfer. So `rsp` is the whole of what is left to check.

	Measured over the 424 sites this was written for: 159 are in a function
	that can lend, and **not one of those spans touches `rsp`**. The guard
	costs nothing today, which is why it must be in the code rather than in
	the finding -- a span that grows later has nothing else to stop it.
	Finding 95.
	"""
	for position in range(first, last + 1):
		if position >= len(instructions):
			return False
		_a, _e, mnemonic, operands, _c = instructions[position]
		if mnemonic in ("push", "pushq", "pop", "popq"):
			return False
		if RSP_WRITTEN.search(operands or ""):
			return False
	return True


def assign_helpers(plain, positions, index, members, lendable=False):
	"""One helper register per LIFETIME in the run, all distinct, or None.

	Greedy over the lifetimes in load order, which is enough here: a run
	holds ten at the very most and the candidate sets are large. Distinctness
	has to be enforced rather than assumed -- two helpers are both invisible
	to the original code, so nothing else keeps them apart.

	Keyed by position rather than by register, so that `lower_ymm_run` can
	ask "which helper does THIS load or store use" instead of "which helper
	does this register use". See `lifetimes` for why that distinction is a
	correctness one.
	"""
	spans = lifetimes(index, members, wide_move(*plain[index][1:4])[1])
	if spans is None:
		return None
	taken, out, borrowed = set(), {}, set()
	for register, load_at, stores in spans:
		if not stores:
			return None
		own = scratch_finder.xmm_numbers(plain[load_at][3])
		free = free_across(plain, positions, load_at, stores[-1], own) - taken
		if not free:
			# **Nothing is dead across this lifetime, so borrow one that is
			# live and give it back**, exactly as a starved site does. The
			# caller decides whether the function can lend and whether the
			# span leaves `rsp` alone; this only picks a register the run
			# does not itself name. Finding 95.
			if not lendable:
				return None
			# **Every instruction the helper is live across, not just the
			# load and the stores.** A run swallows whatever lies between
			# them into the same stub, and those passengers are re-emitted
			# BETWEEN the carry-load and the carry-store -- so a passenger
			# naming the borrowed register overwrites the half in flight,
			# and the stub then stores the passenger's value as the upper
			# half. The save and restore protect the CALLER's register
			# across the stub and say nothing about the middle of it.
			#
			# Measured on Starfield before the fix: 347 runs borrowed, 171
			# had a plain passenger naming the borrowed register, and 138
			# of those were PLACED -- wrong bytes in the shipped image.
			# The comment this replaces said it picked "a register the run
			# does not itself name", and the passengers are the run.
			# Finding 252.
			free = set(VOLATILE_XMM) - taken - set(own)
			for position in range(load_at, max(stores) + 1):
				free -= set(scratch_finder.xmm_numbers(plain[position][3]))
			if not free:
				return None
			chosen = min(free)
			borrowed.add(chosen)
		else:
			chosen = min(free)
		taken.add(chosen)
		out[load_at] = chosen
		for position in stores:
			out[position] = chosen
		# **An extract reads a helper without owning one.** It needs to know
		# where its source's upper half is living at its own position, which
		# is this lifetime's helper when it falls inside this lifetime -- and
		# which lifetime that is matters, because one register can hold two
		# values in one run. See `lifetimes` and Finding 77.
		for kind, position, _held in members:
			if kind != "extract" or not load_at < position <= stores[-1]:
				continue
			# The extract's SOURCE, which is the lifetime this asks about --
			# the member carries its DESTINATION, because that is what
			# `held_open` guards.
			if inplace.split_operands(plain[position][3])[1] == register:
				out[position] = chosen
	# **An extract whose source's lifetime ended before it gets nothing.**
	# The helper physically still holds those bytes, but the model says the
	# lifetime is over and a later one may take the register, so believing
	# otherwise is how Finding 77's silent wrongness comes back. Refuse the
	# run; `run_prefixes` will offer a shorter one that does not reach here.
	for kind, position, _held in members:
		if kind == "extract" and position not in out:
			return None
	return out, borrowed


# How many 16-byte slots a home space holds. Two per region, and a site
# whose function lends both has four. See Finding 133.
SLOTS_PER_REGION = HOME_SPACE // SLOT


def ymm_span(instructions, index, blocked, positions, limit=48, why=None):
	"""A stretch of 256-bit work whose upper halves can live in slots.

	`(members, last position, slots)` or None. This is analysis only -- it
	emits nothing and nothing depends on it yet -- and it exists to price
	the build Finding 133 scoped.

	**Why a span and not an instruction.** An upper half exists only in the
	machine's ymm register, which no SSE instruction can reach, so it can
	be kept in a slot only if EVERY instruction that produces or consumes
	it was rewritten too. The representation has to be consistent from the
	definition to the death, which makes the unit a closed span rather than
	a site.

	`ymm_run` is this with two of the three cases: a load defines, a store
	consumes, and anything else about the value ends the run. Arithmetic is
	the third, and it is what `256-bit: arithmetic rather than a copy`
	counts -- 1,974 sites, the largest 256-bit refusal there is.

	Two more definitions were added once `make spans` could say what
	actually stopped a span rather than only that something had. A
	register-to-register copy defines the destination from a source this
	span must already hold; a broadcast defines one from nothing, because
	its two lanes are the same sixteen bytes. Neither is arithmetic and
	neither has lane structure, and both were being refused by the branch
	that reports a form as not lane-wise. Finding 140.

	**The span must close.** Every register it tracks has to be dead at the
	end, because a value still live would have to be put back into a real
	ymm register and nothing available can do that. A call ends the span and
	costs nothing: Win64 makes every ymm upper half volatile across one, so
	the value was dead there anyway.

	`slots` is the PEAK number of upper halves live at once, not the number
	of registers touched. A span that defines four values one after another
	and kills each before the next needs one slot, not four.
	"""
	address, encoding, mnemonic, operands, _comment = instructions[index]
	first = wide_move(encoding, mnemonic, operands)
	if first is None or first[0] != "load":
		note(why, "span: does not begin with a 256-bit load")
		return None
	# {register: [defined at member index, last used at member index]}
	live = {first[1]: [0, 0]}
	members = [("load", index, first[1])]
	at = address + len(encoding)
	stopped = "the span reached its limit"
	# **Which form stopped it, not merely that one did.** The refusal
	# reason is what a span failed on; extending `LANE_WISE` needs to
	# know WHICH 256-bit form, and a count of "not lane-wise" ranks
	# nothing. Reported beside the reasons rather than folded into
	# them, so the existing buckets stay comparable across runs.
	stopper = None
	for step in range(1, limit + 1):
		position = index + step
		if position >= len(instructions):
			stopped = "the end of the listing"
			break
		next_address, bits, name, text, _c = instructions[position]
		if next_address != at:
			stopped = "a gap in the listing"
			break
		if next_address in blocked:
			stopped = "a branch target inside the span"
			break
		if name.startswith(CONTROL_PREFIXES):
			# A call ends it for free -- the upper halves were volatile
			# across one anyway -- and so does any other transfer.
			stopped = "a control transfer"
			break
		text = text or ""
		vex = inplace.decode_vex(bits)
		touched = [r for r in live
		           if r in text or "%xmm" + r[len("%ymm"):] in text]
		if vex is not None and vex["L"]:
			what = wide_move(bits, name, text)
			if what is not None and what[0] == "store" and what[1] in live:
				live[what[1]][1] = len(members)
				members.append(("store", position, what[1]))
				at = next_address + len(bits)
				continue
			if what is not None and what[0] == "load":
				live.setdefault(what[1], [len(members), len(members)])[1] = \
					len(members)
				members.append(("load", position, what[1]))
				at = next_address + len(bits)
				continue
			if what is not None and what[0] == "store":
				# **A store of a value this span never defined**, whose
				# upper half is therefore in a machine ymm nothing here can
				# read. A correct refusal, and it gets its own reason
				# because it used to land in the lane-wise catch-all: 125
				# of the 319 stops were this one shape, and a bucket
				# reading "not lane-wise" made them look like work that
				# extending `LANE_WISE` would reach. Finding 140.
				stopped = "a 256-bit store of a value this span never defined"
				stopper = name + " reg,mem"
				break
			copied = wide_copy(bits, name, text)
			if copied is not None:
				source, destination = copied
				# A copy is exactly as representable as its source: the
				# destination's upper half IS the source's.
				if source not in live:
					stopped = "a 256-bit copy of a value this span " \
						"never defined"
					stopper = name + " reg,reg"
					break
				live[source][1] = len(members)
				live.setdefault(destination,
				                [len(members), len(members)])[1] = \
					len(members)
				members.append(("copy", position, destination))
				at = next_address + len(bits)
				continue
			splatted = wide_broadcast(bits, name, text)
			if splatted is not None:
				live.setdefault(splatted,
				                [len(members), len(members)])[1] = \
					len(members)
				members.append(("splat", position, splatted))
				at = next_address + len(bits)
				continue
			pulled = extract_upper(bits, name, text, set(live))
			if pulled is not None:
				# **`extract_upper` returns the DESTINATION**, spelled as a
				# ymm because that is what `ymm_run`'s `held_open` has to
				# guard. What this span accounts for is the SOURCE, whose
				# upper half the extract consumes; the destination is a
				# fresh narrow value the original zeroed the top of, and it
				# is tracked by nobody. Indexing `live` with the returned
				# name was a `KeyError` on the first real listing.
				source = canonical_ymm(inplace.split_operands(text)[1])
				live[source][1] = len(members)
				members.append(("extract", position, pulled))
				at = next_address + len(bits)
				continue
			if name in LANE_WISE:
				# **Every 256-bit SOURCE must already be tracked**, since
				# its upper half has to come from somewhere this span
				# wrote. A memory source needs no slot at all: its upper
				# half is the sixteen bytes above it, addressed directly.
				fields = inplace.split_operands(text)
				if not fields:
					stopped = "a lane-wise form with no operands"
					break
				wanted = [f for f in fields[:-1] if f.startswith("%ymm")]
				if any(canonical_ymm(f) not in live for f in wanted):
					stopped = "a lane-wise source this span never defined"
					break
				for field in wanted:
					live[canonical_ymm(field)][1] = len(members)
				destination = fields[-1]
				if destination.startswith("%ymm"):
					live.setdefault(canonical_ymm(destination),
					                [len(members), len(members)])[1] = \
						len(members)
				members.append(("lane", position, canonical_ymm(destination)
				                if destination.startswith("%ymm") else None))
				at = next_address + len(bits)
				continue
			stopped = "a 256-bit form that is not lane-wise"
			# **The mnemonic alone hides the shape**, and for a move the
			# shape is the whole question: a register-to-register copy
			# and a store of a value this span never defined arrive here
			# spelled the same way and are not the same problem.
			shape = [("mem" if "(" in f else
			          "reg" if f.startswith("%") else "imm")
			         for f in inplace.split_operands(text)]
			stopper = name
			if len(shape) == 2:
				stopper = name + " " + ",".join(shape)
			break
		if touched:
			stopped = "the value is touched by something narrower"
			break
		members.append(("plain", position, None))
		at = next_address + len(bits)

	# **The span closes or it is worth nothing.** A register still live at
	# the end would have to be put back into a real ymm, and nothing here
	# can do that.
	end = index + len(members) - 1
	for register in live:
		if upper_half_read_later(instructions, end, register,
		                         positions=positions):
			note(why, "span: " + register[1:] + " is still live after "
			     + stopped)
			if stopper is not None:
				note(why, "form: " + stopper)
			return None
	if not any(kind in ("lane", "store", "extract")
	           for kind, _p, _r in members):
		note(why, "span: nothing consumes the value")
		return None
	# **The demand is the peak of the intervals, not the count of the
	# registers.** Counting how many were ever tracked said two where a
	# span defines a value, kills it, and defines another -- which needs
	# one slot and reuses it. The selftest case for that is the reason this
	# is computed from the intervals; the incremental count passed the
	# other six.
	peak = 0
	for point in range(len(members)):
		peak = max(peak, sum(1 for low, high in live.values()
		                     if low <= point <= high))
	return members, end, peak


def canonical_ymm(field):
	"""`%ymm7` from an operand, whatever else is around it."""
	found = re.search(r"%ymm\d+", field)
	return found.group(0) if found else field


def perm2_immediate(operands):
	"""`vperm2f128`'s imm8 as an int, or None.

	Read from the operand text rather than from the encoding's last byte
	because the two agree and only one of them is unambiguous to a reader.
	A form whose immediate objdump did not render as a constant is refused
	rather than guessed at.
	"""
	fields = inplace.split_operands(operands or "")
	if not fields or not fields[0].startswith("$"):
		return None
	try:
		return int(fields[0][1:], 0) & 0xFF
	except ValueError:
		return None


def ymm_alias(field):
	"""`%ymm7` for `%xmm7` as well as for `%ymm7`, or None.

	A lane operation names the same architectural register in both widths
	-- `vextractf128 $1,%ymm1,%xmm2` writes the low half of ymm2 -- and
	the slot belongs to the ymm. `canonical_ymm` hands back an %xmm
	operand unchanged, which then has no slot; this is the conversion it
	deliberately does not do.
	"""
	numbers = scratch_finder.xmm_numbers(field)
	return f"%ymm{numbers[0]}" if numbers else None


# The lane operations this can emit against slots. They are in
# NO_LEGACY_FORM -- there is no one-width-down encoding and prefix-stripping
# them produces bytes that decode to nothing -- but that set is about a
# TECHNIQUE, not about the semantics, which `lower.py` has emitted on the
# plain path since Finding 205 by carrying a rule per shape. Under the
# uniform representation the rule is a 16-byte move, because an upper half
# IS a slot: `lower.py` already writes `movaps shadow(%ymm1),%xmm0` and
# calls that path Y2. Finding 246.
# The shapes those mnemonics produce, which are emitted as slot moves and
# are therefore the exemption from NO_LEGACY_FORM. Named once so the guard
# and the shapes cannot drift apart.
SLOT_SHAPES = ("extract", "extractmem", "insert", "insertmem", "perm2",
               "bcastmem", "bcastreg", "permmem", "permil", "regmove",
               "lanemove", "lanemem")

# **A 256-bit register-to-register move, which is not arithmetic.** The
# refusal bucket called "a register-to-register move" holds three different
# things and only these are moves: 53 `vmovups`, 12 `vmovdqu` and 6
# `vmovaps`. The other 57 are `vcvtdq2ps` and `vcvtps2dq`, which CONVERT and
# so need a vector register, and 7 are `vpmovmskb`, which writes a
# general-purpose one. Finding 253.
# `vmovapd` and `vmovupd` were missing and are the same instruction with a
# different operand-size prefix; three sites were refused for it.
YMM_REGISTER_MOVES = frozenset(("vmovups", "vmovaps", "vmovupd", "vmovapd",
                                "vmovdqu", "vmovdqa"))

# **One source, one destination, and every element decided by itself.** An
# operation like this splits by half exactly the way the slot
# representation wants: the low half is the same instruction one width
# down, and the upper half is the source's slot run through a helper into
# the destination's. The destination's upper half is wholly overwritten, so
# unlike `lanereg` there is nothing to load first and one helper is enough.
#
# **Width-changing conversions are excluded and that is the whole risk
# here.** `vcvtps2pd` reads four floats from an xmm and writes four doubles
# to a ymm, `vcvtpd2ps` the reverse: the halves do not correspond and
# splitting by half is meaningless. Every member below keeps its element
# count and width, so half the elements are half the work.
#
# Of these, `vcvtdq2ps` (45), `vcvtps2dq` (12) and `vrcpps` (2) occur in
# Starfield; the rest are here because the same argument covers them
# exactly. `vptest` is deliberately absent -- it writes FLAGS, and a stub
# may not, which is the constraint `encode_tls_base` is built around.
# Finding 285.
LANE_UNARY = frozenset(("vcvtdq2ps", "vcvtps2dq", "vcvttps2dq",
                        "vrcpps", "vrsqrtps", "vsqrtps", "vsqrtpd"))

# **Operations whose operands may be exchanged with no change to the bytes
# produced.** `op %ymmD,%ymmS,%ymmD` computes `D = S op D`, and SSE's
# two-operand form computes `dst = dst op src` -- so for these the SSE form
# IS the wanted value with the sources read the other way round, needing no
# scratch and no extra move. For everything else it is a different value.
#
# **Floating-point add and multiply are deliberately absent.** They are
# commutative in arithmetic and not in x86: with two NaN operands the result
# carries the FIRST source's payload, so exchanging them changes the bytes.
# That is 30 of the 72 sites this set could otherwise reach -- see Finding
# 284 -- and it is the copyright holder's call rather than one to take while
# in the file, because this project is bit-exact by rule (Finding 4).
#
# FP min and max are absent for a stronger reason: they are defined
# asymmetrically on NaN and on signed zero, so they are not commutative at
# all. Integer min and max have neither hazard.
COMMUTATIVE_YMM = frozenset((
	"vpaddb", "vpaddw", "vpaddd", "vpaddq",
	"vpmullw", "vpmulld", "vpmulhw", "vpmulhuw", "vpmuludq", "vpmuldq",
	"vpand", "vpor", "vpxor",
	"vandps", "vandpd", "vorps", "vorpd", "vxorps", "vxorpd",
	"vpcmpeqb", "vpcmpeqw", "vpcmpeqd", "vpcmpeqq",
	"vpminsb", "vpminsw", "vpminsd", "vpminub", "vpminuw", "vpminud",
	"vpmaxsb", "vpmaxsw", "vpmaxsd", "vpmaxub", "vpmaxuw", "vpmaxud",
	"vpavgb", "vpavgw",
))

# **Member kinds that put no value in a vector register.** A `load` moves an
# upper half through one and a `lanereg3` needs two; these four move a half
# straight between a machine register and its slot, or emit a constant, and
# want nothing of their own. Naming them is what lets the collector ASK
# whether a helper is needed rather than assume it -- which it did, at 1,704
# windows of which only 49 had no member wanting one. Finding 250.
HELPER_FREE = frozenset(("plain", "insert", "bcastmem", "bcastreg",
                         "extract"))

# **Kinds a general-purpose register can move instead.** Each of these puts
# sixteen bytes between memory and a slot and does nothing to them on the
# way, so two 8-byte `mov`s stand in for a vector round trip. The arithmetic
# shapes are absent on purpose: a packed operation has to happen in a vector
# register whatever else is free. Finding 251.
GPR_MOVABLE = frozenset(("load", "store", "regmove"))

# **Shapes wanting TWO vector registers**, which decides how many a
# non-volatile borrow has to find. `lanereg` and `lanereg3` move both
# sources' upper halves into registers before operating; `perm2` and
# `permil` do the same. Finding 255.
TWO_HELPERS = frozenset(("lanereg", "lanereg3", "perm2", "permil", "blendv",
                         "immreg3"))

SLOT_LANE_FORMS = ("vextractf128", "vextracti128",
                   "vinsertf128", "vinserti128",
                   "vperm2f128", "vperm2i128",
                   "vbroadcastss", "vbroadcastsd", "vpbroadcastd",
                   "vpermq", "vpermpd", "vpermilps")


def lower_ymm_run(strategy, at, pool):
	"""The run, with every 256-bit copy split and everything else moved."""
	_helpers, entries = strategy[0], strategy[1]
	body = bytearray()
	# The second field is the helper this load or store uses, resolved per
	# entry when the run was collected. It used to be the ymm register, with
	# the helper looked up from it -- which cannot express one register
	# holding two values in one run. See `lifetimes`.
	for kind, helper, vex, tail, address, length, moved in entries:
		if kind == "plain":
			fixed = moved_instruction(moved, at + len(body), pool)
			if fixed is None:
				return None
			body += fixed
			continue
		if kind == "extract":
			# The upper half is already in a register: hand it over. The
			# destination is the encoding's `rm` field and the source its
			# `reg` field, which is the opposite way round from every other
			# instruction here -- `vextractf128` stores to r/m.
			body += encode_movaps((vex["B"] << 3) | (tail[1] & 7), helper)
			continue
		high_vex, high_tail = retarget(vex, tail, helper)
		for one_vex, one_tail, delta in ((vex, tail, 0),
		                                 (high_vex, high_tail, 16)):
			piece = narrow_piece(one_vex, one_tail, delta, address, length,
			                     at + len(body))
			if piece is None:
				return None
			body += piece
	return bytes(body)


def span_shape_name(encoding, operands):
	"""What shape a 256-bit instruction is, as a label.

	`span_operand_shape` answers whether the lowering can emit one, which
	is a yes or a no; this names the shape whatever the answer, so that the
	refusals can be ranked. Building the next increment means picking from
	this histogram rather than from a guess about which form is common.

	The three the lowering emits today come back as "load", "store" and
	"lane mem,D,D". Everything else is named by what would have to be built
	for it.
	"""
	vex = inplace.decode_vex(encoding)
	if vex is None or not vex["L"]:
		return None
	fields = inplace.split_operands(operands or "")
	if not fields:
		return "no operands"
	wide = [f for f in fields if f.startswith("%ymm")]
	immediate = [f for f in fields if f.startswith("$")]
	if len(fields) == 2 and len(wide) == 1:
		if "(" in fields[0]:
			return "load"
		if "(" in fields[1]:
			return "store"
		return "a register-to-register move"
	if len(fields) == 2 and len(wide) == 2:
		return "a register-to-register move"
	if len(fields) == 2:
		return "a broadcast or a narrowing move"
	if len(fields) == 3 and immediate:
		return "an immediate form"
	if len(fields) == 3 and len(wide) == 2 and "(" in fields[0]:
		if fields[1] == fields[2]:
			return "lane mem,D,D"
		return "mem,S,D with a destination of its own"
	if len(fields) == 3 and len(wide) == 3:
		# **Split by WHICH source is the destination**, because only one of
		# them is what the lowering emits. `op %ymmS,%ymmD,%ymmD` has src1
		# as the destination and is the SSE two-operand form with the
		# prefix dropped; `op %ymmD,%ymmS,%ymmD` has src2 as the
		# destination, which is the aliasing case `lower_vex` needs a
		# scratch for and this does not build. Lumping them together would
		# make `SPAN_EMITTABLE` claim a shape that is not emitted.
		if fields[1] == fields[2]:
			return "a register second source, src1 is D"
		if fields[0] != fields[2] and fields[1] != fields[2]:
			return "a register second source, D of its own"
		return "a register second source, src2 is D"
	if len(fields) == 4:
		return "four operands -- an insert, a blend or an FMA"
	return "some other shape"


# The shapes `lower_ymm_span` can emit today. Named here rather than
# inferred, so that the survey and the lowering cannot drift apart about
# what is built.
SPAN_EMITTABLE = frozenset(("load", "store", "lane mem,D,D",
                            "a register second source, src1 is D",
                            "a register second source, D of its own",
                            "an immediate form"))


def region_start(instructions, index, blocked, limit=192):
	"""Where this site's call-free region begins, or None if it cannot be
	found within `limit` instructions.

	**A region begins where every upper half is known to be dead**, and
	Win64 says exactly where that is: the upper half of every ymm is
	volatile across a call, so the instruction after one starts a region.
	So does a branch target, because control can arrive there from a path
	this walk did not take, and so does the first instruction of a
	function.

	This is the unit the whole-function rewrite actually operates on. A
	whole function is the wrong frame: it can contain calls, and a value
	cannot live across one anyway. A call-free region is the largest
	stretch over which an upper half can be represented at all.
	"""
	address = instructions[index][0]
	at = index
	while at > 0 and index - at < limit:
		previous = instructions[at - 1]
		if previous[2].startswith(CONTROL_PREFIXES):
			return at		# the instruction after a transfer
		if instructions[at][0] in blocked:
			return at		# anything can branch here
		if previous[0] + len(previous[1]) != instructions[at][0]:
			return at		# a gap: the listing does not join them
		at -= 1
	return at if index - at < limit else None


def region_boundary(instructions, first, blocked):
	"""What kind of edge a region begins at, as a label.

	`region_start` stops at ANY control transfer, and only one of them
	carries the ABI argument the region rests on: **the upper half of every
	ymm is volatile across a CALL**, and across nothing else. After a
	conditional branch, or at a target something jumps to, ymm values flow
	in with their upper halves live and a region cannot see where they came
	from.

	That difference decides whether "reads a ymm defined outside the
	region" is a hard bound or a conservatism, and Finding 172 measured it
	at 5,397 refusals -- the largest single number in the whole region
	machinery. Which edge they sit behind is the question, so it is asked
	rather than assumed.
	"""
	if first == 0:
		return "at the listing's start"
	if instructions[first][0] in blocked:
		return "at a branch target"
	previous = instructions[first - 1]
	if previous[0] + len(previous[1]) != instructions[first][0]:
		return "after a gap"
	if previous[2].startswith("call"):
		return "after a call"
	if previous[2].startswith("ret"):
		return "after a return"
	return "after a jump"


def region_defines(instructions, first, index):
	"""The ymm registers written by a 256-bit instruction in
	`[first, index)`, which is where an upper half may have come from.

	**Only a 256-bit write defines an upper half.** A VEX.128 write ZEROES
	bits [255:128], so it defines the upper half too -- as zero -- and that
	is representable; but the in-place lowerings have already destroyed
	that zeroing, which is what Finding 40 named and what makes a narrower
	write a definition this cannot trust. It is counted separately.
	"""
	wide, narrow = set(), set()
	for position in range(first, index):
		_a, encoding, _m, operands = instructions[position][:4]
		vex = inplace.decode_vex(encoding)
		if vex is None:
			continue
		fields = inplace.split_operands(operands or "")
		if not fields:
			continue
		destination = fields[-1]
		if not destination.startswith("%ymm") and not destination.startswith("%xmm"):
			continue
		(wide if vex["L"] else narrow).add(canonical_ymm(destination))
	return wide, narrow


def region_reachable(instructions, index, blocked):
	"""Why a region-based rewrite could not take this site, or None if it
	could.

	The question a whole-function rewrite has to answer, asked per site:
	**is every ymm this instruction READS defined by a 256-bit write since
	the region began?** If it is, the upper half is something the region
	itself computed and can therefore be kept in a slot; if it is not, the
	value arrived from somewhere no representation covers.

	Nothing here is emitted. This is the measurement that decides whether
	the design is worth building, which is what Finding 133 said to take
	before starting it and what this project has got wrong on this item
	three times by pricing capacity instead of reach.
	"""
	first = region_start(instructions, index, blocked)
	if first is None:
		return "the region start is further than the walk looks"
	_a, encoding, _m, operands = instructions[index][:4]
	vex = inplace.decode_vex(encoding)
	if vex is None or not vex["L"]:
		return "not a 256-bit site"
	fields = inplace.split_operands(operands or "")
	read = [f for f in fields[:-1] if f.startswith("%ymm")]
	# A destination that is also a source is read. `vaddps a,%ymm1,%ymm0`
	# reads ymm1 and writes ymm0; `vaddps a,%ymm0,%ymm0` reads and writes
	# the same one.
	wide, narrow = region_defines(instructions, first, index)
	for field in read:
		name = canonical_ymm(field)
		if name in wide:
			continue
		if name in narrow:
			return "the value's last write was 128-bit, so its upper half " \
				"is a zeroing the lowering already destroyed"
		return "the value is not defined in its own region"
	return None


def region_end(instructions, index, blocked, limit=192):
	"""Where this site's call-free region ends, exclusive.

	The mirror of `region_start`: a call ends a region because the ABI
	kills every upper half there, and a branch target ends one because
	control can leave and arrive by a route this walk did not take.
	"""
	at = index
	while at < len(instructions) and at - index < limit:
		address, encoding, mnemonic, _o = instructions[at][:4]
		if at > index and address in blocked:
			return at
		if mnemonic.startswith(CONTROL_PREFIXES):
			return at + 1		# the transfer itself is the last member
		following = at + 1
		if following < len(instructions) \
				and instructions[following][0] != address + len(encoding):
			return following
		at = following
	return at


def region_demand(instructions, first, last):
	"""`(peak, registers)` -- how many upper halves are live at once.

	The peak of the intervals and not the count of the registers, which is
	`ymm_span`'s distinction and the reason it is computed the same way: a
	region that defines a value, kills it, and defines another needs one
	slot and reuses it. Counting registers said two where one was wanted.

	A register's interval runs from its first 256-bit write to its last
	read of any width, because a narrower read still consumes the value
	the slot is standing in for.
	"""
	live = {}
	for position in range(first, last):
		_a, encoding, _m, operands = instructions[position][:4]
		operands = operands or ""
		vex = inplace.decode_vex(encoding)
		fields = inplace.split_operands(operands)
		for field in fields:
			if not field.startswith("%ymm"):
				continue
			name = canonical_ymm(field)
			if name in live:
				live[name][1] = position
		if vex is None or not vex["L"] or not fields:
			continue
		destination = fields[-1]
		if destination.startswith("%ymm"):
			name = canonical_ymm(destination)
			live.setdefault(name, [position, position])[1] = position
	peak = 0
	for point in range(first, last):
		peak = max(peak, sum(1 for begin, end in live.values()
		                     if begin <= point <= end))
	return peak, frozenset(live)


def span_operand_shape(vex, tail, operands, tracked, mnemonic=None):
	"""`("load"|"store"|"lane", register)` if this member is one this can
	emit, else None.

	**The first increment deliberately handles one arithmetic shape**: an
	operation whose only ymm operand is its own destination, with the other
	source in memory. That is `op mem,%ymmD,%ymmD`, and it is the shape SSE
	can express by dropping the prefix -- two operands, destination read and
	written. Anything with a second ymm SOURCE needs that source's slot as
	a memory operand of the operation itself, which is a different encoding
	problem and is not built here.

	A span containing a shape this refuses is not lowered at all rather
	than lowered in part: a span is a representation, and half of one is a
	program that reads an upper half nobody wrote.
	"""
	fields = inplace.split_operands(operands or "")
	wide = [f for f in fields if f.startswith("%ymm")]
	# **The lane operations, first, so they cannot fall through.** Left to
	# the shapes below, `vbroadcastss (%rax),%ymm0` reads as a `load` and
	# would be prefix-stripped into nothing -- which is why NO_LEGACY_FORM
	# exists. These four are different: each is a pure 128-bit half move
	# once the halves are separately addressable, which is exactly what a
	# permanent slot makes them.
	#
	# **Only under `--shadow-regs=all`, and that is soundness rather than
	# caution.** `extract` READS the source's upper half from its slot, and
	# only the uniform representation promises that slot is maintained; a
	# span-local table may not track the source at all.
	#
	# **Only `$0x1` and only registers**, because that is the population:
	# in Starfield, 362 of 383 `vextractf128` and 141 of 157 `vinsertf128`
	# are register forms with that immediate, and every `vextracti128` and
	# `vinserti128` is. A memory form is refused rather than guessed at.
	if SHADOW_REGS_RULE == SHADOW_REGS_ALL and mnemonic in SLOT_LANE_FORMS:
		if mnemonic in ("vextractf128", "vextracti128"):
			if len(fields) == 3 and fields[0] == "$0x1":
				if fields[2].startswith("%xmm"):
					return ("extract", ymm_alias(fields[2]),
					        canonical_ymm(fields[1]))
				# **To MEMORY, which needs no zeroing.** The register form
				# writes %xmmD with a VEX.128 instruction and so must zero
				# D's slot; this one writes sixteen bytes of memory and
				# touches no ymm at all, so the only half in play is the
				# source's. 21 of Starfield's 383.
				if "(" in fields[2] and fields[1].startswith("%ymm"):
					return ("extractmem", canonical_ymm(fields[1]))
			return None
		if mnemonic == "vpermilps":
			# **In-lane, which is the whole reason it is here.** Each
			# 128-bit half is permuted by its own half of the control and
			# neither reaches across, so the 256-bit form is exactly two
			# of the 128-bit one -- `lower_permilps`, twice. The
			# cross-lane variable permute is `vpermd`, and it is a
			# different problem.
			#
			# Operand order is control, data, destination: VEX.vvvv holds
			# the DATA and r/m the CONTROL, which is the opposite way
			# round from `vpermd`. See src/permil.h, which decoded a real
			# site to settle it.
			#
			# Only the variable form reaches here; the immediate one is a
			# `shufps` that the ordinary path already takes.
			if (len(fields) == 3 and fields[0].startswith("%ymm")
					and fields[1].startswith("%ymm")
					and fields[2].startswith("%ymm")):
				return ("permil", canonical_ymm(fields[2]),
				        canonical_ymm(fields[1]), canonical_ymm(fields[0]))
			return None
		if mnemonic in ("vpermq", "vpermpd"):
			# **A cross-lane 64-bit permute whose source is MEMORY**, which
			# is what makes it easy rather than hard: every quadword of the
			# source has its own address, so each output quadword is a
			# 64-bit load and no shuffle unit is involved at all. Two bits
			# of the immediate choose each one.
			#
			# The register-source form is not this: it would have to reach
			# a quadword inside a machine xmm, and is not built.
			if (len(fields) == 3 and fields[0].startswith("$")
					and "(" in fields[1]
					and fields[2].startswith("%ymm")):
				return ("permmem", canonical_ymm(fields[2]))
			return None
		if mnemonic in ("vbroadcastss", "vbroadcastsd", "vpbroadcastd"):
			# **A broadcast makes both halves the same 128 bits**, so
			# under this representation it is the ordinary SSE broadcast
			# followed by a copy of the result into the slot. `lower.py`
			# has emitted the 128-bit half since Finding 205 -- "a
			# broadcast is `movss` plus `shufps $0`" -- and the second
			# half is that same register stored once more.
			if len(fields) != 2 or not fields[1].startswith("%ymm"):
				return None
			if fields[0].startswith("%xmm"):
				return ("bcastreg", canonical_ymm(fields[1]),
				        ymm_alias(fields[0]))
			if "(" in fields[0]:
				return ("bcastmem", canonical_ymm(fields[1]))
			return None
		if mnemonic in ("vperm2f128", "vperm2i128"):
			# **Pure 128-bit lane selection**, which `lower.py` has said
			# since Finding 205 becomes moves "once halves are split" --
			# and a permanent slot is exactly that split. The immediate
			# picks each output half from one of the four input halves, or
			# zeroes it, and is read at emit time rather than carried in
			# the shape so that every shape here stays a list of
			# registers. AT&T order is src2, src1, dst.
			if (len(fields) == 4 and fields[1].startswith("%ymm")
					and fields[2].startswith("%ymm")
					and fields[3].startswith("%ymm")):
				return ("perm2", canonical_ymm(fields[3]),
				        canonical_ymm(fields[1]), canonical_ymm(fields[2]))
			return None
		if len(fields) == 4 and fields[0] == "$0x1" \
				and fields[2].startswith("%ymm") \
				and fields[3].startswith("%ymm"):
			if fields[1].startswith("%xmm"):
				return ("insert", canonical_ymm(fields[3]),
				        ymm_alias(fields[1]), canonical_ymm(fields[2]))
			# **FROM memory**: sixteen bytes read straight into the
			# destination's slot. 16 of Starfield's 157.
			if "(" in fields[1]:
				return ("insertmem", canonical_ymm(fields[3]),
				        canonical_ymm(fields[2]))
		return None
	# **A 256-bit register-to-register move**, which is a move and not
	# arithmetic: the low half is the same instruction one width down and
	# the upper half is sixteen bytes from one slot to another. It needs
	# the permanent slots, so it is gated with them -- and it sits at THIS
	# level rather than inside the lane block above, which is keyed on
	# `SLOT_LANE_FORMS` and so could never have reached a `vmovups`. The
	# first draft was written inside it and could not fire at all, which
	# the fixture caught and nothing else would have. Finding 253.
	if SHADOW_REGS_RULE == SHADOW_REGS_ALL \
			and mnemonic in YMM_REGISTER_MOVES and len(fields) == 2 \
			and len(wide) == 2:
		return ("regmove", canonical_ymm(fields[1]),
		        canonical_ymm(fields[0]))
	# **The same shape with the bytes transformed on the way.** See
	# `LANE_UNARY`: one source, one destination, every element decided by
	# itself, so the upper half is the source's slot through a helper.
	# Finding 285.
	if SHADOW_REGS_RULE == SHADOW_REGS_ALL \
			and mnemonic in LANE_UNARY and len(fields) == 2 \
			and len(wide) == 2:
		return ("lanemove", canonical_ymm(fields[1]),
		        canonical_ymm(fields[0]))
	if len(fields) == 2 and len(wide) == 1:
		if "(" in fields[0] and wide[0] == fields[1]:
			return ("load", canonical_ymm(fields[1]))
		if "(" in fields[1] and wide[0] == fields[0]:
			return ("store", canonical_ymm(fields[0]))
		return None
	if len(fields) == 3 and len(wide) == 2 and "(" in fields[0] \
			and fields[1] != fields[2]:
		# **`op mem,%ymmS1,%ymmD` with a destination of its own.** The same
		# shape as `lane` below except that src1 is not the destination, so
		# SSE's two-operand form needs the source copied into the
		# destination first -- `movaps S1,D; op mem,D` -- which is what
		# `lower_vex` does for a Class C site one width down. The upper
		# half is the same: S1's slot into the helper, the operation
		# against memory plus sixteen, the helper into D's slot.
		#
		# 296 refusals in Starfield, of which 61 have a helper and a block
		# -- 53 of those only because a non-volatile borrow exists.
		# Finding 257.
		return ("lanemem", canonical_ymm(fields[2]), canonical_ymm(fields[1]))
	if len(fields) == 3 and len(wide) == 2 and "(" in fields[0] \
			and fields[1] == fields[2]:
		# `op mem,%ymmD,%ymmD` -- src1 IS the destination, so the SSE form
		# is the prefix dropped and nothing rearranged.
		return ("lane", canonical_ymm(fields[2]))
	if len(fields) == 4 and len(wide) == 3 and fields[0].startswith("$"):
		# **`op $imm,%ymmS2,%ymmS1,%ymmD`** -- `lanereg3` with an
		# immediate, and per-lane for the same reason the three-operand
		# immediates are: `vshufps` and `vpblendw` apply the same imm8
		# within each 128-bit lane independently. 95 and 2 of the 111
		# sites in this bucket.
		#
		# **The other 14 are excluded by requiring an immediate**, and
		# that is the point rather than an accident: `vblendvps` and
		# `vblendvpd` carry a REGISTER mask in the fourth operand, and
		# SSE's `blendvps` takes that mask only in the implicit `xmm0`,
		# which is a different lowering and is not built here. An FMA in
		# this bucket is refused by NO_LEGACY_FORM before reaching it.
		# Finding 273.
		return ("immreg3", canonical_ymm(fields[3]),
		        canonical_ymm(fields[1]), canonical_ymm(fields[2]))
	if len(fields) == 4 and len(wide) == 4:
		# **`vblendvps %ymmM,%ymmS2,%ymmS1,%ymmD`** -- four ymm and no
		# immediate, the case the note above held out. The mask is a
		# REGISTER and SSE's `blendvps` reads it only from the implicit
		# `xmm0`, so the lowering has to marshal it there and give back
		# whatever `xmm0` held. That is the whole of the difficulty and
		# it is why this waited: the sites are
		# `%ymm4,%ymm1,%ymm0,%ymm1`, so `ymm0` is SRC1 -- refusing
		# whenever `xmm0` is involved would refuse every one of them,
		# and the save has to come first with the operands then read
		# from the saved copy.
		#
		# Four slots, which is one more than any other shape: the
		# destination's, both sources' and the mask's. Finding 307.
		return ("blendv", canonical_ymm(fields[3]),
		        canonical_ymm(fields[1]), canonical_ymm(fields[2]),
		        canonical_ymm(fields[0]))
	if len(fields) == 3 and len(wide) == 2 and fields[0].startswith("$"):
		# **`op $imm,%ymmS,%ymmD` -- an in-lane operation with an
		# immediate.** Every one of the 108 in Starfield operates within
		# each 128-bit lane, so both halves take the SAME immediate
		# unchanged: 104 shifts, two `vroundps` and two `vpshufd`. The
		# cross-lane immediates -- `vperm2f128`, `vpermq`, `vpermilps` --
		# are held out by NO_LEGACY_FORM and this shape is deliberately
		# NOT in SLOT_SHAPES, so they stay refused rather than reaching
		# here and being split per lane, which would be wrong.
		#
		# **Two narrowings, and the opcode is what tells them apart.**
		# `0F 71/72/73` is the immediate-shift group: ModRM.reg is an
		# opcode extension and `vvvv` carries the DESTINATION, so the SSE
		# form puts the destination in r/m and the operands move.
		# Everything else uses ModRM.reg as a register and the prefix
		# strips directly. `vvvv` cannot be the discriminator, because
		# `decode_vex` normalises the inverted field and an unused vvvv
		# is indistinguishable from register 0 -- `vpslld $2,%ymm1,%ymm0`
		# would read as the non-destructive form and be emitted wrong.
		# Finding 271.
		return ("immreg", canonical_ymm(fields[2]),
		        canonical_ymm(fields[1]))
	if len(fields) == 3 and len(wide) == 3 and fields[1] == fields[2]:
		# `op %ymmS,%ymmD,%ymmD` -- the second source is a REGISTER, so its
		# upper half is in a slot of its own and the operation has to reach
		# it there. That is `slot_tail`'s reason for existing. Finding 152.
		return ("lanereg", canonical_ymm(fields[2]),
		        canonical_ymm(fields[0]))
	if len(fields) == 3 and len(wide) == 3 and fields[0] == fields[2] \
			and mnemonic in COMMUTATIVE_YMM:
		# **`op %ymmD,%ymmS,%ymmD` -- the destination is the OTHER
		# source.** `lower_vex` needs a scratch for this and the slot path
		# refused it outright, which was 82 sites. Where the operation
		# commutes it needs neither: the same `lanereg` emission serves,
		# with the source taken from `vvvv` rather than from ModRM.rm, and
		# `commuted_piece` writes the low half. Finding 284.
		return ("lanereg", canonical_ymm(fields[2]),
		        canonical_ymm(fields[1]))
	if len(fields) == 3 and len(wide) == 3 and fields[0] == fields[2] \
			and inplace.has_direct_sse_form(mnemonic):
		# **`op %ymmD,%ymmS,%ymmD` where the operation does NOT commute.**
		# The branch above serves this shape by exchanging the sources, which
		# only an operation like `vpaddd` or `vxorps` permits. `vsubps` may
		# not be exchanged at all, and FP add and multiply may not either --
		# not arithmetically, but because exchanging them changes which NaN
		# payload propagates, which is a semantic deviation nobody asked for.
		#
		# So the operand order is KEPT and the destination's own value is
		# moved aside first, which needs somewhere to put it. `lower_vex`
		# wants a scratch REGISTER for this and 35 of Starfield's 39 sites
		# have none; the emission below wants none, because the helper the
		# span already owns serves as the temporary for the low half and is
		# reloaded from a slot for the upper.
		#
		# ONE helper, so this is deliberately NOT in TWO_HELPERS: the upper
		# half reads the destination's slot as an OPERAND rather than moving
		# it into a second register, which is what `lanereg` spends its
		# second helper on. That costs an alignment requirement the image has
		# to declare -- see `slot_arithmetic_safe` -- and buys the shape a
		# register budget `lanereg` cannot meet.
		#
		# Reached only after the two branches above, so `fields[1]` is a
		# different register from `fields[2]` and the three-alike case
		# `op %ymmD,%ymmD,%ymmD` has already gone to `lanereg`, where
		# dropping the prefix is right. Finding 312.
		return ("lanealias", canonical_ymm(fields[2]),
		        canonical_ymm(fields[1]))
	if len(fields) == 3 and len(wide) == 3 and fields[0] != fields[2]:
		# `op %ymmS2,%ymmS1,%ymmD` with a destination of its own, which is
		# the largest shape Finding 150 counted and the one the region
		# reaches that no span could. SSE has no three-operand form, so
		# both halves become a move and an operation -- which is exactly
		# what `lower_vex` does for a Class C site, one width down.
		# Finding 158.
		return ("lanereg3", canonical_ymm(fields[2]),
		        canonical_ymm(fields[0]), canonical_ymm(fields[1]))
	return None


def slot_tail(register, base, slot, block=None):
	"""modrm (and SIB) addressing a slot, with modrm.reg = `register`.

	The same address `span_slot_move` writes, built as a TAIL so that
	`sse_encoding` can put any opcode in front of it -- which is what makes
	an upper half an OPERAND of the operation rather than only something
	moved in and out. That is the whole of what the register-second-source
	shape needed: `op slot(%base),%xmmH` instead of a load, an operation
	and a store.

	`(%rsp)` needs a SIB byte because rm=100 is how the encoding says "a
	base register follows"; a block register is named in rm directly. In
	both cases a disp32, for `encode_tls_spill`'s reason -- the block runs
	to kilobytes and a frame's slot can sit a whole frame up.

	**It is NOT safe as the operand of a packed arithmetic instruction**,
	which is what it was written for and what it cannot do. SSE requires a
	memory operand to be 16-byte aligned and nothing aligns a slot: Win64
	guarantees `rsp` at a call boundary and says nothing in between, which
	is why every slot move here is a `movups`. `lower_ymm_span` moves the
	value into a second helper instead. Kept because the addressing is
	right and a caller that can guarantee alignment could use it; nothing
	does today.
	"""
	offset = base + slot * SLOT
	if block is None:
		return bytes([0x80 | ((register & 7) << 3) | 4, 0x24]) \
			+ struct.pack("<i", offset)
	return bytes([0x80 | ((register & 7) << 3) | (block & 7)]) \
		+ struct.pack("<i", offset)


def span_entries(members, instructions, slots, scope, plain):
	"""The span's members resolved to bytes, as `build_stub` needs them.

	`lower_ymm_span` is handed this rather than the listing, for
	`lower_ymm_run`'s reason: a stub is built long after the collector
	walked, and a strategy that carried positions would have to carry the
	listing with them.
	"""
	out = []
	for kind, position, register in members:
		address, encoding, mnemonic, operands, comment = instructions[position]
		moved = None
		if kind == "plain":
			moved = (address, encoding, comment, operands, mnemonic,
			         swallowed_scratch(plain, position, address, encoding,
			                           operands, mnemonic, scope))
		# A register-second-source operation needs TWO slots: its
		# destination's, and the one it reads from. The second is resolved
		# here because `build_stub` has no operand text to look it up with.
		second = third = fourth = None
		vex = inplace.decode_vex(encoding)
		if vex is not None and vex["L"]:
			shape = span_operand_shape(vex, encoding[vex["length"]:],
			                           operands, None, mnemonic)
			if shape is not None and shape[0] in ("lanereg", "lanereg3",
			                                      "extract", "perm2",
			                                      "permil", "regmove",
			                                      "lanemove", "lanemem",
			                                      "immreg", "immreg3",
			                                      "blendv", "lanealias"):
				second = slot_for(slots, shape[2])
			# `lanereg3` reads TWO slots and writes a third, so the first
			# source's is resolved here too. `build_stub` has no operand
			# text to look either of them up with. `perm2` is the same
			# shape: it may read either half of either source.
			if shape is not None and shape[0] in ("lanereg3", "perm2",
			                                      "permil", "immreg3",
			                                      "blendv"):
				third = slot_for(slots, shape[3])
			# **A fourth, for `blendv` alone.** Every other shape reads
			# at most two sources; a variable blend reads two and a
			# mask. Threading one more field is two edits because the
			# tuple has exactly one construction and one unpack.
			# Finding 307.
			if shape is not None and shape[0] == "blendv":
				fourth = slot_for(slots, shape[4])
		out.append((kind, address, encoding, mnemonic, operands,
		            slot_for(slots, register), moved, second, third,
		            fourth))
	return out


# **How many slots a per-thread span may use.** One number for the whole
# image, because `SizeOfZeroFill` is one number: the block has to be big
# enough for the largest thing that will ever address it. A borrow spill
# wants one slot and a span wants its peak, and the two never overlap in
# time -- a stub runs to completion before another is entered on the same
# thread -- so they share the area rather than each needing their own.
# **Four, and raising it was measured to buy nothing.** Finding 148's slot
# histogram says regions wanting five to eight upper halves at once are 585
# sites, so eight looked like the obvious turn of the dial. It changed the
# binary not at all -- the regions this offers are three to twelve
# instructions long and rarely hold five distinct values. Kept at four
# because a bigger `SizeOfZeroFill` for no sites is a cost with no return.
# Finding 157.
TLS_SLOTS = 4

# **Sixteen permanent slots, one per ymm, which is the uniform
# representation.** A span's slot table is LOCAL to the span, so a member
# reading a register the span does not track gets `None` and the operation
# is refused -- `lanereg second source is in no slot`. That single refusal
# is what 1,875 "arithmetic rather than a copy" sites and 5,383 of 5,580
# unrepresentable regions come down to: the value's upper half exists
# nowhere the lowering can address.
#
# Give every register a slot that outlives every span and the question
# stops being asked. Nothing has to be proved about where a value came
# from, which is the whole purpose of the provenance walk.
#
# The price is real: sixteen ymm cannot be sixteen xmm pairs, so the upper
# halves live in memory permanently, and the representation is only
# coherent if EVERY writer maintains its slot. Finding 244.
#
# **It is the default since 2026-09-18, on the copyright holder's
# instruction and on this measurement**: the shipped build left 5,691 VEX
# in `.text` and this leaves 3,114, for 894 KB more image on 112 MB --
# 2,577 sites for eight tenths of a percent. 5,398 of the old default's
# 5,691 refusals were a single class, "reads a ymm defined outside the
# region", which a permanent slot dissolves by construction; nothing else
# in that census was above 311.
#
# **What was NOT measured is runtime**, and for a game that is the number
# that decides it: every lowered site reaches its upper half through
# `gs:[0x58]`, an index and a load, where the old default kept more of
# them in registers. This host has no AVX and nothing here runs the game,
# so the trade was taken on size and correctness with that gap stated
# rather than closed. `--shadow-regs=off` stays reachable as the A/B, the
# same way `--spill=home` stays beside `--spill=tls`. Finding 287.
SHADOW_REGS = 16
SHADOW_REGS_OFF, SHADOW_REGS_ALL = "off", "all"
SHADOW_REGS_RULE = SHADOW_REGS_ALL


def tls_block_slots():
	"""How many slots the per-thread block must hold."""
	return TLS_SLOTS + (SHADOW_REGS if SHADOW_REGS_RULE == SHADOW_REGS_ALL else 0)


def shadow_index(register):
	"""The permanent slot index for `%ymmN`, past the transient ones."""
	# A `plain` passenger names no register, and `slot_for` asks about
	# every member. `slots.get(None)` answered None; this has to too.
	if register is None:
		return None
	name = canonical_ymm(register)
	if name is None or not name.startswith("%ymm"):
		return None
	try:
		number = int(name[len("%ymm"):])
	except ValueError:
		return None
	return TLS_SLOTS + number if 0 <= number < SHADOW_REGS else None


def slot_for(slots, register):
	"""`slots`'s answer, or the register's permanent slot when shadows are on.

	The one place the uniform representation differs from the span's own
	bookkeeping, so that `lower_ymm_span` needs no change: it already knows
	how to operate between a slot and a helper.
	"""
	found = slots.get(register)
	if found is not None or SHADOW_REGS_RULE != SHADOW_REGS_ALL:
		return found
	return shadow_index(register)


def encode_gpr_at(register, save, base_register, offset):
	"""`mov` a 64-bit register to or from `offset(%base)`, disp32.

	`base_register` is None for `(%rsp)`, which needs a SIB byte because
	rm 100 is how the encoding says a base register follows.
	"""
	out = bytearray()
	out.append(0x48 | (0x04 if register >= 8 else 0)
	           | (0x01 if base_register is not None and base_register >= 8
	              else 0))
	out += b"\x89" if save else b"\x8b"
	if base_register is None:
		out.append(0x80 | ((register & 7) << 3) | 4)
		out.append(0x24)
	else:
		out.append(0x80 | ((register & 7) << 3) | (base_register & 7))
	out += struct.pack("<i", offset)
	return bytes(out)


def encode_mem64(register, save, vex, tail, address, encoding, at):
	"""A 64-bit `mov` reusing the original instruction's memory operand.

	`encode_mem`'s counterpart for general-purpose moves. It cannot be that
	function because a GPR move needs REX.W and an SSE one must not have
	it, and because the opcode pair is different: 8B loads, 89 stores.
	"""
	out = bytearray()
	out.append(0x48 | ((register >> 3) << 2) | (vex["X"] << 1) | vex["B"])
	out += b"\x89" if save else b"\x8b"
	out.append((tail[1] & 0xC7) | ((register & 7) << 3))
	out += tail[2:]
	if rip_relative(tail):
		old = struct.unpack_from("<i", out, len(out) - 4)[0]
		target = address + len(encoding) + old
		displacement = target - (at + len(out))
		if not -(1 << 31) <= displacement < (1 << 31):
			return None
		out[len(out) - 4:] = struct.pack("<i", displacement)
	return bytes(out)


def gpr_move_half(mover, to_slot, vex, tail, address, encoding, at, base,
                  slot, block, half):
	"""One 8-byte half of a 16-byte move, through a general-purpose register.

	**A 16-byte move needs no vector register.** `load`, `store` and the two
	memory lane forms put an upper half between memory and a slot and do
	nothing to it on the way, so a pair of 8-byte `mov`s does the same work
	as a vector round trip -- four instructions instead of two, and a GPR
	instead of an xmm. Measured: of 1,455 windows refused for want of a
	helper, 883 contain nothing but moves. Finding 251.

	The arithmetic shapes are not like this and never will be: `lanereg3`
	applies a packed operation, which has to happen in a vector register.

	`half` is 0 or 8. The memory side is the original operand advanced by
	`SLOT + half`, which for a RIP operand has to be done by hand because
	`offset_operand` refuses those -- it is not told where the stub put the
	instruction, and `encode_mem64` is.
	"""
	if rip_relative(tail):
		old = struct.unpack_from("<i", tail, 2)[0]
		moved = tail[:2] + struct.pack("<i", old + SLOT + half)
	else:
		moved = inplace.offset_operand(tail, SLOT + half)
		if moved is None:
			return None
	memory = encode_mem64(mover, not to_slot, vex, moved, address, encoding,
	                      at)
	if memory is None:
		return None
	slot_side = encode_gpr_at(mover, to_slot,
	                          block[0] if block is not None else None,
	                          base + slot * SLOT + half)
	return memory + slot_side if to_slot else slot_side + memory


def span_slot_zero(base, slot, block):
	"""Sixteen zero bytes into slot `slot`, using no vector register.

	**A VEX.128 write zeroes bits 255:128, and under this representation
	that is a slot.** The obvious emission is `xorps` a helper against
	itself and store it, and that is what this did -- which made every
	`extract` want an xmm for no reason but a constant. Two immediate
	stores write the same sixteen bytes and want nothing at all.

	Measured before it was written: `extract` is the only shape whose
	helper is used for a CONSTANT rather than for a value in flight, it
	wanted one at 333 windows, and `extract` alone is 290 of them.
	Finding 250.
	"""
	out = bytearray()
	for half in (0, 8):
		if block is None:
			# `movq $0,disp32(%rsp)` -- rm 100 says a SIB follows, and the
			# SIB names rsp with no index.
			out += b"\x48\xc7\x84\x24"
			out += struct.pack("<i", base + slot * SLOT + half)
		else:
			register = block[0]
			out.append(0x48 | (0x01 if register >= 8 else 0))
			out += b"\xc7"
			out.append(0x80 | (register & 7))	# mod 10, /0, disp32
			out += struct.pack("<i", base + slot * SLOT + half)
		out += struct.pack("<i", 0)
	return bytes(out)


def span_slot_op(prefix, opcode, reg, base, slot, block):
	"""`opcode <slot>,%xmm<reg>` -- arithmetic straight out of a slot.

	**A slot is memory, and an SSE arithmetic instruction takes memory as
	its source.** `span_slot_move` loads one into a register because a
	MOVE has to; an operand does not, and going through a register costs
	a register the span usually has not got. The first FMA emission
	loaded both halves and refused 66 windows for want of a second
	helper -- more than it lowered.

	Only the per-thread block, which addresses a slot as `disp32(%reg)`.
	The stack backing store reaches the same bytes three ways depending
	on `SPILL`, one of them RIP-relative, and an emitter that got that
	wrong would write arithmetic into a caller's frame; the caller
	refuses rather than guessing. A block register is never `rsp` or
	`r12`, so no SIB is needed -- they are drawn from VOLATILE_GPRS, the
	same property `encode_tls_base` relies on. Finding 300.
	"""
	if block is None:
		return None
	# **The alignment is the image's to declare and this is where it binds.**
	# A packed operation faults on an unaligned m128; the slot OFFSET is a
	# multiple of SLOT by construction and the BASE is whatever the loader
	# gave, bound only by the TLS directory. Refusing here costs a site and
	# emitting without it costs a fault on somebody else's thread.
	if not slot_arithmetic_safe():
		return None
	register = block[0]
	out = bytearray()
	if prefix is not None:
		out.append(prefix)
	rex = 0x40 | (0x04 if reg >= 8 else 0) | (0x01 if register >= 8 else 0)
	if rex != 0x40:
		out.append(rex)
	out += opcode
	out.append(0x80 | ((reg & 7) << 3) | (register & 7))	# mod 10, disp32
	out += struct.pack("<i", base + slot * SLOT)
	return bytes(out)


def span_slot_move(helper, save, base, slot, block, at):
	"""Move `helper` to or from slot `slot`, wherever the slots live.

	The two backing stores address a slot differently and nothing else
	about the span changes: `(%rsp)` plus a displacement for the home space
	and the caller's shadow, and a displacement from a general-purpose
	register for a per-thread block. Keeping that in one function is what
	stops the difference leaking into every member's emission.
	"""
	if block is None:
		return encode_spill(helper, save, at, 0, slot, base)
	return encode_tls_spill(helper, save, block[0], base + slot * SLOT)


# **Why a region the collector accepted was not emitted**, counted across a
# whole run. Module-level because `region_candidate` is called from inside
# `collect`'s loop and threading a counter through six call sites to answer
# a diagnostic question is how the loop's signature grows without end; it is
# cleared at the top of `collect`, so a run reports its own numbers and not
# the previous one's. Reported by `report_regions`.
REGION_REFUSED = Counter()
# **And a few addresses for each**, because a count says how big a cause is
# and never what it is. Finding 172 put 3,376 regions behind "reads a ymm
# defined outside the region, after a call" -- which is where the ABI says
# every upper half is dead, so the walk is missing a definition rather than
# the value arriving from outside. Which definition it misses is a question
# only an example answers.
REGION_EXAMPLES = {}
# **Every refused site, not a sample of six.** Whether a refused region's
# sites are LOST or merely taken by a cheaper strategy is the difference
# between 5,610 being a queue of work and being bookkeeping, and a sample of
# sixteen addresses cannot tell them apart. `apply` writes the whole list to
# `build/region-refused.txt` so it can be cross-checked against the image it
# just produced. Finding 172.
REGION_EXAMPLE_CAP = None


def lower_ymm_span(entries, base, helper, at, pool, block=None,
                   second_helper=None, reasons=None):
	"""The span, with every upper half kept in a 16-byte slot. Bytes or None.

	**The first thing here that emits 256-bit work rather than measuring
	it.** `ymm_span` has been analysis since Finding 133 and priced three
	times since; this is the lowering it was pricing.

	The shape is one rule applied per member: the low half is the original
	instruction with `VEX.L` cleared, acting on the real xmm the program
	already uses, and the upper half is the same operation performed
	between a slot and `helper`. A load fills both, a store empties both,
	and an operation reads the slot into `helper`, applies itself, and puts
	it back.

	`helper` is one register and not two, which is what confines this to
	operations whose second source is memory -- see `span_operand_shape`.

	**`reasons` names every refusal.** `region_members` says a region is
	representable and then this declines to emit it, which is two functions
	disagreeing about what is emittable -- the drift `SPAN_EMITTABLE`
	prevents between the survey and the lowering, and which nobody had
	prevented between the COLLECTOR and the lowering. It was the largest
	named filter left with its reason recorded nowhere, so the reason is
	recorded here and counted in `REGION_REFUSED`. Finding 171.
	"""
	def refuse(why):
		if reasons is not None:
			reasons.append(why)
		return None

	# **A permanent slot needs the per-thread block, and this is the one
	# place that can enforce it for every caller.** A slot index below
	# `TLS_SLOTS` is a span's own bookkeeping and the callee home space
	# holds it; an index at or above is a REGISTER's permanent slot under
	# `--shadow-regs=all`, and the home space is two slots wide. Addressing
	# slot 4 off it writes `base + 64` into somebody's locals -- silently,
	# because it does not fault. Checked here rather than in each of the
	# three candidate builders, so a fourth cannot reintroduce it.
	#
	# **It has not been seen to fire, and that is stated rather than
	# implied.** `region_candidate` routes to the block before reaching
	# here, and on every fixture in this tree -- with the routing
	# deliberately removed and `--spill` swept over home, none and stack --
	# the region is refused earlier, by `more slots than a store holds`.
	# So this is a floor for a builder that does not exist yet, not
	# evidence that anything is protected today: the routing is what
	# actually does the work. Finding 246.
	if block is None:
		for entry in entries:
			if any(x is not None and x >= TLS_SLOTS
			       for x in (entry[5], entry[7], entry[8])):
				return refuse("permanent slot needs the per-thread block")
	body = bytearray()
	if block is not None:
		# **Once, at the top.** The block pointer stays in its register for
		# the length of the span, which is what `window_gpr_free` had to
		# establish before the span was offered -- a pointer recomputed per
		# member would cost three instructions each and a pointer clobbered
		# mid-span would address somebody else's thread data.
		# **Three ways to stand the block pointer up**, and which one is
		# used is decided by the collector from what the site can supply.
		#
		#   False   two dead registers, clobbered and never put back
		#   True    one dead register; the index is stashed in an xmm
		#   "home"  none; BOTH are saved in the callee home space
		#
		# The helper doubles as the stash in the second, which is what
		# makes it cost nothing: the index is restored three instructions
		# later, before any member is emitted, so the register it borrows
		# is one the body has not started using.
		mode = block[3] if len(block) > 3 else False
		if len(block) > 6 and block[6] is not None:
			# The mover is a live register borrowed for the length of the
			# stub, saved beside the block's own borrows.
			body += encode_gpr_at(block[5], True, None, block[6])
		for register, where in (block[7] if len(block) > 7 else ()):
			# **A non-volatile xmm the enclosing function itself saves.**
			# `movups`, not `movaps`: nothing aligns the home space beyond
			# what the caller's own frame happened to give it, which is
			# `encode_spill`'s argument and the same one. Finding 255.
			body += encode_spill(register, True, at + len(body), 0, 0,
			                     where)
		if mode in ("home", "teb"):
			# The block's own save comes back at the very END of the stub,
			# because unlike the index it has to hold the pointer for
			# every member. See the restore below the member loop.
			#
			# "teb" differs from "home" in one thing: WHERE the eight
			# bytes are. Both borrow two live registers and give them
			# back, and the sequence between is identical. Finding 280.
			keep = encode_gpr_home if mode == "home" else encode_gpr_teb
			body += keep(block[0], True, block[4])
			body += keep(block[1], True, block[4] + 8)
			body += encode_tls_base(block[0], block[1], block[2],
			                        at + len(body))
			body += keep(block[1], False, block[4] + 8)
		else:
			body += encode_tls_base(block[0], block[1], block[2], at,
			                        helper if mode else None)
		# **After the pointer, not before.** The non-volatile borrow above
		# is stashed in the callee home space and addressed off `rsp`, so
		# it can be saved first. A scratch slot is addressed off the block
		# pointer and cannot be written until that pointer stands up --
		# which is also why mode True is refused for this borrow rather
		# than emitted: it stands the pointer up USING an xmm, and that
		# xmm is the register being saved. Finding 262.
		for register, slot in (block[8] if len(block) > 8 else ()):
			body += span_slot_move(register, True, base, slot, block,
			                       at + len(body))
		# The mover, where its eight bytes went to a scratch slot rather
		# than to the callee home space. Same reason as the stash above:
		# a slot is addressed off the block pointer, so it cannot be
		# written until that pointer stands up. Finding 267.
		if len(block) > 9 and block[9] is not None:
			body += encode_gpr_at(block[5], True, block[0],
			                      base + block[9] * SLOT)
	for kind, address, encoding, mnemonic, operands, slot, moved, second, \
			third, fourth in entries:
		if kind == "plain":
			# **The whole entry, not its first five fields.** The sixth is
			# the passenger's OWN scratch, which `span_entries` resolves
			# with `swallowed_scratch` and this discarded -- so any
			# passenger that needs one, a `vblendvps` or an FMA or a Class
			# C whose src2 is its destination, was refused. It is the same
			# omission `moved_instruction`'s docstring records as having
			# refused 2,437 stubs on the ordinary path, made again here
			# and invisible for the same reason: no counter named it.
			# Finding 171.
			fixed = moved_instruction(moved, at + len(body), pool)
			if fixed is None:
				return refuse("passenger cannot be moved")
			body += fixed
			continue
		vex = inplace.decode_vex(encoding)
		if vex is None or not vex["L"]:
			return refuse("member is not a 256-bit VEX")
		if helper is None and kind not in HELPER_FREE \
				and not (kind in GPR_MOVABLE and block is not None
				         and len(block) > 5 and block[5] is not None):
			# The collector decides whether a helper is wanted; this
			# refuses rather than emitting bytes that name register None
			# if the two ever disagree. A move with a mover to hand is not
			# a disagreement -- it is the case Finding 251 added.
			return refuse(f"member {kind} wants a helper and has none")
		tail = encoding[vex["length"]:]
		shape = span_operand_shape(vex, tail, operands, None, mnemonic)
		if shape is None:
			return refuse("no span shape at emit time")
		# **The SLOT_SHAPES exemption is for mnemonics whose SEMANTICS are a
		# move, and an FMA's are not.** The exemption exists because a lane
		# operation is emitted as a 16-byte slot move rather than by clearing
		# `VEX.L` -- so having no legacy encoding costs it nothing. `lanemem` is
		# in that list, and `lanemem` is also what `vfmadd213ps (%rax),%ymm1,%ymm2`
		# classifies as: three operands, two ymm, one memory. That shape IS
		# narrowed -- `movaps S1,D` then the opcode against memory -- so the
		# exemption handed the emitter exactly the instruction the set exists to
		# refuse, and 12 `66 0f 38 a8` sequences decoded to nothing.
		#
		# It was unreachable until Finding 258 put the FMA family in
		# NO_LEGACY_FORM, which is what makes this that fix's own hole rather
		# than an old one: before it, no member of the set could produce a
		# `lanemem`. Finding 263.
		# **The exemption stays shut for the FMA family, with one door.**
		# Finding 263 refuses every FMA whatever its shape, because
		# `lanemem` is narrowed and narrowing an FMA emits `66 0f 38 a8`,
		# which decodes to nothing. That is an argument about NARROWING,
		# not about the instruction: a plain packed multiply-add has a
		# two-instruction SSE sequence and the branch below emits it for
		# both halves. Everything else in the family -- the negated
		# forms, the lane-alternating ones, the scalars -- still refuses,
		# so the population this exempts is exactly the one that has an
		# emitter. Finding 300.
		fma_span = (mnemonic in FMA_SPAN_FORMS
		            and shape[0] in FMA_SPAN_SHAPES)
		if mnemonic in NO_LEGACY_FORM and not fma_span and (
				shape[0] not in SLOT_SHAPES
				or mnemonic in FMA_FORMS):
			# Narrowing this would emit bytes that decode to nothing. See
			# NO_LEGACY_FORM. Finding 205. The two lane shapes are the
			# exception and are not narrowed at all: they are emitted as
			# 16-byte moves against slots, which is what `lower.py` does
			# for them on the plain path. Finding 246.
			return refuse(f"member {mnemonic} has no legacy encoding")
		if slot is None:
			return refuse("member has no slot")
		what = shape[0]
		if what == "lanereg" and second is None:
			# The second source's upper half is in no slot this span
			# tracks, so the operation has nothing to read. Refused rather
			# than guessed at.
			return refuse("lanereg second source is in no slot")
		if what == "load":
			low = narrow_piece(vex, tail, 0, address, len(encoding),
			                   at + len(body))
			if low is None:
				return refuse("load low half cannot be narrowed")
			body += low
			mover = block[5] if block is not None and len(block) > 5 else None
			if helper is None and mover is not None:
				for half in (0, 8):
					piece = gpr_move_half(mover, True, vex, tail, address,
					                      encoding, at + len(body), base,
					                      slot, block, half)
					if piece is None:
						return refuse("load half cannot reach memory")
					body += piece
				continue
			high_vex, high_tail = retarget(vex, tail, helper)
			piece = narrow_piece(high_vex, high_tail, SLOT, address,
			                     len(encoding), at + len(body))
			if piece is None:
				return refuse("load high half cannot be narrowed")
			body += piece
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "store":
			low = narrow_piece(vex, tail, 0, address, len(encoding),
			                   at + len(body))
			if low is None:
				return refuse("store low half cannot be narrowed")
			body += low
			mover = block[5] if block is not None and len(block) > 5 else None
			if helper is None and mover is not None:
				for half in (0, 8):
					piece = gpr_move_half(mover, False, vex, tail, address,
					                      encoding, at + len(body), base,
					                      slot, block, half)
					if piece is None:
						return refuse("store half cannot reach memory")
					body += piece
				continue
			body += span_slot_move(helper, False, base, slot, block,
			                       at + len(body))
			high_vex, high_tail = retarget(vex, tail, helper)
			piece = narrow_piece(high_vex, high_tail, SLOT, address,
			                     len(encoding), at + len(body))
			if piece is None:
				return refuse("store high half cannot be narrowed")
			body += piece
			continue
		if what == "extract":
			# **`vextractf128 $1,%ymmS,%xmmD` is two moves.** The low half
			# of D becomes the upper half of S, which is a slot, so it is
			# read straight into D with no helper. And D is written by a
			# VEX.128 instruction, which ZEROES bits 255:128 -- under this
			# representation that is D's own slot, so it is zeroed rather
			# than left holding whatever D last had. Dropping that second
			# half is the stale-upper-read bug pointed the other way.
			if second is None:
				return refuse("extract source is in no slot")
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			body += span_slot_move(low_dst, False, base, second, block,
			                       at + len(body))
			# **The zero wants no register.** Two immediate stores rather
			# than `xorps` a helper and save it, which is what made this
			# shape ask for an xmm it never put a value in. Finding 250.
			body += span_slot_zero(base, slot, block)
			continue
		if what == "insert":
			# **`vinsertf128 $1,%xmmS,%ymmS1,%ymmD` reads no slot at all**:
			# both its sources are 128-bit machine registers, and the only
			# upper half in sight is the one it writes. So it is a store
			# to D's slot, plus D's low half from S1 where those differ.
			#
			# **The store comes first.** With S1 and S in the same machine
			# register as D -- which is what 141 of Starfield's 157 look
			# like -- moving S1 into D first would overwrite the very
			# value the store is meant to save.
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			low_src = scratch_finder.xmm_numbers(shape[2])[0]
			low_s1 = scratch_finder.xmm_numbers(shape[3])[0]
			body += span_slot_move(low_src, True, base, slot, block,
			                       at + len(body))
			if low_dst != low_s1:
				body += encode_movaps(low_dst, low_s1)
			continue
		if what == "permil":
			# **Twice, once per 128-bit lane.** The low half is the
			# ordinary 128-bit lowering on the architectural registers,
			# with a spare xmm for its scratch. The high half is the same
			# sequence on copies pulled out of the two sources' slots --
			# and there the scratch may BE the control copy, since this
			# owns it, which is what keeps the whole thing inside two
			# spare registers instead of three.
			if second_helper is None:
				return refuse("permil wants a second helper")
			if second is None or third is None:
				return refuse("permil source is in no slot")
			low = lower_permilps(dict(vex, L=0), tail, operands, helper,
			                     at + len(body), pool)
			if low is None:
				return refuse("permil low half would not lower")
			body += low
			# data.hi into `helper`, control.hi into `second_helper`.
			# `second` is shape[2]'s slot, which is the DATA; `third` is
			# shape[3]'s, the control. Getting these the wrong way round
			# permutes the control by the data, which is nonsense that
			# still runs -- src/permd.h warns about exactly that mistake
			# one instruction over.
			body += span_slot_move(helper, False, base, second, block,
			                       at + len(body))
			body += span_slot_move(second_helper, False, base, third,
			                       block, at + len(body))
			high_vex = dict(vex, L=0, R=helper >> 3, X=0,
			                B=second_helper >> 3, vvvv=helper)
			high_tail = tail[:1] + bytes([0xC0 | ((helper & 7) << 3)
			                              | (second_helper & 7)])
			high = lower_permilps(high_vex, high_tail, "%xmm,%xmm,%xmm",
			                      second_helper, at + len(body), pool,
			                      clobber_control=True)
			if high is None:
				return refuse("permil high half would not lower")
			body += high
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "regmove":
			# **Both halves are moves.** The low one is the instruction
			# with `VEX.L` cleared, acting on the machine registers the
			# program already uses; the high one is sixteen bytes from one
			# slot to another, which a general-purpose register carries in
			# two halves exactly as it carries a load. Finding 253.
			if second is None:
				return refuse("regmove source is in no slot")
			low = narrow_piece(vex, tail, 0, address, len(encoding),
			                   at + len(body))
			if low is None:
				return refuse("regmove low half cannot be narrowed")
			body += low
			mover = block[5] if block is not None and len(block) > 5 else None
			if helper is not None:
				body += span_slot_move(helper, False, base, second, block,
				                       at + len(body))
				body += span_slot_move(helper, True, base, slot, block,
				                       at + len(body))
			elif mover is not None:
				for half in (0, 8):
					where = block[0] if block is not None else None
					body += encode_gpr_at(mover, False, where,
					                      base + second * SLOT + half)
					body += encode_gpr_at(mover, True, where,
					                      base + slot * SLOT + half)
			else:
				return refuse("regmove has neither helper nor mover")
			continue
		if what == "permmem":
			# Four 64-bit loads: `movsd` fills the low quadword and zeroes
			# the high one, `movhpd` then fills the high one. Uniform for
			# every immediate rather than special-cased for the two that
			# occur, because a special case is a thing to be wrong about
			# and the general form is no longer.
			immediate = perm2_immediate(operands)
			if immediate is None:
				return refuse("permute immediate is not a constant")
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			bare = tail[:-1]
			failed = False
			for target, first_bits, second_bits in ((low_dst, 0, 2),
			                                        (helper, 4, 6)):
				for prefix, opcode, bits in ((0xF2, b"\x0f\x10", first_bits),
				                             (0x66, b"\x0f\x16",
				                              second_bits)):
					moved = inplace.offset_operand(
						bare, 8 * ((immediate >> bits) & 3))
					if moved is None:
						failed = True
						break
					piece = encode_mem(prefix, opcode, target, vex, moved,
					                   address, encoding, at + len(body))
					if piece is None:
						failed = True
						break
					body += piece
				if failed:
					break
			if failed:
				return refuse("permute source is out of reach")
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what in ("bcastmem", "bcastreg"):
			# **Both halves of a broadcast are the same 128 bits**, so it
			# is the ordinary 128-bit lowering followed by one more store,
			# and that store is the whole of the 256-bit part.
			#
			# `lower_broadcast` is that 128-bit lowering and is reused
			# rather than repeated: it already knows that `movss` and
			# `movd` zero the rest of the register so the shuffle after
			# can splat lane 0, that `movddup` does the 64-bit case alone,
			# and how to correct a RIP displacement for the move into the
			# stub. A second copy of that here would be a second thing to
			# be wrong about, and the first draft was one.
			piece = lower_broadcast(dict(vex, L=0), tail, mnemonic,
			                        encoding, address, at + len(body))
			if piece is None:
				return refuse(f"{mnemonic} would not lower")
			body += piece
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			body += span_slot_move(low_dst, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "extractmem":
			# **The source's upper half, straight out to memory.** No slot
			# is written: the destination is sixteen bytes of memory and
			# no ymm is touched, so unlike the register form there is
			# nothing to zero. The imm8 is dropped from the tail, because
			# `encode_mem` carries everything from modrm onward and a
			# `movups` has no immediate.
			body += span_slot_move(helper, False, base, slot, block,
			                       at + len(body))
			piece = encode_mem(None, b"\x0f\x11", helper, vex, tail[:-1],
			                   address, encoding, at + len(body))
			if piece is None:
				return refuse("extract to memory is out of reach")
			body += piece
			continue
		if what == "insertmem":
			# Sixteen bytes of memory into the destination's slot, and its
			# low half from S1 where those differ.
			piece = encode_mem(None, b"\x0f\x10", helper, vex, tail[:-1],
			                   address, encoding, at + len(body))
			if piece is None:
				return refuse("insert from memory is out of reach")
			body += piece
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			low_s1 = scratch_finder.xmm_numbers(shape[2])[0]
			if low_dst != low_s1:
				body += encode_movaps(low_dst, low_s1)
			continue
		if what == "perm2":
			# **Each output half is one of four input halves, or zero.**
			# imm[1:0] selects the low half and imm[5:4] the high one, from
			# SRC1.lo, SRC1.hi, SRC2.lo, SRC2.hi in that order; imm[3] and
			# imm[7] override with zero. Nothing about that is arithmetic
			# once the halves are separately addressable.
			#
			# **Both sources are read before either destination half is
			# written.** Every one of Starfield's twelve has the
			# destination aliasing a source -- eight are `%ymm0,%ymm0,%ymm0`
			# -- so writing the low half first would destroy the value the
			# high half still needs.
			if second_helper is None:
				return refuse("perm2 wants a second helper")
			if second is None or third is None:
				return refuse("perm2 source is in no slot")
			immediate = perm2_immediate(operands)
			if immediate is None:
				return refuse("perm2 immediate is not a constant")
			destination, source2, source1 = shape[1], shape[2], shape[3]
			low_s1 = scratch_finder.xmm_numbers(source1)[0]
			low_s2 = scratch_finder.xmm_numbers(source2)[0]
			# (machine register, slot) for the four selector values, in the
			# SDM's order.
			halves = ((low_s1, None), (None, third),
			          (low_s2, None), (None, second))
			for target, shift, zero in ((helper, 0, 0x08),
			                            (second_helper, 4, 0x80)):
				if immediate & zero:
					body += encode_rr(None, b"\x0f\x57", target, target)
					continue
				register, from_slot = halves[(immediate >> shift) & 3]
				if from_slot is not None:
					body += span_slot_move(target, False, base, from_slot,
					                       block, at + len(body))
				else:
					body += encode_movaps(target, register)
			low_dst = scratch_finder.xmm_numbers(destination)[0]
			body += encode_movaps(low_dst, helper)
			body += span_slot_move(second_helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "immreg3":
			# **`lanereg3` with an immediate.** `movaps S1,D` then the
			# operation against S2 with the selector, and the upper half
			# the same between three slots. The immediate is the last
			# byte of the tail and rides through unchanged, because the
			# classifier has already established the operation is
			# per-lane. Finding 273.
			if second_helper is None:
				return refuse("immreg3 wants a second helper")
			if second is None or third is None:
				return refuse("immreg3 source is in no slot")
			destination, source2, source1 = shape[1], shape[2], shape[3]
			low_dst = scratch_finder.xmm_numbers(destination)[0]
			low_s2 = scratch_finder.xmm_numbers(source2)[0]
			low_s1 = scratch_finder.xmm_numbers(source1)[0]
			immediate = tail[2:]

			def shuffle(reg, rm):
				return inplace.sse_encoding(
					dict(vex, L=0, R=reg >> 3, X=0, B=rm >> 3),
					tail[:1] + bytes([0xC0 | ((reg & 7) << 3)
					                  | (rm & 7)]) + immediate)

			body += encode_movaps(low_dst, low_s1)
			low = shuffle(low_dst, low_s2)
			if low is None:
				return refuse("immreg3 low operation has no SSE form")
			body += low
			# The upper half, between the three slots.
			body += span_slot_move(helper, False, base, third, block,
			                       at + len(body))
			body += span_slot_move(second_helper, False, base, second,
			                       block, at + len(body))
			high = shuffle(helper, second_helper)
			if high is None:
				return refuse("immreg3 high operation has no SSE form")
			body += high
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "immreg":
			# **One immediate, applied to each half unchanged**, which is
			# what makes an in-lane operation splittable at all. The
			# classifier has already refused the cross-lane immediates.
			#
			# The shift group takes its destination from `vvvv` and the
			# SSE form puts it in r/m, so the low half needs the source
			# moved into the destination first -- `movaps S,D; op $imm,D`
			# -- exactly as a Class C site does one width down. Every
			# other immediate form has the same operand layout in both
			# encodings and strips straight through. Finding 271.
			if second is None:
				return refuse("immreg source is in no slot")
			destination, source = shape[1], shape[2]
			low_dst = scratch_finder.xmm_numbers(destination)[0]
			low_src = scratch_finder.xmm_numbers(source)[0]
			shift = vex["map"] == 1 and tail[:1] in (b"\x71", b"\x72",
			                                        b"\x73")
			immediate = tail[2:]

			def immediate_op(reg, rm, extension=None):
				"""The narrowed operation, `reg` ignored for a shift."""
				field = extension if extension is not None else reg
				return inplace.sse_encoding(
					dict(vex, L=0, X=0,
					     R=0 if extension is not None else reg >> 3,
					     B=rm >> 3),
					tail[:1] + bytes([0xC0 | ((field & 7) << 3)
					                  | (rm & 7)]) + immediate)

			extension = ((tail[1] >> 3) & 7) if shift else None
			if shift and low_dst != low_src:
				body += encode_movaps(low_dst, low_src)
			low = immediate_op(low_dst, low_dst if shift else low_src,
			                   extension)
			if low is None:
				return refuse("immreg low operation has no SSE form")
			body += low
			# The upper half: the source's slot into the helper, the same
			# operation on it, the helper into the destination's slot.
			body += span_slot_move(helper, False, base, second, block,
			                       at + len(body))
			high = immediate_op(helper, helper, extension)
			if high is None:
				return refuse("immreg high operation has no SSE form")
			body += high
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "blendv":
			# **The mask lives in `xmm0` and nowhere else.** SSE4.1's
			# `blendvps` takes it implicitly, so each half saves `xmm0`,
			# loads the mask over it, and gives it back.
			#
			# `xmm0` is SRC1 at every one of Starfield's sites, so the
			# save has to come FIRST and every operand then read from
			# the saved copy -- `spare` below. Refusing whenever `xmm0`
			# is involved would refuse all of them, which is the trap
			# Finding 100 already paid for from the other side: offering
			# only `xmm0` as the scratch refused 600 sites with a
			# register they could never use.
			#
			# `blendvps src,dst` keeps `dst` where the mask is clear and
			# takes `src` where it is set, so the destination has to
			# start as SRC1 -- which is why the accumulator is the
			# helper rather than the destination register. Finding 307.
			if second is None or third is None or fourth is None:
				return refuse("blendv operand is in no slot")
			if block is None:
				return refuse("blendv wants a per-thread block")
			if second_helper is None:
				return refuse("blendv wants a second helper")
			if 0 in (helper, second_helper):
				return refuse("blendv cannot borrow xmm0 as a helper")
			kind = mnemonic[-2:]
			blend = b"\x0f\x38\x14" if kind == "ps" else b"\x0f\x38\x15"
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			low_s2 = scratch_finder.xmm_numbers(shape[2])[0]
			low_s1 = scratch_finder.xmm_numbers(shape[3])[0]
			low_mask = scratch_finder.xmm_numbers(shape[4])[0]

			def spare(register):
				"""Where this operand is, once `xmm0` has been put away."""
				return second_helper if register == 0 else register

			body += encode_rr(None, MOVAPS, second_helper, 0)
			if low_mask != 0:
				body += encode_rr(None, MOVAPS, 0, spare(low_mask))
			body += encode_rr(None, MOVAPS, helper, spare(low_s1))
			body += encode_rr(0x66, blend, helper, spare(low_s2))
			# **No restore where the destination IS `xmm0`.** Its old
			# value is dead -- the destination is about to be written --
			# so restoring it and then overwriting it is two wasted
			# instructions, and doing them in the other order would
			# discard the result. Four refusals on Starfield read
			# `blendv destination is xmm0` before this, which was a
			# guard standing in for an ordering question. Finding 307.
			if low_dst == 0:
				body += encode_rr(None, MOVAPS, 0, helper)
			else:
				body += encode_rr(None, MOVAPS, low_dst, helper)
				body += encode_rr(None, MOVAPS, 0, second_helper)

			# The upper half, every operand a slot. `xmm0` is saved into
			# the second helper again rather than kept from the low
			# half: the low half gave it back, and a stub that left it
			# clobbered across the members would be wrong for whatever
			# follows in the window.
			body += encode_rr(None, MOVAPS, second_helper, 0)
			body += span_slot_move(0, False, base, fourth, block,
			                       at + len(body))
			body += span_slot_move(helper, False, base, third, block,
			                       at + len(body))
			piece = span_slot_op(0x66, blend, helper, base, second, block)
			if piece is None:
				return refuse("blendv cannot reach the second source")
			body += piece
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			body += encode_rr(None, MOVAPS, 0, second_helper)
			continue
		if what in ("lanereg3", "lanemem") and mnemonic in FMA_SPAN_FORMS \
				and FMA_PATTERN.match(mnemonic).group(1) == "n":
			# **`D = addend - product`, which cannot accumulate in one
			# register.** SSE has no reverse subtract, so the addend has
			# to be the destination of the `subps` -- and in the upper
			# half the addend is a slot, so it must be LOADED while the
			# product occupies a register of its own. Two helpers, which
			# is why these forms are outside `FMA_ONE_HELPER`.
			#
			# It must intercept ahead of the general branch, which reads
			# the operation as `madd` -- `FMA_PATTERN` puts the negation
			# in its own group -- and would emit the un-negated
			# sequence. Finding 306.
			if second is None:
				return refuse("FMA source is in no slot")
			if block is None:
				return refuse("FMA member wants a per-thread block")
			if second_helper is None:
				return refuse("negated FMA wants a second helper")
			order = FMA_PATTERN.match(mnemonic).group(3)
			kind = mnemonic[-2:]
			prefix = FMA_PREFIX[kind]
			mul, take, load = b"\x0f\x59", b"\x0f\x5c", b"\x0f\x10"
			mem = what == "lanemem"
			if mem and third is not None:
				pass
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			if mem:
				low_s1 = scratch_finder.xmm_numbers(shape[2])[0]
				low_s2 = MEMORY
				s1_slot, s2_slot = second, MEMORY
			else:
				if third is None:
					return refuse("lanereg3 source is in no slot")
				low_s2 = scratch_finder.xmm_numbers(shape[2])[0]
				low_s1 = scratch_finder.xmm_numbers(shape[3])[0]
				s1_slot, s2_slot = third, second

			def at_mem(opcode, pfx, reg, delta):
				return fma_mem_piece(vex, tail, pfx, opcode, reg, delta,
				                     address, encoding, at + len(body))

			# factors and addend, per the SDM's suffix
			pairs = {"132": ((low_dst, low_s2), low_s1),
			         "213": ((low_s1, low_dst), low_s2),
			         "231": ((low_s1, low_s2), low_dst)}
			(f0, f1), addend = pairs[order]
			if f0 is MEMORY:
				return refuse("negated FMA cannot copy from memory")
			body += encode_rr(None, MOVAPS, helper, f0)
			if f1 is MEMORY:
				piece = at_mem(mul, prefix, helper, 0)
				if piece is None:
					return refuse("negated FMA cannot reach its operand")
				body += piece
			else:
				body += encode_rr(prefix, mul, helper, f1)
			if addend is MEMORY:
				piece = at_mem(load, None, low_dst, 0)
				if piece is None:
					return refuse("negated FMA cannot reach its addend")
				body += piece
			elif addend != low_dst:
				body += encode_rr(None, MOVAPS, low_dst, addend)
			body += encode_rr(prefix, take, low_dst, helper)

			# The upper half, with the product in `helper` and the addend
			# loaded into `second_helper` because it is the subtract's
			# destination.
			slots = {"132": ((slot, s2_slot), s1_slot),
			         "213": ((s1_slot, slot), s2_slot),
			         "231": ((s1_slot, s2_slot), slot)}
			(g0, g1), gadd = slots[order]
			if g0 is MEMORY:
				return refuse("negated FMA cannot copy from memory")
			body += span_slot_move(helper, False, base, g0, block,
			                       at + len(body))
			if g1 is MEMORY:
				piece = at_mem(mul, prefix, helper, SLOT)
			else:
				piece = span_slot_op(prefix, mul, helper, base, g1, block)
			if piece is None:
				return refuse("negated FMA cannot reach a slot")
			body += piece
			if gadd is MEMORY:
				piece = at_mem(load, None, second_helper, SLOT)
				if piece is None:
					return refuse("negated FMA cannot reach its addend")
				body += piece
			else:
				body += span_slot_move(second_helper, False, base, gadd,
				                       block, at + len(body))
			body += encode_rr(prefix, take, second_helper, helper)
			body += span_slot_move(second_helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "lanereg3" and mnemonic in FMA_SPAN_FORMS \
				and FMA_PATTERN.match(mnemonic).group(2) == "msubadd":
			# **Both results, then a blend.** See FMA_SPAN_OPS: there
			# is no subadd instruction and negating the addend to reuse
			# `addsubps` flips a NaN's sign bit, which the hardware
			# preserves. Doing the add and the subtract the hardware
			# does makes NaN propagation match by construction.
			#
			# Uniform across the orderings rather than multiplying in
			# place for two of them: the product has to survive into a
			# copy, so there is nothing to gain by putting it in the
			# destination. Finding 304.
			if second is None or third is None:
				return refuse("lanereg3 source is in no slot")
			if block is None:
				return refuse("FMA member wants a per-thread block")
			if second_helper is None:
				return refuse("msubadd wants a second helper")
			order = FMA_PATTERN.match(mnemonic).group(3)
			kind = mnemonic[-2:]
			prefix = FMA_PREFIX[kind]
			mul, add = b"\x0f\x59", b"\x0f\x58"
			take = b"\x0f\x5c"
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			low_s2 = scratch_finder.xmm_numbers(shape[2])[0]
			low_s1 = scratch_finder.xmm_numbers(shape[3])[0]
			first, other, addend = {
				"132": (low_dst, low_s2, low_s1),
				"213": (low_s1, low_dst, low_s2),
				"231": (low_s1, low_s2, low_dst),
			}[order]
			body += encode_rr(None, MOVAPS, helper, first)
			body += encode_rr(prefix, mul, helper, other)
			body += encode_rr(None, MOVAPS, second_helper, helper)
			body += encode_rr(prefix, add, helper, addend)
			body += encode_rr(prefix, take, second_helper, addend)
			body += encode_rr(0x66, BLEND_OPCODE[kind], helper,
			                  second_helper, BLEND_ODD[kind])
			body += encode_rr(None, MOVAPS, low_dst, helper)

			# The same shape between slots, the addend read twice as a
			# memory operand because both results need it.
			sf, so, sa = {
				"132": (slot, second, third),
				"213": (third, slot, second),
				"231": (third, second, slot),
			}[order]
			body += span_slot_move(helper, False, base, sf, block,
			                       at + len(body))
			for opcode, into, which in ((mul, helper, so),):
				piece = span_slot_op(prefix, opcode, into, base, which,
				                     block)
				if piece is None:
					return refuse("msubadd cannot reach a slot")
				body += piece
			body += encode_rr(None, MOVAPS, second_helper, helper)
			for opcode, into in ((add, helper), (take, second_helper)):
				piece = span_slot_op(prefix, opcode, into, base, sa, block)
				if piece is None:
					return refuse("msubadd cannot reach a slot")
				body += piece
			body += encode_rr(0x66, BLEND_OPCODE[kind], helper,
			                  second_helper, BLEND_ODD[kind])
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "lanereg3" and mnemonic in FMA_SPAN_FORMS:
			# **The same sequence with a third slot instead of a memory
			# operand.** `lanereg3` is `op S2,S1,D` with every operand a
			# ymm, so the upper half has three slots in play -- and two
			# of them are read as addresses rather than loaded, which is
			# why this wants one helper where the shape's ordinary
			# emission wants two.
			#
			# `slot` is D's, `second` is S2's and `third` is S1's, which
			# is the mapping the shape's own branch below relies on.
			# Finding 301.
			if second is None or third is None:
				return refuse("lanereg3 source is in no slot")
			if block is None:
				return refuse("FMA member wants a per-thread block")
			what_op, order = FMA_PATTERN.match(mnemonic).group(2, 3)
			kind = mnemonic[-2:]
			prefix = FMA_PREFIX[kind]
			mul, combine = b"\x0f\x59", FMA_SPAN_OPS[what_op]
			# **`addsubps` is F2-prefixed where `addps` has none**, so
			# the combining opcode carries its own prefix rather than
			# the multiply's. `addsubpd` is 66 like the rest of pd.
			joint = (0xF2 if kind == "ps" else 0x66) \
				if what_op == "maddsub" else prefix
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			low_s2 = scratch_finder.xmm_numbers(shape[2])[0]
			low_s1 = scratch_finder.xmm_numbers(shape[3])[0]
			if order == "213":		# D = S1 op* D . S2
				body += encode_rr(prefix, mul, low_dst, low_s1)
				body += encode_rr(joint, combine, low_dst, low_s2)
			elif order == "132":		# D = D op* S2 . S1
				body += encode_rr(prefix, mul, low_dst, low_s2)
				body += encode_rr(joint, combine, low_dst, low_s1)
			else:
				# **231 accumulates in the helper and moves back**, for
				# every operation and not only the ones that need it.
				# Its destination is the ADDEND, so the product needs
				# somewhere to live -- and `addps h,D` would have been
				# right only because addition commutes. `subps` and
				# `addsubps` do not, and a form that is correct for one
				# operation and silently wrong for the next is worth
				# three bytes to avoid. Finding 302.
				body += encode_rr(None, MOVAPS, helper, low_s1)
				body += encode_rr(prefix, mul, helper, low_s2)
				body += encode_rr(joint, combine, helper, low_dst)
				body += encode_rr(None, MOVAPS, low_dst, helper)

			# The upper half accumulates in `helper` and names the other
			# two slots by address.
			load, first, then = {
				"213": (slot, third, second),
				"132": (slot, second, third),
				"231": (third, second, slot),
			}[order]
			body += span_slot_move(helper, False, base, load, block,
			                       at + len(body))
			for opcode, pfx, which in ((mul, prefix, first),
			                           (combine, joint, then)):
				piece = span_slot_op(pfx, opcode, helper, base, which,
				                     block)
				if piece is None:
					return refuse("FMA high half cannot reach a slot")
				body += piece
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "lanereg3":
			# **A destination of its own, so both halves are a move and an
			# operation.** SSE has no three-operand form: `op S2,S1,D`
			# becomes `movaps S1,D; op S2,D`, which is what `lower_vex`
			# emits for a Class C site one width down. The upper half is
			# the same shape between slots -- the two sources' slots into
			# the two helpers, the operation between them, and the result
			# into the destination's slot, which is a THIRD slot and the
			# reason this shape needs the region's slot count rather than
			# a span's two.
			if second_helper is None:
				return refuse("lanereg3 wants a second helper")
			if second is None or third is None:
				return refuse("lanereg3 source is in no slot")
			destination, source2, source1 = shape[1], shape[2], shape[3]
			low_dst = scratch_finder.xmm_numbers(destination)[0]
			low_s2 = scratch_finder.xmm_numbers(source2)[0]
			low_s1 = scratch_finder.xmm_numbers(source1)[0]
			body += encode_movaps(low_dst, low_s1)
			operation = inplace.sse_encoding(
				dict(vex, L=0, R=low_dst >> 3, X=0, B=low_s2 >> 3),
				tail[:1] + bytes([0xC0 | ((low_dst & 7) << 3)
				                  | (low_s2 & 7)]))
			if operation is None:
				return refuse("lanereg3 low operation has no SSE form")
			body += operation
			# The upper half, between slots.
			body += span_slot_move(helper, False, base, third, block,
			                       at + len(body))
			body += span_slot_move(second_helper, False, base, second,
			                       block, at + len(body))
			operation = inplace.sse_encoding(
				dict(vex, L=0, R=helper >> 3, X=0, B=second_helper >> 3),
				tail[:1] + bytes([0xC0 | ((helper & 7) << 3)
				                  | (second_helper & 7)]))
			if operation is None:
				return refuse("lanereg3 high operation has no SSE form")
			body += operation
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "lanemove":
			# **One source, and the destination's upper half is wholly
			# overwritten** -- so unlike `lanereg` there is nothing to
			# load into a second helper first. The source's slot goes
			# into the helper, the operation runs on it in place, and the
			# result goes to the destination's slot.
			#
			# `narrow_piece` is right for the low half without a
			# commuted form: with one source there is no `vvvv` to throw
			# away, so dropping the prefix names the same two registers
			# the program named. Finding 285.
			if second is None:
				return refuse("lanemove source is in no slot")
			if helper is None:
				return refuse("lanemove wants a helper")
			low = narrow_piece(vex, tail, 0, address, len(encoding),
			                   at + len(body))
			if low is None:
				return refuse("lanemove low half cannot be narrowed")
			body += low
			body += span_slot_move(helper, False, base, second, block,
			                       at + len(body))
			# Register to register, reg and rm both the helper: the
			# operation reads its source and writes its destination, and
			# here they are the same sixteen bytes. The opcode byte is the
			# original tail's first, as in `lanereg`.
			operation = inplace.sse_encoding(
				dict(vex, L=0, R=helper >> 3, X=0, B=helper >> 3),
				tail[:1] + bytes([0xC0 | ((helper & 7) << 3)
				                  | (helper & 7)]))
			if operation is None:
				return refuse("lanemove operation has no SSE form")
			body += operation
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "lanealias":
			# **The destination is the other source, and the order is
			# kept.** Six instructions and ONE helper:
			#
			#     movaps %xmmD,%xmmH      save src2's low half
			#     movaps %xmmS,%xmmD      D = src1
			#     op     %xmmH,%xmmD      D = src1 OP src2, in that order
			#     movups slot(S),%xmmH    H = src1's upper half
			#     op     slot(D),%xmmH    H = src1 OP src2, upper
			#     movups %xmmH,slot(D)
			#
			# The low half needs no slot at all -- the helper holds the
			# value the destination is about to lose. The upper half reads
			# the DESTINATION's slot as the operand, which is the only way
			# round with one register: the operation computes
			# `reg OP mem`, so the register has to hold src1 and the
			# memory operand has to be src2. Finding 312.
			if second is None:
				return refuse("lanealias source is in no slot")
			if block is None:
				return refuse("lanealias wants a per-thread block")
			if not slot_arithmetic_safe():
				return refuse("lanealias wants a 16-byte aligned block")
			if len(tail) < 2 or (tail[1] & 0xC0) != 0xC0:
				return refuse("lanealias is not register to register")
			destination = ((tail[1] >> 3) & 7) | (vex["R"] << 3)
			source = vex["vvvv"]
			body += encode_movaps(helper, destination)
			body += encode_movaps(destination, source)
			low = inplace.sse_encoding(
				dict(vex, L=0, R=destination >> 3, X=0, B=helper >> 3),
				tail[:1] + bytes([0xC0 | ((destination & 7) << 3)
				                  | (helper & 7)]))
			if low is None:
				return refuse("lanealias operation has no SSE form")
			body += low
			body += span_slot_move(helper, False, base, second, block,
			                       at + len(body))
			# `slot_tail` was written for exactly this and its docstring
			# said nothing used it. Something does now, and the alignment
			# it asks a caller to guarantee is guaranteed above.
			upper = inplace.sse_encoding(
				dict(vex, L=0, R=helper >> 3, X=0, B=block[0] >> 3),
				tail[:1] + slot_tail(helper, base, slot, block[0]))
			if upper is None:
				return refuse("lanealias upper half has no SSE form")
			body += upper
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "lanereg":
			# **TWO helpers, because a slot cannot be an operand.** The
			# obvious emission is `op slot(%base),%xmmH` -- one helper, the
			# destination's upper half in it, the source's slot read
			# directly -- and `slot_tail` was written for exactly that. It
			# faults. A packed SSE operation requires its memory operand
			# to be 16-byte ALIGNED, and nothing aligns a slot: Win64
			# guarantees `rsp` is aligned at a call boundary and says
			# nothing about an arbitrary instruction, which is the same
			# reason `encode_spill` moves with `movups` and not `movaps`.
			# The first build of this segfaulted on its first run.
			#
			# So the source's upper half is MOVED into a second helper --
			# with `movups`, which has no alignment requirement -- and the
			# operation is register to register.
			if second_helper is None:
				return refuse("lanereg wants a second helper")
			# **Which narrowing is decided by the encoding, not by the
			# shape.** `vvvv` names the source SSE has no room for, so
			# dropping the prefix is right exactly when `vvvv` already
			# names the destination. Where it does not, the destination is
			# the other source and the operands have to be exchanged --
			# which the classifier only allows for an operation that
			# commutes. Reading it back off the bytes keeps the two from
			# disagreeing. Finding 284.
			if len(tail) > 1 and vex["vvvv"] != (
					((tail[1] >> 3) & 7) | (vex["R"] << 3)):
				low = commuted_piece(vex, tail)
			else:
				low = narrow_piece(vex, tail, 0, address, len(encoding),
				                   at + len(body))
			if low is None:
				return refuse("lanereg low half cannot be narrowed")
			body += low
			body += span_slot_move(helper, False, base, slot, block,
			                       at + len(body))
			body += span_slot_move(second_helper, False, base, second,
			                       block, at + len(body))
			# Register to register: modrm mod 11, reg = destination
			# helper, rm = source helper. The opcode byte is the original
			# tail's first, which is what `sse_encoding` expects in front
			# of the addressing -- without it the modrm is read as the
			# opcode and `vaddps` assembles as `shrd`.
			operation = inplace.sse_encoding(
				dict(vex, L=0, R=helper >> 3, X=0, B=second_helper >> 3),
				tail[:1] + bytes([0xC0 | ((helper & 7) << 3)
				                  | (second_helper & 7)]))
			if operation is None:
				return refuse("lanereg operation has no SSE form")
			body += operation
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "lanemem" and mnemonic in FMA_SPAN_FORMS:
			# **A multiply and an add, per half, rather than a narrowing.**
			# The suffix says which operand is the addend, from the SDM:
			# 132 is `D = D*S2 + S1`, 213 is `D = S1*D + S2`, 231 is
			# `D = S1*S2 + D`, and here S2 is the memory operand.
			#
			# NOT bit-exact -- two roundings replace one -- which is the
			# deviation Finding 4 recorded for the plain path and this
			# extends rather than introduces.
			#
			# The low half needs no scratch for 213 and 132, because the
			# destination is itself a factor and can be multiplied in
			# place; 231 has the destination as the ADDEND, so the
			# product needs somewhere to live and borrows `helper`, which
			# the upper half reloads from a slot immediately afterwards.
			# Finding 300.
			if second is None:
				return refuse("lanemem source is in no slot")
			if block is None:
				return refuse("FMA member wants a per-thread block")
			what_op, order = FMA_PATTERN.match(mnemonic).group(2, 3)
			kind = mnemonic[-2:]
			prefix = FMA_PREFIX[kind]
			if FMA_SPAN_OPS[what_op] is None:
				# `msubadd` needs both results and a blend, which the
				# register form below emits and this one does not.
				# Every one of Starfield's 14 is register-only, so the
				# shape has no site to be written against -- and an
				# emitter with no fixture is the thing this file keeps
				# being caught by. Finding 304.
				return refuse(f"member {mnemonic} wants the blend form")
			mul, combine = b"\x0f\x59", FMA_SPAN_OPS[what_op]
			joint = (0xF2 if kind == "ps" else 0x66) \
				if what_op == "maddsub" else prefix
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			low_s1 = scratch_finder.xmm_numbers(shape[2])[0]

			def at_mem(opcode, pfx, reg, delta):
				return fma_mem_piece(vex, tail, pfx, opcode, reg,
				                     delta, address, encoding,
				                     at + len(body))

			if order == "213":		# D = S1 op* D . mem
				body += encode_rr(prefix, mul, low_dst, low_s1)
				piece = at_mem(combine, joint, low_dst, 0)
			elif order == "132":		# D = D op* mem . S1
				piece = at_mem(mul, prefix, low_dst, 0)
				if piece is None:
					return refuse("FMA low half cannot reach its operand")
				body += piece
				piece = encode_rr(joint, combine, low_dst, low_s1)
			else:
				# 231, and the same move-back as `lanereg3`: the
				# destination is the addend, and only addition commutes.
				body += encode_rr(None, MOVAPS, helper, low_s1)
				piece = at_mem(mul, prefix, helper, 0)
				if piece is None:
					return refuse("FMA low half cannot reach its operand")
				body += piece
				body += encode_rr(joint, combine, helper, low_dst)
				piece = encode_rr(None, MOVAPS, low_dst, helper)
			if piece is None:
				return refuse("FMA low half cannot reach its operand")
			body += piece

			# The upper half, in ONE register. Whichever slot is not
			# the accumulator is read as a memory operand rather than
			# loaded, so each ordering starts by loading the slot it
			# needs to accumulate into and then names the other by
			# address. 231 accumulates in the SOURCE's copy and adds
			# the destination's slot, which is why its load differs.
			load = second if order == "231" else slot
			body += span_slot_move(helper, False, base, load, block,
			                       at + len(body))
			if order == "213":		# h = S1h op* h . mem16
				piece = span_slot_op(prefix, mul, helper, base, second,
				                     block)
			else:				# 132 and 231 multiply by memory
				piece = at_mem(mul, prefix, helper, SLOT)
			if piece is None:
				return refuse("FMA high half cannot reach its operand")
			body += piece
			if order == "213":
				piece = at_mem(combine, joint, helper, SLOT)
			elif order == "132":
				piece = span_slot_op(joint, combine, helper, base,
				                     second, block)
			else:
				piece = span_slot_op(joint, combine, helper, base, slot,
				                     block)
			if piece is None:
				return refuse("FMA high half cannot reach its operand")
			body += piece
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		if what == "lanemem":
			# The same as `lane` below, with the source copied into the
			# destination first because SSE has no three-operand form.
			# `narrow_piece` emits `op mem,%xmmD` -- the VEX's own modrm
			# names D -- so after the copy it computes D = S1 op mem.
			if second is None:
				return refuse("lanemem source is in no slot")
			low_dst = scratch_finder.xmm_numbers(shape[1])[0]
			low_s1 = scratch_finder.xmm_numbers(shape[2])[0]
			if low_dst != low_s1:
				body += encode_movaps(low_dst, low_s1)
			low = narrow_piece(vex, tail, 0, address, len(encoding),
			                   at + len(body))
			if low is None:
				return refuse("lanemem low half cannot be narrowed")
			body += low
			# The upper half reads SRC1's slot and writes the
			# DESTINATION's, which are different slots -- the one thing
			# that separates this from `lane`.
			body += span_slot_move(helper, False, base, second, block,
			                       at + len(body))
			high_vex, high_tail = retarget(vex, tail, helper)
			piece = narrow_piece(high_vex, high_tail, SLOT, address,
			                     len(encoding), at + len(body))
			if piece is None:
				return refuse("lanemem high half cannot be narrowed")
			body += piece
			body += span_slot_move(helper, True, base, slot, block,
			                       at + len(body))
			continue
		# A lane-wise operation whose other source is memory. The low half
		# is the instruction with L cleared; the upper half is the same
		# opcode between the slot and the helper.
		#
		# **Through `narrow_piece` and not `sse_encoding`, at delta 0.**
		# The two produce the same bytes for an ordinary displacement and
		# differ on a RIP-relative one, which has to absorb the move into
		# the stub as well -- and `sse_encoding` does not, because it does
		# not know where the instruction landed. The load and the store
		# went through `narrow_piece` from the first line written; this
		# did not, so the low half of every rip-relative operation read
		# from inside the stub section. `check-pe` returned 5 for the
		# fixture built to catch exactly this.
		low = narrow_piece(vex, tail, 0, address, len(encoding),
		                   at + len(body))
		if low is None:
			return refuse("lane low half cannot be narrowed")
		body += low
		body += span_slot_move(helper, False, base, slot, block,
		                       at + len(body))
		high_vex, high_tail = retarget(vex, tail, helper)
		piece = narrow_piece(high_vex, high_tail, SLOT, address,
		                     len(encoding), at + len(body))
		if piece is None:
			return refuse("lane high half cannot be narrowed")
		body += piece
		body += span_slot_move(helper, True, base, slot, block,
		                       at + len(body))
	if block is not None and len(block) > 9 and block[9] is not None:
		# Back before the pointer goes, for the same reason.
		body += encode_gpr_at(block[5], False, block[0],
		                      base + block[9] * SLOT)
	for register, slot in (block[8] if block is not None and len(block) > 8
	                       else ()):
		# Back before the block pointer goes, because the slot is
		# addressed off it. A fault in between leaves a volatile register
		# clobbered, which is what volatile means: no unwinder restores
		# xmm0-5 and no caller expects them across a call. Finding 262.
		body += span_slot_move(register, False, base, slot, block,
		                       at + len(body))
	for register, where in (block[7] if block is not None and len(block) > 7
	                        else ()):
		# Back before the stub returns, so the function finds the register
		# as it left it. A fault in between is answered by the function's
		# OWN save, which is the condition the borrow was chosen under.
		body += encode_spill(register, False, at + len(body), 0, 0, where)
	if block is not None and len(block) > 6 and block[6] is not None:
		body += encode_gpr_at(block[5], False, None, block[6])
	if block is not None and len(block) > 3 and block[3] in ("home", "teb"):
		# **The one place it can go.** Past the refusals this function has
		# a single exit, and every member above has finished with the
		# pointer by the time control reaches it.
		keep = encode_gpr_home if block[3] == "home" else encode_gpr_teb
		body += keep(block[0], False, block[4])
	return bytes(body)


def region_helpers(plain, instructions, first, bound, blocked, scope):
	"""(free across the region, free by the whole-function rule) as sets.

	**Per position, not per function.** `scope_free` asks whether the
	function names the register ANYWHERE, which over a region of up to 192
	instructions is nearly always empty -- Finding 148 measured 2,782 of
	3,355 representable sites refused for exactly that, and Finding 171
	found the collector still paying it: 192 regions declined for want of
	one xmm when this answer was already being computed in the survey
	beside it. `xmm_live_out` asks whether the register is dead at every
	position the region covers, which is a question about the region.

	A region that ends at a CALL knows what is live after it: nothing
	volatile, by the ABI. One that ends at a branch target does not --
	control carries on in the same function and anything may be wanted --
	so `exit_live` is seeded only for the call.

	**The union, because the two are sound for different reasons and
	neither contains the other.** The whole-function rule holds everywhere
	in the function, including after control leaves this region, which is
	exactly where per-position liveness has nothing to say. Measured apart:
	573 by the function rule, 272 by liveness, and each finds regions the
	other refuses.

	`bound` is the region's end INCLUDING a terminating transfer, which is
	not where a window may end but is where the liveness question has to be
	asked -- a call reads the argument registers, and a helper chosen
	without it would be one the call wants.

	One implementation, called by the collector and by the survey both.
	Finding 171: the survey computed this union and the collector asked
	`scope_free` alone, which is the drift `SPAN_EMITTABLE` prevents
	between a survey and a lowering and which nobody had prevented here.
	"""
	inside = tuple(position for position in range(first, bound)
	               if instructions[position][0] in blocked)
	closing = instructions[bound - 1][2]
	live = xmm_live_out(plain, first, bound, inside,
	                    frozenset() if closing.startswith("call") else None)
	free = set(VOLATILE_XMM)
	for position in range(first, bound):
		free -= live[position]
		free -= set(scratch_finder.xmm_numbers(
			instructions[position][3] or ""))
	whole = set(scratch_finder.scope_free(scope, instructions[first][0]))
	return free | whole, whole


def span_helper(scope, address, entries):
	"""The xmm registers free across the whole span, fewest first.

	Two are wanted where the span carries a register-second-source
	operation, because a slot cannot be that operation's memory operand --
	SSE wants it 16-byte aligned and nothing aligns a slot (Finding 152).
	One is enough for every other shape.

	**The whole-function argument and nothing cleverer**, deliberately.
	`find_scratch` answers for a POINT and a span needs a register dead at
	every instruction in it; `assign_helpers` answers per position, which is
	what a run wants because a run can change helper mid-flight and a span
	cannot -- the slot traffic all goes through one register. So this asks
	`function_scope`, which says a register the function never names is free
	everywhere in it, and then removes anything the span's own operands
	mention.

	That is blunt and it is the first increment's bound rather than the
	mechanism's. Finding 141 built the per-position machinery for
	general-purpose registers and nobody has pointed it at xmm.
	"""
	free = set(scratch_finder.scope_free(scope, address))
	if not free:
		return ()
	for entry in entries:
		free -= set(scratch_finder.xmm_numbers(entry[4] or ""))
	return tuple(sorted(free))


def region_members(instructions, first, last, reasons=None):
	"""`(members, slots)` for a whole call-free region, or None.

	The span's walk without its two hard constraints. A span must begin at
	a 256-bit load and must CLOSE -- every value dead at the end -- and
	both are discharged here by the region's edges rather than by
	analysis: at a region's start every upper half is dead because the ABI
	kills them at a call, and at its end the same is true again.

	What is left is the one question Finding 147 named: **is every ymm this
	instruction reads defined by a 256-bit write since the region began?**
	A value that arrives from outside has its upper half in a machine ymm
	nothing here can reach, and one instruction like that spoils the whole
	region -- a representation is not something a program can have half of.

	Members carry the same three fields `ymm_span` produces, because
	`span_entries` and `lower_ymm_span` already read that shape and every
	member kind a region needs is one they emit.

	**`reasons` names the refusal.** Finding 171 named every refusal below
	this function and found the lowering refuses nothing, leaving this one
	at 5,610 -- nineteen times everything else together, and never broken
	down. A shape refusal names the SHAPE, through `span_shape_name`, so
	the histogram is a build list rather than a total. Finding 172.
	"""
	def refuse(why):
		if reasons is not None:
			reasons.append(why)
		return None

	members, slots, defined = [], {}, set()
	for position in range(first, last):
		_a, encoding, member_mnemonic, operands, _c = instructions[position]
		vex = inplace.decode_vex(encoding)
		if vex is None or not vex["L"]:
			members.append(("plain", position, None))
			continue
		shape = span_operand_shape(vex, encoding[vex["length"]:], operands,
		                           None, member_mnemonic)
		if shape is None:
			# The lowering cannot emit this shape. Which one it is decides
			# what to build next, so it is named and not just counted.
			return refuse("shape "
			              + (span_shape_name(encoding, operands) or "?"))
		what, register = shape[0], shape[1]
		if what == "load":
			if register not in slots:
				# **The permanent slot when shadows are on**, so a value
				# this region defines is visible to every later one. A
				# span-local index is invisible outside the span, which is
				# what makes a region unable to read a ymm defined
				# elsewhere. Finding 245.
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what == "insert":
			# Reads no slot -- both sources are machine registers -- and
			# DEFINES the destination's upper half, so it needs nothing
			# proved about what came before it.
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what == "permil":
			# Reads both sources' halves and defines the destination's.
			if shape[2] not in defined or shape[3] not in defined:
				return refuse("permil source from outside the region")
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what == "lanemem":
			# Reads src1's upper half and defines the destination's.
			if shape[2] not in defined:
				return refuse("lanemem source from outside the region")
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what in ("regmove", "lanemove"):
			# Reads the source's upper half and defines the destination's.
			if shape[2] not in defined:
				return refuse(f"{what} source from outside the region")
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what == "permmem":
			# Reads memory only, and defines the destination.
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what in ("bcastmem", "bcastreg"):
			# Defines the destination's upper half from a value that is
			# not an upper half at all, so nothing has to be proved about
			# what came before it.
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what == "extractmem":
			# Reads the source's upper half and defines nothing: the
			# destination is memory.
			if register not in defined:
				return refuse("extract-to-memory source from outside")
		elif what == "insertmem":
			# Reads memory and S1's low half; DEFINES the destination's
			# upper half, so nothing has to be proved about what it held.
			if shape[2] not in defined:
				return refuse("insert-from-memory source from outside")
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what == "perm2":
			# Reads both sources' halves and defines the destination's.
			if shape[2] not in defined or shape[3] not in defined:
				return refuse("perm2 source from outside the region")
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what == "extract":
			# Reads the SOURCE's upper half and defines the destination's.
			if shape[2] not in defined:
				return refuse("extract source from outside the region")
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		elif what == "lanereg3":
			# **Reads two and writes a third.** The destination is not a
			# source, so it need not be defined already -- this DEFINES
			# it -- but both sources must be, and the destination needs a
			# slot of its own.
			if shape[2] not in defined or shape[3] not in defined:
				return refuse("lanereg3 source from outside the region")
			if register not in slots:
				slots[register] = (shadow_index(register)
				                   if SHADOW_REGS_RULE == SHADOW_REGS_ALL
				                   and shadow_index(register) is not None
				                   else len(slots))
			defined.add(register)
		else:
			# Everything else READS the register it names, so the region
			# must already have defined it.
			if register not in defined:
				return refuse("reads a ymm defined outside the region")
			if what == "lanereg" and shape[2] not in defined:
				return refuse("lanereg second source from outside")
		members.append((what, position, register))
	if not slots:
		# Nothing in the region wrote a 256-bit value, so there is no upper
		# half to keep and nothing for a slot to hold. Not a defect: a
		# region of pure reads is simply not a region this represents.
		return refuse("no 256-bit definition, so no slot")
	return (members, slots)


def region_anchor(instructions, first, last):
	"""The position a region is offered at, or None if it has no site.

	**Once per region, at its first 256-bit SITE.** Once per region because
	asking at every member would build the same window many times and let
	the placer commit whichever it saw first. At the first site rather than
	the first INSTRUCTION because `region_candidate` is only ever called
	from `collect`'s 256-bit branch -- so a region whose head is an
	ordinary `mov` was never visited at all, unreachable by construction
	rather than outranked, which is a different failure from Finding 160's.

	`make why` found it on the frontier address: the region containing
	`0x1428d1492` begins at `mov %rdi,0x8(%r11)`, and no VEX site in it
	could ever have been the head.

	A function rather than a rule written twice, because `why.py` reports
	this and had its own copy for one commit -- long enough to print the
	old answer after the collector had the new one. Two places holding one
	rule is what `SPAN_EMITTABLE` exists to prevent between the survey and
	the lowering, met again between the explainer and the collector.
	"""
	for position in range(first, last):
		vex = inplace.decode_vex(instructions[position][1])
		if vex is not None and vex["L"]:
			return position
	return None


def region_candidate(instructions, plain, positions, index, blocked, home,
                     ranges, scope, tls, limit=24):
	"""A candidate lowering a whole call-free region, or None.

	Offered where the span declined, and it reaches what the span cannot:
	Finding 153 measured that every span which CLOSES is a load and a
	store, because arithmetic is exactly what keeps a value alive past the
	end. A region does not ask for closure, so arithmetic is what it is
	for.

	**The window stops before the terminating transfer.** `region_end`
	includes the call, because the liveness question needs it -- a call
	reads the argument registers. A window may not: a stub is entered by a
	jump and a call inside one has a return address to get right and unwind
	data to describe it. Ending before it costs nothing, since the upper
	halves are dead at the call either way, which is the whole reason the
	region ends there.

	`limit` is a cap on the window in instructions, and it is a placement
	bound rather than a correctness one. A region may run to 192, and a
	window that long swallows everything inside it and collides with every
	candidate it covers -- which is Finding 126's lesson at a scale nobody
	has measured. Small first, then widen with the binary as the judge --
	and widening it to 64 was measured and moved nothing, because the
	regions this offers run to twelve instructions and not to 192. The cap
	is not the bound and never was. Finding 157.
	"""
	first = region_start(instructions, index, blocked)
	if first is None:
		return None
	last = region_end(instructions, first, blocked)
	if last - first > limit:
		return None
	if region_anchor(instructions, first, last) != index:
		return None
	# **The liveness bound is the region's real end, the window's is not.**
	# `region_end` includes the terminating transfer because a call reads
	# the argument registers and the helper question needs that; a window
	# may not contain it, because a stub is entered by a jump. Keep both.
	bound = last
	closing = instructions[last - 1][2]
	if closing.startswith(CONTROL_PREFIXES):
		last -= 1
	if last - first < 2:
		return None
	told = []
	found = region_members(instructions, first, last, told)
	if found is None:
		why = told[-1] if told else "no reason"
		if why.startswith("reads a ymm"):
			# The dominant refusal, split by the edge it sits behind: only
			# a call makes the ABI argument, so only behind a call is this
			# a value the region could ever have owned. Finding 172.
			why += ", " + region_boundary(instructions, first, blocked)
		REGION_REFUSED["members: " + why] += 1
		seen = REGION_EXAMPLES.setdefault("members: " + why, [])
		if REGION_EXAMPLE_CAP is None or len(seen) < REGION_EXAMPLE_CAP:
			seen.append((instructions[first][0], instructions[index][0]))
		return None
	members, slots = found
	# Past this line the collector has SAID YES, so every refusal below is
	# the disagreement Finding 171 went after and each one is named.

	# **The region must close, exactly as the run and the span must.** A
	# region leaves each represented ymm's upper half in a SLOT and the
	# machine register's upper half untouched, so a 256-bit read after the
	# region ends reads whatever was there before -- and there is no
	# epilogue that could put it back, because writing a ymm's upper half
	# needs `vinsertf128`, which is itself VEX-256.
	#
	# The recorded justification was that "the region ends at a call", where
	# the ABI makes every upper half volatile. **That was false of all 166
	# regions the tool emitted**: not one ended at a call, because the
	# region is offered below the pair, the run and the span, and the span
	# refuses precisely when a value is still live at the end -- so the
	# region inherited the live-out cases as its leftovers. The shipped
	# image detoured 0x1407dac8b, kept the upper half in a slot, and
	# returned to `vmovups %ymm0,0x10(%rax)` at 0x1407dac98, still VEX,
	# storing sixteen correct bytes and sixteen stale ones.
	#
	# `upper_half_read_later` is the guard the pair got in Finding 38, the
	# run in Finding 64 and the span in Finding 153. Finding 65's table of
	# what each lowering leaves behind had no row for the region, and this
	# is what a missing row cost. Finding 173.
	# **`last - 1`, because the scan starts strictly after the index given**
	# -- `for step in range(1, limit + 1)`. `last` is exclusive and already
	# trimmed of a trailing transfer, so `last - 1` is the region's final
	# member and the walk begins on the first instruction it does not
	# cover. Passing `last` instead skips exactly that instruction, which
	# is the commonest place the stale upper half is read.
	if any(upper_half_read_later(instructions, last - 1, register,
	                             positions=positions)
	       for register in slots):
		REGION_REFUSED["upper half read after the region ends"] += 1
		return None
	address = instructions[first][0]
	tail_entry = instructions[last - 1]
	window = tail_entry[0] + len(tail_entry[1]) - address
	if window < 5:
		REGION_REFUSED["window under five bytes"] += 1
		return None
	if not inplace.covered_by(ranges, address, window):
		REGION_REFUSED["window outside .pdata"] += 1
		return None
	base, block = window_borrow(home, address, window), None
	# **A permanent slot is not a thing one window owns.** With
	# `--shadow-regs=all` a slot index is the REGISTER's, running to
	# `tls_block_slots()`, and addressing that off the callee home
	# space -- two slots wide -- writes `base + 4*16` and up into
	# somebody's locals. It does not fault and the fixture still
	# answered 77, which is the whole hazard `--rsp=blanket` exists
	# for. The block is the only backing store the representation
	# admits. Finding 246.
	if SHADOW_REGS_RULE == SHADOW_REGS_ALL:
		base = None
	need = (max(slots.values()) + 1) if slots else 0
	if base is None or len(slots) > SLOTS_PER_REGION:
		if tls is None or need > tls_block_slots():
			REGION_REFUSED[f"more slots than a store holds ({len(slots)})"] \
				+= 1
			return None
		free = sorted(window_gpr_free(home, address, window), reverse=True)
		if len(free) < 2:
			REGION_REFUSED["fewer than two dead GPRs for the block"] += 1
			return None
		base, block = tls[1], (free[0], free[1], tls[0])
	entries = span_entries(members, instructions, slots, scope, plain)
	# **The region's own liveness, not the whole function's.** This asked
	# `span_helper` -- the blunt whole-function rule -- while the survey
	# beside it computed the union with per-position liveness and reported
	# a far larger number. Finding 171 measured the gap at 192 regions
	# refused for want of one xmm.
	free, _whole = region_helpers(plain, instructions, first, bound,
	                              blocked, scope)
	for entry in entries:
		free -= set(scratch_finder.xmm_numbers(entry[4] or ""))
	helpers = tuple(sorted(free))
	if not helpers:
		REGION_REFUSED["no xmm helper free across the region"] += 1
		return None
	second = helpers[1] if len(helpers) > 1 else None
	told = []
	if lower_ymm_span(entries, base, helpers[0], address, address, block,
	                  second, told) is None:
		REGION_REFUSED[told[-1] if told else "lowering refused, no reason"] \
			+= 1
		return None
	# **Labelled `region`, not `span`.** They share a lowering and nothing
	# else: a span walks from a load and must close, a region is bounded by
	# the ABI and carries arithmetic. Sharing the label made every tally
	# add them together, and that is how a build with the region switched
	# off read as "the anchor changed nothing" -- `span 21 windows` was 21
	# spans and zero regions, and looked exactly like 21 of a mixture.
	#
	# A count that cannot go to zero for one cause alone cannot serve as
	# the positive control for a null result about that cause. Finding 167.
	return (address, instructions[first][1], instructions[first][3],
	        instructions[first][2], window, [], None, [],
	        ("region", (entries, helpers[0], block, base, second)))


# **Why a site the unconditional lowering was offered was not taken.**
# The same shape as `REGION_REFUSED` and cleared beside it: this one is
# the measurement Finding 246 exists to take, so its histogram IS the
# result rather than a diagnostic beside it.
# **The lowerings that maintain a slot**, which is what the uniform
# representation needs of every 256-bit site. Everything else lowers a
# site by other means and leaves its upper half to the machine register,
# which under this representation is nobody maintaining it.
SLOT_CARRYING = ("span", "region", "unit")
# **Which non-volatile xmm each function saves**, filled once per run from
# `.pdata` and read by `unit_candidate` when no volatile register is free.
# See `saved_xmm_map`. Finding 255.
SAVED_XMM = {}

# **Borrows declined because the home-space slot would have landed on the
# function's own save area.** Counted rather than assumed zero: the guard
# is cheap and the alternative is a silent corruption of the one thing the
# non-volatile borrow depends on. Finding 256.
OVERLAP_REFUSED = Counter()

# **Why the backward fallback did not save a site the forward widening
# could not.** Keyed `(forward reason, backward reason)`, because the
# pair is the finding: a bucket named for the first blocker cannot say
# whether the second was the same wall or a different one, and those
# want different work. Finding 299.
BACKWARD_REFUSED = Counter()

# **Why the neighbour would not move**, keyed `(direction, reason)`.
# `moved_instruction` has taken a `reasons` Counter since Finding 88 and
# `build_stub` has passed one all along; the two widening call sites in
# the candidate loop passed nothing, so 113 sites whose real blocker is
# a passenger that will not lower were recorded only as "will not move".
# The mechanism existed and was wired at one of its three callers --
# an interface is only as wired as its least-used method. Finding 299.
WIDEN_REFUSED = Counter()

# The denominator for the table above, so a reader can see whether the
# rows sum past it -- one refused move can report more than one reason,
# and a row total above the site count means exactly that rather than an
# error. Finding 299.
WIDEN_SITES = Counter()

# How many instructions a unit window may absorb, longest first. 12 is what
# the strategy was built with; the rest are what it retries at when the long
# window cannot find a helper. Finding 276.
UNIT_LIMITS = (12, 6, 3, 1)

UNIT_REFUSED = Counter()
UNIT_EXAMPLES = {}

# **Which rung of the ladder each unit window was actually taken at.**
# `unit_shortening` descends from 12 members to 1 because "a greedy window
# starves its own helper", and it snapshots the refusal counters around the
# retries -- correctly, so a site that succeeds short does not also leave the
# long window's reason behind. The consequence is that a DESCENT is invisible:
# the roll shows only sites the whole ladder refused, 41 of them, while every
# window that placed shorter than it could have is unrecorded.
#
# That matters because the cost of a short window is not a refusal, it is an
# overlap -- `unit_shortening` says so itself, "a shorter window is one more
# likely to be overlapped by its neighbour" -- and there are 53,101 skipped
# for overlap against 41 refused. So the question of what helper pressure
# costs cannot be read off the refusal roll at all, in either direction.
# Finding 317.
UNIT_RUNG = Counter()

# **The rungs the ladder did not take, for the windows that can be
# dropped.** The stale-read repair withholds a whole window because of one
# instruction it swallowed, and at 1,318 windows for 1,364 survivors each
# drop costs about a site. 1,310 of those 1,318 are `unit` -- the one
# strategy that already knows how to build a shorter window and one in the
# other direction -- so the losing rungs are worth keeping, and the repair
# substitutes one rather than losing the site.
#
# **Keyed by the winning candidate's start**, which is what `dropped`
# holds, and NOT by the site: a window widened backwards starts on the
# instruction before its site, so the two differ exactly where it matters.
#
# **A callable, not a list**, so the ladder is re-walked only for the
# windows that are actually dropped. See `unit_shortening` for what the
# first version cost by deciding that up front with a predicate.
#
# A module-level map because `place_stubs` unpacks a candidate as a strict
# nine-tuple and a tenth field would break it. `apply` and `verify` run the
# same collection and so fill this identically, which is the property
# Finding 197 needs and the reason it is not a parameter. Finding 281.
UNIT_ALTERNATIVES = {}
REPAIR_SUBSTITUTED = 0

# **Why each dropped window was dropped**, keyed `(strategy, reason)`.
# The drop count alone says how much is being lost and nothing about
# where to push: a window with no ladder behind it and one that walked
# every rung and found each blamed are the same number and want
# opposite work. Finding 298.
# **Why each refused stub was refused, per site.** `place_stubs` has
# taken a `detail` dict since it was written and nobody has ever passed
# one, so `stub_reasons` tallied causes with no address to chase -- an
# interface as wired as its least-used caller, for the third time in
# this file. The frontier reported 43 sites `lost to a refused stub`
# when this was wired and there was no way to ask which 43 or why; the
# count is a measurement of that day, not a property of the tool.
# Finding 311.
STUB_DETAIL = {}

# **Bytes a rebuilt window gave up, which the census could not name.** The
# stale-read repair replaces a guilty window with another rung rather than
# dropping it, and the replacement is a DIFFERENT rung -- it may start
# earlier and it is usually shorter. A site the original covered and the
# replacement does not is then in no final extent, carries no decline
# because the collector did produce a candidate for it, and is not dropped
# because the window was rebuilt rather than dropped.
#
# So it fell through every test into `never a candidate` -- the bucket
# Finding 310 named as the place a mis-keyed lookup goes to be invisible,
# and which still has no assertion attached. Four sites, every one an
# ordinary three-register shape this tool lowers, sitting next to an FMA.
# Finding 319.
REPAIR_EXCLUDED = set()

# **Every 256-bit site the collector got past its own door.** Finding 310
# said the only thing that makes a bucket named for missing information
# honest is an assertion about what may land in it, and `never a candidate`
# still had none: it absorbed the rebuild casualties above for as long as
# the repair has been substituting windows, and nothing could have said so.
#
# This is the weaker claim that can actually be made -- not "the bucket is
# empty", which it is not, but "the bucket says which of two things
# happened". A site the loop refused at its head (not VEX, `(bad)`, inside
# a data island, already patched in place) never reached a strategy; a site
# past that point was offered to every one of them and a silent exit is a
# defect rather than a property of the binary. Finding 319.
COLLECT_SEEN = set()

REPAIR_READERS = set()
REPAIR_BLAMED_BY = defaultdict(set)
REPAIR_DROPPED_WHY = Counter()
REPAIR_DROPPED_SITES = Counter()

# **Where the blamed producer sits in the window it sank.** The split
# above says the ladder is being exhausted rather than missing; this
# says whether anything COULD have excluded the producer. A producer at
# the window's own first instruction is the site being lowered, and no
# shorter window that still lowers that site can leave it out -- those
# are a floor. An interior one is a window that wants splitting rather
# than shortening, which is a rung the ladder does not offer.
# Finding 298.
REPAIR_BLAME_WHERE = Counter()

# **Whether a gap in the window still holds a site to lower.** The
# position buckets are a proxy and a leaky one: they are measured
# against the ORIGINAL candidate's extent while blame accrues against
# whatever shape was placed that round, and "the window's own first
# instruction" is the SITE only when the window was not widened
# backwards -- which is exactly the case `unit` is built to exploit.
#
# This asks the question the proxy was standing in for. Cut the window
# at every producer blamed on it; if any surviving piece still contains
# a VEX site, a placement exists that lowers something and swallows
# none of the blame, and the ladder cannot reach it because every rung
# it offers is one contiguous run anchored at one end. Finding 298.
REPAIR_SPLITTABLE = Counter()

# **The candidate list the repair actually placed**, substitutions applied.
# Anything reconstructing a window's extent from an address must read this
# rather than `candidates`: a substituted window is refused or overlapped
# under its SUBSTITUTE's start, which appears in no original candidate, so
# a lookup there silently contributes nothing. That is what put 79
# survivors in the census's `unaccounted` bucket -- the one its own output
# says should be zero. Finding 282.
REPAIR_FINAL = []


WIDE_SITES = Counter()


def unit_shortening(instructions, plain, index, blocked, home,
                    ranges, scope, tls):
	"""`unit_candidate`, retried with shorter windows where it refuses.

	**A greedy window starves its own helper.** `unit_candidate` absorbs the
	whole run of adjacent 256-bit sites rather than stopping at five bytes,
	so its members name many registers -- measured at five to fourteen
	distinct xmm -- and the helper must avoid every one of them, because a
	helper is clobbered and a register any member READS cannot serve. With
	six volatile registers that is what leaves nothing. A window with fewer
	members touches fewer.

	So where the long window refuses, ask for a shorter one. The ladder is
	the absorption limit the function already takes, and it descends to a
	single site, which is the shape the strategy is named for.

	**The greed is not gratuitous and this is a trade, not a fix.** It
	exists because the first version produced one window per site, each
	overlapping the next -- three candidates built and one placed. A
	shorter window is one more likely to be overlapped by its neighbour, so
	this buys a helper with an overlap and only the binary says which wins.
	Finding 276.

	The refusal counters are snapshotted and restored around the retries,
	so a site that succeeds at a shorter length does not also leave the
	long window's reason behind -- the census would otherwise count a
	refusal for a site that was lowered.
	"""
	global UNIT_REFUSED, UNIT_EXAMPLES

	def snapshot():
		return UNIT_REFUSED.copy(), {why: list(seen)
		                             for why, seen in UNIT_EXAMPLES.items()}

	before = snapshot()
	last = None
	# Forward at every length, then backward at every length. Forward is
	# the direction the strategy was measured with, so it keeps first
	# refusal on every site it can serve, and backward is asked only for
	# what it leaves. Finding 277.
	rungs = [(cap, False) for cap in UNIT_LIMITS] \
		+ [(cap, True) for cap in UNIT_LIMITS]
	for rung, (cap, back) in enumerate(rungs):
		# **Each attempt starts from the snapshot**, so a site leaves ONE
		# refusal behind rather than one per rung. Without this a failing
		# site recorded all four, and the census every measurement here is
		# taken from would have been inflated fourfold for exactly the
		# sites it is consulted about. Measured once in that state: 14,724
		# refusals "of 48,388 sites", against 3,912 of 37,401.
		UNIT_REFUSED, UNIT_EXAMPLES = before[0].copy(), {
			why: list(seen) for why, seen in before[1].items()}
		lone = unit_candidate(instructions, plain, index, blocked, home,
		                      ranges, scope, tls, limit=cap, back=back)
		if lone is not None:
			UNIT_RUNG[(cap, "back" if back else "forward")] += 1
			# **Walked on demand, not now.** The ladder is eight rungs and
			# there are 35,428 unit windows, so building every rung at
			# every site is eight times the collection for an answer only
			# the dropped windows will ever read -- 1,318 of them.
			#
			# A closure rather than a filter, because the first version
			# WAS a filter -- "does this window hold a VEX.128 write" --
			# and it excluded 34,367 of 35,428 windows including 1,306 of
			# the 1,319 the repair went on to blame. A cheap predicate
			# standing in for the repair's own question got it wrong in
			# the direction that reports success: the substitution ran on
			# 13 windows, found an answer for one, and looked like a
			# mechanism that does not pay. Finding 281.
			def rebuild(taken=lone, at=index):
				# **Put the counters back.** This walks rungs that were
				# never taken, and `unit_candidate` records a refusal for
				# each -- so without the snapshot the census gains a
				# reason for every rung explored on behalf of a window
				# that was dropped. Measured in that state: refusals rose
				# 814 -> 2,457 and `too short to place, nothing follows`
				# came back at 264, which Finding 277 identified as an
				# artifact of the ladder rather than a property of the
				# binary. The image is unaffected either way, which is
				# exactly what makes it a measurement bug rather than a
				# wrong one. Findings 277 and 281.
				global UNIT_REFUSED, UNIT_EXAMPLES
				held = snapshot()
				spare = []
				# **One anchor, and splitting the window was measured
				# and does not pay.** Every rung here is a contiguous
				# run from `at`, so the ladder cannot express a window
				# that starts past a producer in the middle -- which
				# looked like the gap, because of 1,136 windows the
				# repair dropped, 1,036 had walked every rung and found
				# each blamed, and cutting those at the producers they
				# were blamed for left a piece still holding a VEX site
				# in 586.
				#
				# Anchoring the ladder at every site the window covers
				# reaches those pieces and the frontier got WORSE:
				# 2,346 -> 2,349. It recovered 130 sites from dropped
				# windows and gave back 53 to stubs that would not
				# build and 13 to overlap, the pieces being smaller and
				# more numerous; the census could not attribute a
				# further 67, the substituted-start blind spot of
				# Finding 282 arriving by a new route. It also took the
				# repair from 15 rounds to 103, because a substitution
				# creates fresh blame and the decay is not monotone.
				#
				# The window count is not the thing to optimise. 134
				# fewer windows were dropped and three more sites
				# survived, which is the whole lesson: a window is not
				# a unit of loss. Finding 298.
				for other_cap, other_back in rungs:
					other = unit_candidate(instructions, plain, at,
					                       blocked, home, ranges, scope,
					                       tls, limit=other_cap,
					                       back=other_back)
					if other is None:
						continue
					if (other[0], other[4]) == (taken[0], taken[4]):
						continue	# the window that was already dropped
					if any((item[0], item[4]) == (other[0], other[4])
					       for item in spare):
						continue
					spare.append(other)
				UNIT_REFUSED, UNIT_EXAMPLES = held
				return spare
			UNIT_ALTERNATIVES[lone[0]] = rebuild
			UNIT_REFUSED, UNIT_EXAMPLES = before
			return lone
		if last is None:
			last = snapshot()
	# **The FIRST rung's reason is kept, not the last.** Keeping the
	# shortest looked like keeping the most fundamental answer and is the
	# opposite: at `limit=1` the widening loop never iterates -- the
	# condition is `last - index < limit` with `last` already `index + 1`
	# -- so a site under five bytes refuses "nothing follows"
	# unconditionally, whatever was really wrong with it. That reason
	# reached 866 in one census and is an artifact of the ladder rather
	# than a property of the binary.
	#
	# The longest window's reason is what the census said before the ladder
	# existed, which also keeps every earlier measurement comparable.
	# Finding 277.
	UNIT_REFUSED, UNIT_EXAMPLES = last
	return None


def unit_candidate(instructions, plain, index, blocked, home,
                   ranges, scope, tls=None, limit=12, back=False):
	"""A candidate lowering ONE 256-bit instruction, or None.

	**The strategy none of the others is.** Every lowering above this one
	is CONSUMER-DRIVEN: a pair wants a load and a store, a run a chain of
	copies, a span a chain that closes, a region a stretch whose every
	definition it can see. All four ask the same question in different
	words -- *can I account for this value's upper half* -- and a site
	whose answer is no is left as VEX. That is why the frontier is what it
	is, and no amount of widening any one of them reaches a site whose
	value simply arrives from somewhere the walk cannot see.

	The uniform representation inverts the question. A 256-bit instruction
	is lowered BECAUSE IT IS 256-BIT: the upper half goes to the
	register's permanent slot, and nothing has to be proved about where
	the value came from or who reads it next. Provenance stops being a
	precondition, which is the whole purpose of `--shadow-regs=all`.

	**Three properties, and the third is not this function's to hold.**

	- It needs the per-thread block, never a home-space borrow. A borrowed
	  frame lasts as long as its window; a permanent slot has to outlive
	  every window in the image, so `--spill=tls` is not one backing store
	  among three here but the only one the representation admits.
	- It does not ask `upper_half_read_later`. Every other lowering must,
	  because it leaves the machine ymm's upper half stale and a later
	  256-bit read would see it. Here the slot IS the upper half, so a
	  later reader is correct -- **provided that reader is lowered too.**
	- Which is the third property, and it is a whole-image one: the
	  representation is sound only if it is TOTAL. One 256-bit site left
	  as VEX reads a machine upper half this has stopped maintaining, and
	  one VEX.128 write left in place zeroes a machine upper half while
	  the slot keeps the old value. So this function's refusals are not a
	  list of missed opportunities; each one is a hole in the invariant,
	  and `report_units` totals them as such. Finding 246.

	`limit` bounds how far the window may widen over neighbours to reach
	the five bytes a jump needs. Four rather than the region's twenty-four
	because a passenger here buys nothing but length: the member is one
	instruction and widening exists only to make it placeable.
	"""
	def refuse(why):
		UNIT_REFUSED[why] += 1
		seen = UNIT_EXAMPLES.setdefault(why, [])
		seen.append(instructions[index][0])
		return None

	if SHADOW_REGS_RULE != SHADOW_REGS_ALL:
		return None
	address, encoding, mnemonic, operands, _comment = instructions[index]
	vex = inplace.decode_vex(encoding)
	if vex is None or not vex["L"]:
		return None
	# **Asked AFTER the shape, which is the correction.** This read as a
	# property of the instruction set -- "no legacy encoding, so nothing
	# reaches it" -- and NO_LEGACY_FORM says no such thing. It forbids one
	# TECHNIQUE, clearing `VEX.L` and re-emitting, which for these
	# mnemonics produces bytes that decode to nothing. The semantics are
	# emitted on the plain path by `lower.py`, per shape, and four of them
	# are 16-byte moves once an upper half is a slot. Finding 246.
	shape = span_operand_shape(vex, encoding[vex["length"]:], operands, None,
	                           mnemonic)
	if shape is None:
		if mnemonic in NO_LEGACY_FORM:
			return refuse(f"{mnemonic} has no legacy encoding")
		return refuse("shape " + (span_shape_name(encoding, operands) or "?"))
	# See the note in `lower_ymm_span`: an FMA classifies as `lanemem`
	# and that shape is narrowed, so it must not take the
	# SLOT_SHAPES exemption. Finding 263.
	# The same door as the member guard, and it has to be the same door:
	# Finding 263 says "both guard sites now refuse an FMA whatever its
	# shape", so relaxing one and not the other would let the collector
	# build a window the emitter then refuses -- a candidate nobody can
	# place. Finding 300.
	fma_span = (mnemonic in FMA_SPAN_FORMS
	            and shape[0] in FMA_SPAN_SHAPES)
	if mnemonic in NO_LEGACY_FORM and not fma_span and (
			shape[0] not in SLOT_SHAPES
			or mnemonic in FMA_FORMS):
		return refuse(f"{mnemonic} has no legacy encoding")
	what, register = shape[0], shape[1]
	if shadow_index(register) is None:
		return refuse("destination is not one of the sixteen ymm")
	members, slots = [], {}

	def take(at, one):
		"""Give every register `one` names its permanent slot."""
		for named in one[1:]:
			if named is None:
				continue
			found = shadow_index(named)
			if found is None:
				return "a register outside the sixteen ymm"
			slots.setdefault(named, found)
		members.append((one[0], at, one[1]))
		return None

	# Every register the shape names resolves to its own permanent slot,
	# which is exactly what this representation is for: `region_members`
	# refuses a source it did not itself define, and here there is nothing
	# to refuse because every source already has one.
	# **Widening backward, where forward is blocked.** The window starts on
	# the instruction BEFORE the site and swallows the site itself -- the
	# second of the two directions this tool has always had, which the
	# plain path uses and this strategy did not. Measured at the refusal:
	# 837 sites end the forward walk under five bytes and 795 reach five
	# going the other way, 12 refused because the previous instruction
	# transfers control.
	#
	# **The branch-target refusal below fires 388 times, not the 30 that
	# probe reported** -- it sampled one rung of the ladder and this is
	# asked at four. Of the 388, 387 are refused further down anyway and
	# the one candidate that survives loses at placement, so removing the
	# guard leaves this binary's image byte-identical. That is why it is
	# watched by a fixture rather than by Starfield. Finding 279.
	#
	# The neighbour is carried in `preceding` rather than as a member:
	# `build_stub` emits that list before the span, which is the order it
	# already executed in, and `place_stubs` reads it to record which
	# boundaries a window swallows deliberately.
	#
	# **This used to add "as a member it is emitted correctly and accounted
	# nowhere", and that was wrong.** Measured: taken as a member the whole
	# of `verify` passes -- every boundary, every branch target, zero VEX in
	# the stub section -- because `swallowed` never recorded FORWARD members
	# either and `verify` derives an internal boundary from the window's
	# extent. Ordering needs nothing either: this block runs before the
	# site's own `take` and `span_entries` walks `members` in list order
	# with no sort, so the instruction that executes first is listed first.
	#
	# **The route is sound and does not pay, which is a different reason to
	# leave it alone.** A member's registers join the set the helper must
	# avoid, and 54 windows then found none -- a refusal reason that did not
	# previously exist, `no volatile xmm and scratch slot to stash it`. The
	# frontier held at 996 with detours unchanged at 202,259, which is what
	# shows nothing was lowered: the refusal moved from stub time to collect
	# time. Unplaced windows rose 443 to 471.
	#
	# So the asymmetry is real -- the forward walk below says a 256-bit
	# neighbour is a MEMBER, never a passenger, and this direction carries
	# one -- and closing it needs the helper demand to fall first. That is a
	# dependency between two items and it was invisible until one was built.
	# Finding 318.
	#
	# **It is `window_start` and not `start` because this function already
	# has a `start`** -- the enclosing FUNCTION's address, used for the
	# `SAVED_XMM` lookup forty lines below. The first two versions of this
	# called it `start` and anchored every window that reached the xmm
	# borrow at the head of its function, swallowing the prologue and a
	# `call`; `nonvol` and `unwindsave` answered 5 and `verify` named four
	# boundaries lost and a call no stub re-emitted. The emission was
	# correct throughout. Finding 277.
	window_start, first_member, carried = address, len(encoding), None
	if back:
		if index == 0:
			return refuse("nothing before it to widen into")
		if address in blocked and CODE_SABOTAGE != "backtarget":
			return refuse("widening back would bury a branch target")
		before_address, before_encoding, before_mnemonic, before_operands, \
			before_comment = instructions[index - 1]
		if before_address + len(before_encoding) != address:
			return refuse("previous not adjacent")
		if before_mnemonic.startswith(CONTROL_PREFIXES):
			return refuse("previous transfers control")
		if before_encoding[:1] == b"\x62":
			return refuse("previous is EVEX")
		carried = (before_address, before_encoding, before_comment,
		           before_operands, before_mnemonic,
		           swallowed_scratch(plain, index - 1, before_address,
		                             before_encoding, before_operands,
		                             before_mnemonic, scope))
		window_start = before_address
		first_member += len(before_encoding)

	told = take(index, shape)
	if told is not None:
		return refuse(told)

	# **Absorb the whole run of adjacent 256-bit sites, not just enough
	# bytes to place a jump.** The first version widened only while the
	# window was under five bytes, and on a cluster of lane operations
	# that produced one window per site, each overlapping the next: three
	# candidates built and one placed, because they were competing for the
	# same bytes. A strategy offered at EVERY 256-bit site collides with
	# itself in a way none of the consumer-driven ones can, since those
	# are offered at a site only when a walk found something to do there.
	#
	# So a neighbour that is itself 256-bit is taken whether or not the
	# window needs the length, and a plain one only while it does. The
	# conditions for crossing into either are the ordinary ones --
	# adjacent, not a branch target, not a control transfer -- because the
	# hazard is the same: an address in the middle of a window is an
	# address nothing may reach.
	last = index + 1
	window = first_member
	while last - index < limit and last < len(instructions):
		nxt_address, nxt_encoding, nxt_mnemonic, nxt_operands, _nc = \
			instructions[last]
		nxt_vex = inplace.decode_vex(nxt_encoding)
		wide_next = nxt_vex is not None and nxt_vex["L"]
		if not wide_next and window >= 5:
			break			# long enough, and nothing left to absorb
		stop = None
		if nxt_address != window_start + window:
			stop = "next not adjacent"
		elif nxt_address in blocked:
			stop = "next is a branch target"
		elif nxt_mnemonic.startswith(CONTROL_PREFIXES):
			stop = "next transfers control"
		if stop is None and wide_next:
			# **A 256-bit neighbour is a MEMBER, never a passenger.** A
			# passenger is emitted into the stub as it stands, and
			# emitting VEX into a stub is the one thing this tool exists
			# not to do -- `moved_instruction` refuses it, so carrying
			# one turns a four-byte site into `passenger cannot be
			# moved`. Taking it as a member lowers it instead, which is
			# what the representation says to do with any 256-bit
			# instruction whatever.
			nxt_shape = span_operand_shape(
				nxt_vex, nxt_encoding[nxt_vex["length"]:], nxt_operands,
				None, nxt_mnemonic)
			if nxt_shape is None:
				stop = ("neighbour " + nxt_mnemonic + " has no legacy form"
				        if nxt_mnemonic in NO_LEGACY_FORM
				        else "neighbour shape "
				             + (span_shape_name(nxt_encoding, nxt_operands)
				                or "?"))
			elif nxt_mnemonic in NO_LEGACY_FORM \
					and nxt_shape[0] not in SLOT_SHAPES:
				stop = "neighbour " + nxt_mnemonic + " has no legacy form"
			else:
				told = take(last, nxt_shape)
				if told is not None:
					stop = "neighbour names " + told
		if stop is not None:
			# Past five bytes the run simply ends here; under it, there is
			# no window to place and the reason is the refusal.
			if window >= 5:
				break
			return refuse("too short to place, " + stop)
		if not wide_next:
			members.append(("plain", last, None))
		window += len(nxt_encoding)
		last += 1
	if window < 5:
		return refuse("too short to place, nothing follows")

	if not inplace.covered_by(ranges, window_start, window):
		return refuse("window outside .pdata")
	# **The block, and only the block.** `window_borrow` is not consulted:
	# a home-space displacement is valid for the length of one window and
	# a permanent slot is not a thing one window owns.
	if tls is None:
		return refuse("no per-thread block, so no permanent slots")
	# **One dead register, not two.** The block pointer has to survive the
	# whole stub so it must be dead across the window; the index register
	# is clobbered for three instructions and put back, so it need not be
	# dead at all -- `encode_tls_base`'s stash saves it in an xmm, which
	# touches no memory and sets no flags. Where a second dead register
	# happens to exist the plain sequence is used, because it is ten bytes
	# shorter. Finding 247.
	free = sorted(window_gpr_free(home, address, window), reverse=True)
	lent = window_borrow(home, address, window)
	# **The callee home space is 32 bytes and three things may want it**:
	# the block's two GPR saves at 8 bytes each, the mover's one, and a
	# borrowed non-volatile xmm at 16. Handing out fixed offsets worked
	# while there were two claimants and would have silently overlapped
	# with a third, so it is allocated. Finding 255.
	home_used = 0
	if len(free) >= 2:
		base, block = tls[1], (free[0], free[1], tls[0], False, None)
	elif free and INDEX_CONST:
		# **One dead register is enough when the index is a constant.**
		# Mode True exists only to park a borrowed index register in an
		# xmm for three instructions; with the index folded into a
		# displacement there is no index register to park, so the site
		# needs neither the borrow nor the xmm. That is what dissolves
		# `mode True has no xmm to stash the index in`. Finding 293.
		base, block = tls[1], (free[0], None, tls[0], False, None)
	elif free:
		borrowed = next((n for n in sorted(GPR_NUMBERS[name]
		                                   for name in VOLATILE_GPRS)
		                 if n != free[0]), None)
		if borrowed is None:
			return refuse("no register to borrow for the index")
		base, block = tls[1], (free[0], borrowed, tls[0], True, None)
	else:
		# **No dead register at all, so borrow two live ones and give them
		# back.** The stash of the branch above frees the INDEX, which is
		# clobbered for three instructions; the block pointer has to hold
		# for every member, so freeing it needs somewhere that lasts the
		# whole stub. The callee home space is that somewhere, and reaching
		# it needs no register because `(%rsp)` is not a register the site
		# has to spare.
		#
		# **What these registers must be is UNNAMED, not dead.** They are
		# put back, so what the program does with them after the stub is
		# no business of this; what matters is that nothing inside the
		# window reads or writes them while the borrow stands. That is a
		# weaker test than `window_gpr_free` and it is why sites with
		# nothing dead can still be reached. Finding 249.
		spare = sorted(window_gpr_unnamed(home, address, window),
		               reverse=True)
		if len(spare) < 2:
			return refuse("fewer than two unnamed GPRs to borrow")
		base = tls[1]
		# **A stub still cannot allocate its own sixteen bytes**: a
		# chained fragment's UWOP_ALLOC_SMALL is not applied, so the
		# handler gets an establisher frame sixteen bytes out, and
		# unchaining to get the code applied loses the handler instead.
		# `unwindspill` measures it at 99. Findings 49, 67, 68 and 270.
		# Mode "teb" below takes the sixteen bytes somewhere that needs
		# no allocation and no unwind code at all.
		# **Unless the TEB is carrying it.** `lent is None` cannot be
		# reproduced by hand -- Finding 268 tried, and a leaf entered by
		# the loader still has the caller's home space above `rsp` -- so
		# the path is forced instead, exactly as mode "frame" was, and
		# `check-teb` asserts a teb block was really emitted before
		# believing the answer. Finding 280.
		if lent is None or (TEB_SCRATCH is not None
		                    and CODE_SABOTAGE in FORCE_TEB):
			if TEB_SCRATCH is None:
				return refuse("no dead GPR and no home space to save one")
			block = (spare[0], spare[1], tls[0], "teb",
			         teb_scratch_offset())
		else:
			block = (spare[0], spare[1], tls[0], "home", lent)
			home_used = 16

	entries = span_entries(members, instructions, slots, scope, plain)
	helpers, _whole = region_helpers(plain, instructions, index, last,
	                                 blocked, scope)
	for entry in entries:
		helpers -= set(scratch_finder.xmm_numbers(entry[4] or ""))
	helpers = tuple(sorted(helpers))
	# **Asked, not assumed.** Every member here may be one that moves a
	# half straight between a machine register and its slot, in which case
	# the window needs no vector register at all -- and the block pointer
	# only wants one in the middle mode, where an xmm holds the index for
	# three instructions. Finding 250.
	wants = any(kind not in HELPER_FREE for kind, _p, _r in members) \
		or (len(block) > 3 and block[3] is True)
	mover, mover_save, mover_slot = None, None, None
	# **One claim list for the block's four scratch slots.** The mover and
	# the xmm stash both draw from them and the mover is chosen first, so
	# a set each would hand the same slot out twice. Seeded from the slots
	# the members already occupy. Finding 267.
	claimed = {i for i in slots.values() if i < TLS_SLOTS}
	if wants and not helpers:
		# **A 16-byte move needs no vector register.** Where every member
		# that wanted a helper is a pure move, a general-purpose register
		# does the same work in two 8-byte halves. The arithmetic shapes
		# are not like this and get no second chance here. Finding 251.
		needy = frozenset(k for k, _p, _r in members) - HELPER_FREE
		# An arithmetic shape cannot use a general-purpose register at any
		# price and falls through to the non-volatile borrow below, which
		# is the only thing left that can serve it.
		if needy <= GPR_MOVABLE:
			taken = {block[0], block[1]}
			spare = [n for n in free if n not in taken]
			if spare:
				mover = spare[0]
			elif lent is not None and home_used + 8 <= HOME_SPACE:
				mover_save = lent + home_used
				home_used += 8
				borrowed = [n for n in sorted(window_gpr_unnamed(
					home, address, window)) if n not in taken]
				if not borrowed:
					return refuse("no register to borrow for the move")
				mover = borrowed[0]
			else:
				# **The home space is 32 bytes and the block carries 64
				# more.** The branch above wants eight of the callee's,
				# and where they are gone the same eight fit in one of
				# the per-thread block's scratch slots -- addressed off
				# the pointer this window has already stood up, which is
				# why the save has to be emitted after it rather than at
				# the top of the stub with the rest.
				#
				# Measured at this refusal: all 642 sites have a free
				# scratch slot, and mode True is no obstacle because the
				# mover is drawn from registers that exclude the block's
				# two. Finding 267.
				loose = [i for i in range(TLS_SLOTS) if i not in claimed]
				borrowed = [n for n in sorted(window_gpr_unnamed(
					home, address, window)) if n not in taken]
				if not loose or not borrowed:
					return refuse("no register to move a half through")
				mover_slot = loose[0]
				claimed.add(mover_slot)
				mover = borrowed[0]
	# **A non-volatile xmm, where the function itself saves it.** Finding
	# 124 refused xmm6-xmm15 outright, because the only way out of a live
	# borrow is a fault and the unwinder restores those from the primary's
	# `UWOP_SAVE_XMM128` codes -- which a function that never used the
	# register does not have. A function that DOES save it has the opposite
	# property: the unwinder restores the caller's value from the
	# function's own slot, whatever the borrow left behind. So the blanket
	# becomes a condition, and `saved_xmm_map` is that condition read from
	# the same bytes the unwinder will read. Finding 255.
	borrowed_xmm = ()
	stashed_xmm = ()
	if wants and not helpers and mover is None:
		start = None
		if home is not None:
			starts, ranges_here, _usable, _state = home
			at = bisect.bisect_right(starts, address) - 1
			if 0 <= at < len(ranges_here) and address < ranges_here[at][1]:
				start = ranges_here[at][0]
		saved = SAVED_XMM.get(start, frozenset()) if start is not None \
			else frozenset()
		# **Not NAMED by the window, which is weaker than dead**: this
		# saves and restores, so what the program does with the register
		# outside the stub is not the borrow's business -- only that no
		# member reads or writes it while the borrow stands.
		touched = set()
		for kind, position, _r in members:
			touched |= set(scratch_finder.xmm_numbers(
				instructions[position][3] or ""))
		usable = set(saved) - touched
		# **An FMA `lanereg3` wants one, not two.** `TWO_HELPERS` is
		# keyed by shape, and the shape is right for every other
		# mnemonic that wears it: two sources loaded into two helpers.
		# An FMA reads both of its slot sources as memory operands and
		# accumulates in one register. Asking for two anyway is what
		# cost the memory form 66 windows before `span_slot_op`
		# existed. Finding 301.
		need = 2 if any(kind in TWO_HELPERS
		                and not (kind == "lanereg3"
		                         and instructions[position][2]
		                         in FMA_ONE_HELPER)
		                for kind, position, _r in members) \
			else 1
		taken = []
		for register in sorted(usable):
			if len(taken) == need:
				break
			if lent is None or home_used + SLOT > HOME_SPACE:
				break
			where = lent + home_used
			# **Never over the function's own save area.** The condition
			# this borrow rests on is that the unwinder can restore the
			# caller's value from the function's slot; writing the borrow
			# into that slot would destroy exactly what makes it safe.
			# Measured to overlap nowhere in Starfield, and checked anyway
			# because "nowhere today" is not a property of the next
			# binary. Finding 256.
			clash = any(where < offset + SLOT and offset < where + SLOT
			            for offset in saved.values())
			if clash:
				OVERLAP_REFUSED[register] += 1
				continue
			taken.append((register, where))
			home_used += SLOT
		if len(taken) < need:
			# **A live VOLATILE xmm, stashed in the block's own scratch.**
			# The restriction above is an UNWIND argument and it is exact
			# for xmm6-15: a non-volatile register the function never
			# saves still holds the CALLER's value, and clobbering it
			# destroys that with no unwind code to repair it. xmm0-5 carry
			# no such obligation -- nothing preserves them across a call,
			# so an unwind past this frame owes the caller nothing for
			# them, and the save/restore this borrow already performs is
			# the whole requirement. Finding 124's blanket was about the
			# non-volatile half; the volatile case was never revisited
			# because `helpers` above already takes any xmm that is DEAD.
			#
			# The stash goes in the block rather than the callee home
			# space because home space is what actually binds. Measured at
			# the refusal, under the real window: of 1,122 sites, 890 have
			# a free volatile xmm, and only 314 of those have 32 bytes of
			# home space left once the GPR mover has taken its share. The
			# block carries four 16-byte scratch slots that no `unit`
			# window ever assigns -- every one of the 1,122 already has a
			# block pointer, and not one had a scratch slot in use.
			#
			# **Mode True cannot compose and is refused here rather than
			# emitted wrongly.** That mode stands the pointer up by
			# stashing the index GPR in an xmm helper, which is the very
			# register being borrowed, so the value a slot would hold is
			# gone before the slot exists. It costs 337 of the 890 and
			# wants its own change: stash the index in a slot too, and it
			# needs no xmm at all. Finding 262.
			if block is None:
				return refuse("no non-volatile xmm this function saves")
			spare = [i for i in range(TLS_SLOTS) if i not in claimed]
			loose = [n for n in VOLATILE_XMM if n not in touched]
			if len(loose) < need or len(spare) < need:
				return refuse("no volatile xmm and scratch slot to stash it")
			# **Mode True is rewritten HERE, not forty lines below.** The
			# guard after this one already rebuilds a mode True block as
			# one wanting no xmm -- but it runs after the borrow, so the
			# borrow was refusing a slot stash on the strength of a mode
			# that was about to change. 322 of 381 sites refused "no
			# non-volatile xmm this function saves" have a free volatile
			# xmm, a free slot and somewhere for the block's own saves:
			# they were declined by the order of two decisions rather than
			# by anything the site lacked. Finding 269.
			if (len(block) > 3 and block[3] is True
					and CODE_SABOTAGE != "modetrue"):
				rebuilt = block_off_xmm(block, mover, home, instructions,
				                        index, address, window, lent,
				                        home_used)
				if rebuilt is None:
					return refuse("no non-volatile xmm this function saves")
				block, home_used = rebuilt
			elif len(block) > 3 and block[3] is True:
				return refuse("no non-volatile xmm this function saves")
			stashed_xmm = tuple(zip(loose[:need], spare[:need]))
			claimed.update(slot for _r, slot in stashed_xmm)
			helpers = tuple(register for register, _s in stashed_xmm)
		else:
			borrowed_xmm = tuple(taken)
			helpers = tuple(register for register, _o in taken)
	if wants and not helpers and mover is None:
		# A mover is not a helper, and a window served by one wants no
		# vector register at all -- refusing here for want of one refused
		# every GPR-movable window the moment this check was added.
		return refuse("no xmm helper free at the site")
	block = block[:5] + (mover, mover_save, borrowed_xmm, stashed_xmm,
	                     mover_slot)
	first = helpers[0] if helpers else None
	second = helpers[1] if len(helpers) > 1 else None
	# **Mode True stashes a LIVE index register in an xmm, so it cannot
	# stand without one.** The index is chosen as the lowest volatile GPR
	# that is not the block pointer and is NOT checked for being dead --
	# Finding 247 says in as many words that it "need not be dead at all"
	# because the stash saves it. With no xmm the emitter is handed None,
	# `encode_tls_base` emits no stash, and the register is loaded with the
	# TLS index and never put back.
	#
	# The two halves are each correct and were never guarded together.
	# Finding 251's mover runs BEFORE the xmm borrow and, when it finds a
	# general-purpose register, the borrow block is skipped entirely -- so
	# `helpers` stays empty and mode True loses the one thing it depends
	# on. A GPR cannot serve: the stash is a `movq` between a GPR and an
	# xmm precisely because memory would need a register to address.
	#
	# Measured on Starfield: 2,213 mode True candidates, 1,675 of them
	# with no xmm at all and a mover in every one. Read out of the image
	# at 0x140055e9e, whose stub loads the index into %rax and never
	# restores it -- while the original sets %rax to zero four
	# instructions above and reads it five below, so the program stored
	# the TLS index where it meant to store nothing. `verify` cannot see
	# this: it reads decoding, VEX survival and stale upper halves, not
	# liveness. Finding 264.
	if len(block) > 3 and block[3] is True and first is None \
			and CODE_SABOTAGE != "modetrue":
		# **The sites the borrow above left unserved.** It rewrites the
		# mode when it takes a slot stash; this catches a mode True block
		# that reached here with no xmm at all -- Finding 264's defect,
		# where the mover won and the borrow was skipped entirely, so the
		# emitter would have been handed `helper=None` and emitted no
		# stash, leaving a live index register clobbered.
		#
		# Both callers go through `block_off_xmm` so there is one
		# derivation rather than two that drift. Findings 264, 265, 269.
		rebuilt = block_off_xmm(block, mover, home, instructions, index,
		                        address, window, lent, home_used)
		if rebuilt is None:
			return refuse("mode True has no xmm to stash the index in")
		# **The tail, which the helper does not carry.** `block` is the
		# ten-tuple by the time this runs -- mover, mover_save, the two
		# borrows and the mover's slot -- while `block_off_xmm` returns
		# only the five fields that describe the pointer. Dropping the
		# rest took `block[5]` away, and `lower_ymm_span` allows a member
		# no helper only where a mover is there: 2,025 sites refused
		# "member load/store wants a helper and has none" and the frontier
		# went backwards by 531. The borrow's caller above is unaffected
		# because `block` is still five fields there. Finding 269.
		block, home_used = rebuilt[0] + block[5:], rebuilt[1]
	told = []
	if lower_ymm_span(entries, base, first, address, address, block,
	                  second, told) is None:
		return refuse(told[-1] if told else "lowering refused, no reason")
	# **`preceding`, which is field SEVEN, not field five.** A candidate is
	# `(start, encoding, operands, mnemonic, window, displaced, scratch,
	# preceding, strategy)`, and `preceding` is the slot for instructions
	# BEFORE the site -- exactly what widening backward produces. Put in
	# `displaced` instead it is still emitted, so every fixture passed,
	# and `place_stubs` accounts it as though it were AFTER the site:
	# `swallowed.add(entry[0])` marks the window's first byte, which keeps
	# its boundary, and never marks the site, which loses one. 22
	# boundaries lost that were not swallowed on purpose, every one a
	# four-byte `vmovups %ymm0,(%rax)` behind a four-byte `vpxor`.
	# Finding 277.
	return (window_start, encoding, operands, mnemonic, window, [], None,
	        [carried] if carried is not None else [],
	        ("unit", (entries, first, block, base, second)))


def report_units(candidates, placed, home, wide=0, original=None):
	"""What the unconditional lowering reached, and what the invariant needs.

	**Two denominators, and reporting one of them was a defect.** The first
	version printed the refusals against `wide` -- every 256-bit site in the
	image -- and called them "holes in it". That is the wrong population in
	the flattering direction, twice over.

	`unit_candidate` is offered LAST, so it is only ASKED at a site every
	other strategy declined: on Starfield that is 3,553 of 35,844, and a
	deficit quoted against the larger number reads an order of magnitude
	better than it is.

	And the sites it was never asked about are not therefore safe. `pair`,
	`run`, `zero`, `spill` and the ordinary path lower a 256-bit site
	without maintaining any slot, because they were written before slots
	existed and answer a different question. Under the uniform
	representation each of those is a hole too -- a machine upper half
	nobody maintains, read by whatever comes next.

	So the honest figure is the one this prints last: how many 256-bit
	sites are covered by a lowering that CARRIES a slot, against how many
	there are. Finding 246.
	"""
	if SHADOW_REGS_RULE != SHADOW_REGS_ALL:
		return
	taken = sum(1 for c in candidates if c[8] and c[8][0] == "unit")
	missed = sum(UNIT_REFUSED.values())
	asked = taken + missed
	if OVERLAP_REFUSED:
		print(f"apply: non-volatile borrows declined for landing on the "
		      f"function's own save area: {sum(OVERLAP_REFUSED.values()):,}")
		for _r, _n in sorted(OVERLAP_REFUSED.items()):
			print(f"apply:   xmm{_r:<3} {_n:>7,}")
	print(f"apply: unconditional lowering: {taken:,} built, "
	      f"{missed:,} refused, of {asked:,} sites it was asked about")
	for why, count in sorted(UNIT_REFUSED.items(), key=lambda kv: -kv[1]):
		print(f"apply:   {why:<52} {count:>7,}")
		for site in UNIT_EXAMPLES.get(why, [])[:3]:
			print(f"apply:       site {site:#x}")
	from pathlib import Path		# imported here as elsewhere in this file
	roll = Path("build") / "unit-refused.txt"
	if roll.parent.is_dir():
		with roll.open("w", encoding="utf-8") as out:
			# **Name the image, because the path is fixed.** A fixture run
			# overwrote Starfield's 3,216 rows with an empty file and
			# nothing said so -- Finding 240's fault, met again by a roll
			# written a day after that one was fixed.
			out.write(f"# {original}\t{missed:,} refused\t"
			          f"{run_configuration()}\n")
			for why, rows in sorted(UNIT_EXAMPLES.items()):
				for site in rows:
					out.write(f"{why}\t{site:#x}\n")
		print(f"apply: every refused site written to {roll}")
	if BACKWARD_REFUSED:
		# **The pair, because neither half is the finding on its own.**
		# A site too short to detour tries forward and then backward,
		# and only the forward reason reaches `declined` -- so the
		# frontier census reports 228 under `next instruction is a
		# branch target` without saying whether the fallback met the
		# same wall or a different one. Same shape as the repair's
		# drop total in Finding 298: a bucket named for the first
		# blocker cannot say which blocker operated. Finding 299.
		total = sum(BACKWARD_REFUSED.values())
		print(f"apply: {total:,} short site(s) declined, by what stopped "
		      f"the forward widening and then the backward fallback:")
		for (ahead, behind), count in BACKWARD_REFUSED.most_common():
			print(f"apply:   {ahead:<38} then {behind:<34} {count:>6,}")
	if WIDEN_REFUSED:
		# The half of the pair above that is not geometry: a neighbour
		# that COULD be swallowed and will not lower as a passenger.
		print(f"apply: and why a neighbour would not move, over "
		      f"{WIDEN_SITES['forward']:,} declined site(s) whose forward "
		      f"move was refused and {WIDEN_SITES['backward']:,} whose "
		      f"backward move was (a refusal may give more than one "
		      f"reason):")
		for (way, why), count in WIDEN_REFUSED.most_common():
			print(f"apply:   {way:<9} {why:<58} {count:>6,}")
	# **The figure that answers whether the representation is whole.**
	# Counted from the windows actually PLACED, not from candidates built:
	# a candidate the placer dropped maintains nothing.
	if home is None:
		return
	plain = home[3]["plain"]
	starts = [row[0] for row in plain]
	kind_of = {}
	for entry in candidates:
		strategy = entry[8]
		kind_of[entry[0]] = strategy[0] if strategy is not None else "plain"
	carried = 0
	for address, window, _stub, _body, _prologue in placed:
		if kind_of.get(address, "plain") not in SLOT_CARRYING:
			continue
		low = bisect.bisect_left(starts, address)
		high = bisect.bisect_left(starts, address + window)
		for position in range(low, high):
			vex = inplace.decode_vex(plain[position][1])
			if vex is not None and vex["L"]:
				carried += 1
	print(f"apply: 256-bit sites lowered through a slot: {carried:,} of "
	      f"{wide:,}")
	if carried < wide:
		print(f"apply:   {wide - carried:,} are not, so the representation "
		      f"is not whole: each is lowered by a")
		print(f"apply:   strategy that maintains no slot, or not lowered "
		      f"at all -- an upper half nobody keeps")



def span_candidate(instructions, plain, positions, index, blocked, home,
                   ranges, scope, tls=None):
	"""A candidate that lowers a whole 256-bit span, or None.

	The span is the analysis Finding 133 built and Findings 140 and 143
	priced; this is what turns one into a window the placer can commit.
	Every condition below is a way the representation fails rather than a
	tidiness rule:

	  * it must CLOSE -- every upper half dead at the end -- which
	    `ymm_span` decides;
	  * the function must lend enough slots at one displacement, which is
	    `window_borrow`'s question and not `borrow_offset`'s, because the
	    save and the restore are written once for the whole window;
	  * one xmm must be free across all of it, since the slot traffic goes
	    through a single register;
	  * and every member must be a shape `lower_ymm_span` can emit, which
	    is asked by building the bytes rather than by classifying.
	"""
	address, encoding, mnemonic, operands, _c = instructions[index]
	found = ymm_span(instructions, index, blocked, positions)
	if found is None:
		return None
	members, last, peak = found
	tail_entry = instructions[members[-1][1]]
	window = tail_entry[0] + len(tail_entry[1]) - address
	if window < 5 or not inplace.covered_by(ranges, address, window):
		return None
	slots = {}
	for _kind, _position, register in members:
		if register is not None and register not in slots:
			slots[register] = len(slots)
	# **The frame first, the block second**, for `--spill=tls`'s reason: a
	# displacement from `rsp` needs no register and no directory raised, so
	# it is strictly cheaper wherever it serves. `window_borrow` answers for
	# the callee home space AND the caller's shadow -- whichever this
	# function will lend -- but for one of them, not both: the two are 32
	# bytes each at different displacements, and a span writes its slot
	# addressing once.
	base, block = window_borrow(home, address, window), None
	if base is None or peak > SLOTS_PER_REGION:
		# Neither frame region will serve, or the span wants more slots
		# than one of them holds. A per-thread block has neither limit: it
		# is as large as `SizeOfZeroFill` asks, and TLS_SLOTS is what this
		# image asks for. What it costs is two general-purpose registers
		# dead across the WHOLE span, which is `window_gpr_free`'s
		# question -- one to hold the block and one to index it, and
		# neither restored, exactly as Finding 142's borrow does.
		if tls is None or peak > TLS_SLOTS:
			return None
		free = sorted(window_gpr_free(home, address, window), reverse=True)
		if len(free) < 2:
			return None
		base, block = tls[1], (free[0], free[1], tls[0])
	if len(slots) > max(SLOTS_PER_REGION, TLS_SLOTS if block else 0):
		return None
	entries = span_entries(members, instructions, slots, scope, plain)
	free = span_helper(scope, address, entries)
	if not free:
		return None
	helper = free[0]
	second_helper = free[1] if len(free) > 1 else None
	if lower_ymm_span(entries, base, helper, address, address, block,
	                  second_helper) is None:
		return None
	return (address, encoding, operands, mnemonic, window, [], None, [],
	        ("span", (entries, helper, block, base, second_helper)))


def value_survives_loop(instructions, index, register, blocked, sources,
                        limit=32):
	"""True if the loop this store heads cannot disturb the register.

	Finding 82 refuses a zero store that is itself a branch target, because
	another path reaches it without passing the zeroing. **Nineteen of the
	twenty-one it refused were correct anyway**, and all of one shape: a
	`memset` loop whose head is the store, whose body writes the register
	nowhere, and whose only entry is that head. The register is zero on the
	fall-through by the walk below, and zero on every later iteration because
	nothing between the head and the back edge touches it.

	That is an induction, and it needs all of its premises:

	  * **every** edge into the store comes from inside the body, so there is
	    no third path carrying an unknown value;
	  * **no instruction in the body is a branch target**, or control could
	    enter mid-loop and reach the back edge without ever passing the head;
	  * nothing in the body **writes** the register, in either spelling;
	  * no call and no unconditional transfer out, a call being opaque and
	    the upper half of every ymm volatile across one.

	Refusing when `sources` is absent keeps every other caller conservative.
	Finding 83.

	**The induction is about the register, not about what is in it.** Nothing
	below asks what the value is -- only that no path into the head carries a
	different one, and that the body writes it nowhere -- so it serves the
	read-only constant `constant_ymm` proves exactly as it serves a zero.
	"""
	address = instructions[index][0]
	incoming = sources.get(address) if sources else None
	if not incoming:
		return False			# indirect, or no direct source at all
	last = max(incoming)
	if any(source <= address for source in incoming):
		return False			# an edge from outside the body
	narrow = "%xmm" + register[len("%ymm"):]
	for step in range(1, limit + 1):
		position = index + step
		if position >= len(instructions):
			return False
		at, _encoding, mnemonic, operands, _comment = instructions[position]
		if at > last:
			return False		# walked past the back edge without meeting it
		if at in blocked:
			return False		# the body is enterable somewhere other than
						# its head
		if mnemonic in UPPER_HALF_KILLERS:
			return False		# the body clears every upper half
		fields = inplace.split_operands(operands)
		if fields and fields[-1] in (narrow, register):
			return False		# the body writes it
		if at == last:
			return True		# the back edge, and nothing on the way wrote
		if mnemonic.startswith(CONTROL_PREFIXES) \
				and not conditional_branch(mnemonic):
			return False		# a call, or a jump out of the body
	return False


def predecessors_of(instructions, position, sources):
	"""Positions that can fall or branch into `position`, or None.

	`None` means the set is not knowable -- a `.pdata` function start is
	reachable by an indirect call that no direct-branch map enumerates, and
	answering from the edges that ARE known would be answering about some
	of the ways in. 121 of the 605 joins the stale-read walk stalls on are
	that shape. Finding 190.
	"""
	if sources is None:
		return None
	address = instructions[position][0]
	# **Blocked, but no branch names it: the ways in are not enumerable.**
	# This only refused when the way list came out EMPTY, which happens
	# just when the target is preceded by `int3` padding. A chained
	# `.pdata` fragment starting mid-block kept its fall-through and was
	# answered from it -- 57 resolutions resting on the assumption this
	# file already closed as unsafe, that a `.pdata` start is reachable
	# only the ways a direct-branch map can see. Two counterexamples
	# settled that; this is the same assumption wearing a different hat.
	# Finding 193.
	if address not in sources:
		return None
	ways = []
	# Each way is `(position, inclusive)`. A FALL-THROUGH predecessor is an
	# ordinary instruction that may itself write the register, so the walk
	# must examine it; a BRANCH predecessor is the edge's terminator, which
	# defines nothing, and the walk must start behind it. Passing the same
	# index for both landed step 1 on the `jmp` and refused it as a control
	# transfer -- 73 of the 248 sources this could not resolve, and 8 of
	# them are real stale reads. Finding 193.
	before = position - 1
	if before >= 0:
		prior = instructions[before]
		if prior[0] + len(prior[1]) == address:
			if not prior[2].startswith(CONTROL_PREFIXES) \
					or conditional_branch(prior[2]):
				ways.append((before, True))
	index_of = {row[0]: i for i, row in enumerate(instructions)} \
		if len(instructions) < 4096 else None
	for origin in sources.get(address, ()):
		if index_of is not None:
			if origin not in index_of:
				return None
			ways.append((index_of[origin], False))
		else:
			found = address_position(instructions, origin)
			if found is None:
				return None
			ways.append((found, False))
	return ways or None


def address_position(instructions, address):
	"""The index of `address`, by bisection over a sorted listing."""
	low, high = 0, len(instructions) - 1
	while low <= high:
		middle = (low + high) // 2
		here = instructions[middle][0]
		if here == address:
			return middle
		if here < address:
			low = middle + 1
		else:
			high = middle - 1
	return None


# How many times the loop fixpoint may grow its assumption before giving
# up. The lattice is finite -- subsets of the definitions in one function --
# so it terminates on its own; the bound is a cost ceiling, and exhausting
# it is a refusal like every other budget here.
class JoinCycle(Exception):
	"""The walk re-entered a join it is already inside.

	**A cycle through the predecessor graph is a loop, and this project
	already knows what to do with one.** `loop_fixpoint` handles the back
	edge it can see in listing order -- a predecessor at a higher index --
	and refused the ones it could only see as recursion, 27 of the 230
	unresolved sources at depth 16. The ancestor that owns the cycle
	catches this and re-runs itself as a fixpoint, with itself assumed;
	the re-entry then reads the assumption instead of raising. A cycle
	naming a different ancestor propagates to it. Finding 197.
	"""

	def __init__(self, position):
		super().__init__(position)
		self.position = position


def refuse(why, reason, address=None):
	"""Record why the walk gave up, and give up. Always None.

	**A count of unresolved sources is not a list of reasons**, and the
	project has twice acted on a breakdown measured when the total was
	something else. `why` is None on every hot path; the census passes a
	list and reads the FIRST entry, which is the deepest refusal rather
	than the one that propagated out. Finding 197.
	"""
	if why is not None:
		why.append((reason, address))
	return None


LOOP_ROUNDS = 6

# How many times `apply` may drop windows and re-place. Dropping one
# un-swallows what it covered, which can expose a producer that was hidden
# inside it, so the repair has to settle rather than run once. Finding 197.
#
# **This is a safety valve and was being used as a termination
# condition.** At 6 the loop fell out of its `range` having settled
# nothing, placed the windows it had just called guilty, and said nothing
# -- the failure then surfaced downstream as "the producer is not an
# in-place patch and cannot be reverted", which is a misattribution: the
# producer IS a patch, inside a window the repair gave up on. That wrong
# message is why the class read as an irreducible floor rather than as a
# cap set too low.
#
# ~~Measured under `--shadow-regs=all` ... the repair settles after 15
# rounds ... 64 is headroom over a measured 15.~~ **It is 56, and 64 was
# eight rounds away from refusing to build anything.** Re-measured
# 2026-09-21 on both configurations:
#
#     default build          56 rounds,   693 windows dropped
#     --teb-scratch=auto     56 rounds, 1,136 windows dropped
#
# The 15 was taken when `--shadow-regs=all` was new and did not survive
# the two default flips after it, which is the shelf life of a fact
# recorded without a way to re-take it: the decay it quoted lived in a
# session and not in the tool, so nothing could show the margin closing.
# `REPAIR_DECAY` is that trace, and it prints.
#
# **The round count is a property of the binary, not of the flags.** The
# two runs above share their last 41 rounds value for value -- the same
# stubborn windows in both -- so turning a flag off does not buy margin.
# And the decay is NOT monotone: it rises 17 times on the way down, as
# each substitution creates fresh blame, so no safe bound can be
# extrapolated from the early rounds.
#
# 256 is roughly the same multiple over 56 that 64 was meant to be over
# 15. A higher cap costs nothing when the loop settles, because it
# breaks as soon as nothing is guilty; it costs about three seconds a
# round only in the case it exists for, which is a reasoning error.
#
# The loop terminates without any cap -- `spent` and `dropped` only
# grow and a substitute inherits no ladder of its own -- so exceeding
# this means the reasoning is wrong, and `repaired_placement` refuses
# rather than shipping. Measured deliberately at a cap of 8: it refuses,
# naming 440 dropped. Findings 259 and 298.
REPAIR_ROUNDS = int(os.environ.get("ANTI_AVX_REPAIR_ROUNDS", "256"))

# The newly-guilty count per round, which is the evidence the paragraph
# above rests on. It was quoted there from a measurement nobody could
# re-take: the trace existed in a session and not in the tool, so the
# next person to move a rung -- which is what Finding 298 did -- had no
# way to see whether the loop was converging slowly or not at all.
# A fact recorded without its method has a shelf life.
REPAIR_DECAY = []

# How many joins deep the stale-read walk may recurse. It was 4 because 4
# was enough for the memset shape Finding 84 built it for, and a census of
# the unresolved sources found **77 of 257 refused on it** -- the largest
# attackable class, quoted for months as part of an indirect-entry floor it
# has nothing to do with.
#
# Swept 4/8/16/32/64 over one setup: the class empties at 16 and 32 and 64
# find nothing more, so this is where it converges rather than where the
# budget ran out. It costs nothing measurable -- 9 seconds against 8, in a
# step whose setup is 514 -- because a deeper walk is only entered by the
# few readers that need it. Finding 197.
JOIN_DEPTH = 16

# The same budget for the COLLECTOR's two questions -- `zeroed_ymm` asking
# whether a register is all zero, `constant_ymm` asking where a constant
# came from. It was 4 while the gate's was raised to 16, which is how one
# walk came to be counted twice: 1,046 sites declined "ymm value has no
# known upper half" and 208 readers the gate cannot resolve are the same
# analysis at two budgets. Finding 201.
VALUE_DEPTH = 16


def loop_fixpoint(instructions, position, register, blocked, limit, sources,
                  depth, visiting, assume, ways, why=None):
	"""The definitions reaching a join with a back edge, or None.

	**Assume the back edge contributes nothing, then check the assumption
	rather than keeping it.** That distinction is the whole of this
	function. A prototype simply skipped back edges and reported 508
	resolutions against 61 stale reads, and Finding 193 recorded it as
	unsound and not to be gated -- rightly, because a loop that rewrites
	the register on its second iteration is exactly what the skip cannot
	see, and skipping says the value is whatever the first iteration left.

	Iterating repairs it. Start the assumption at the empty set, evaluate
	every way in under it, and union what comes back; stop when a round
	adds nothing, which makes the assumption a fixpoint of the equation it
	stands in. Reaching definitions is a union analysis over a finite
	lattice, so the ascent from the empty set terminates and lands on the
	LEAST fixpoint -- the one that assumes nothing it has not derived.

	The difference from the skip is visible in one round: the skip stops
	after evaluating the forward ways, this one then walks the back edge
	with what it has and asks whether the loop body can add a definition.
	Where the body writes the register, that write comes back and the
	assumption grows to include it; the skip never asked. Where the body
	does not, the second round adds nothing and the two agree -- which is
	why the skip looked right on the cases anybody checked.

	`value_survives_loop` still answers first, because it is cheap and
	proven and covers the memset shape this project met earliest. This runs
	only where that says no, so it adds resolutions and removes none.
	Finding 195.
	"""
	current = frozenset()
	for _ in range(LOOP_ROUNDS):
		seen = dict(assume) if assume else {}
		seen[position] = current
		answers = set()
		for way, inclusive in ways:
			answer = reaching_definitions(
				instructions, way + 1 if inclusive else way, register,
				blocked, limit, sources, depth - 1, visiting | {position},
				seen, why)
			if answer is None:
				return None
			answers |= answer
		if answers <= current:
			# The assumption reproduced itself: a fixpoint, and sound.
			return set(current) or refuse(
				why, "loop decided nothing", instructions[position][0])
		current = frozenset(current | answers)
	return refuse(why, "loop did not converge", instructions[position][0])


def reaching_definition(instructions, index, register, blocked, limit=640,
                        sources=None, depth=4, visiting=frozenset(),
                        assume=None, why=None):
	"""The single position `register`'s value was decided at, or None.

	A wrapper on `reaching_definitions`, which answers with the SET of
	positions the ways into a join reach. A caller wanting one answer --
	`zeroed_ymm` asking whether the value is a zeroing idiom,
	`constant_ymm` asking where a constant came from -- gets one only when
	the ways agree, which is the conservative reading and what both have
	always had. `stale_upper_reads` wants the set, because its question is
	"is ANY of them a site this rewrite touched". Finding 194.
	"""
	try:
		found = reaching_definitions(instructions, index, register, blocked,
		                             limit, sources, depth, visiting, assume,
		                             why)
	except JoinCycle:
		# **A cycle nobody anchored is a refusal, never a crash.** Letting
		# one escape would abort the caller mid-run, which is how Finding
		# 188 lost `verify`'s last two checks. Finding 197.
		return refuse(why, "join cycle escaped")
	if found is None or len(found) != 1:
		return None
	return next(iter(found))


def reaching_definitions(instructions, index, register, blocked, limit=640,
                          sources=None, depth=4, visiting=frozenset(),
                          assume=None, why=None):
	"""Where `register`'s value at `index` was decided, or None.

	Returns the position of the nearest instruction that writes it. Sound
	because it walks back to that NEAREST write, so nothing between it and
	`index` can have changed the register. Everything unresolved is refused:

	  * a **branch target** in between means another path reaches this point
	    without passing the write;
	  * a **call** in between is opaque, the upper half of every ymm being
	    volatile across one -- that is what `vzeroupper` exists for -- so no
	    definition survives it;

	An instruction that merely **reads** the register is scanned past, the
	value being unchanged by it. That was refused when this was written, on
	the grounds that "the nearest mention decides" is the rule easiest to be
	sure of; measured afterwards, the simplification was costing 3,299
	stores, which is more than a simplification is worth. Finding 44.

	**A conditional branch is transparent in this direction, and that is the
	asymmetry worth understanding.** Going forwards a branch splits the paths
	and the answer has to hold on both, which is why Finding 42 had to follow
	the edges. Going backwards there is nothing to split: reaching this point
	by falling through a `jcc` means the branch was not taken on this
	execution, so everything before it ran in order. An unconditional jump is
	not transparent -- the instruction after one is reachable only by a
	branch, and a branch target has already been refused above, so meeting a
	`jmp` walking backwards means bytes nothing reaches.

	`vzeroall` would be the one instruction that writes an xmm without naming
	it. There are none in `.text`, checked rather than assumed.

	**What the write means is the caller's question, not this one's.**
	`zeroed_ymm` asks whether it was a zeroing idiom and `constant_ymm`
	whether it was a load of memory that cannot change; the walk that finds
	it is the same walk, written once. Two of them answering one question is
	how a collector and an encoder come to disagree -- Finding 52 -- and this
	was one walk with one caller until there were two.
	"""
	# **The site's own address counts, and it was not being checked.** The
	# walk below refuses a branch target it passes over, on the grounds that
	# another path reaches the site without passing the write. That is
	# exactly as true when the SITE is the branch target, and this started
	# at index-1 and never looked.
	#
	# It shipped wrong bytes. At 0x1424e3b5f a `jmp` lands on the store and
	# skips the `vxorps` two instructions above it, so on that path ymm0
	# holds something else and the lowering wrote the low half twice. Two
	# such sites were in the built binary and nineteen more were accepted by
	# the scan and lost elsewhere. Finding 82.
	# ...unless it heads a loop that cannot disturb the register, which is
	# what nineteen of the twenty-one turned out to be. See
	# `value_survives_loop`; without `sources` this stays the flat refusal.
	# **Not when this call IS the enumeration of those paths.** A non-empty
	# `visiting` means a join below asked each way in, so refusing here for
	# "another path reaches this point" would refuse the very question that
	# was posed -- and the fall-through way re-enters at the join itself.
	# Finding 190.
	if not visiting and instructions[index][0] in blocked:
		# **The reader's own address is a join like any other.** This
		# refused outright unless `value_survives_loop` rescued it, which
		# left 95 of the 248 unresolved sources -- 18 of them real stale
		# reads -- for want of asking the same question one line lower
		# down asks. The ways in are enumerable or they are not; where
		# they are, the answer is the union over them. Finding 194.
		if not value_survives_loop(instructions, index, register, blocked,
		                           sources):
			ways = predecessors_of(instructions, index, sources)
			if ways is None:
				return refuse(why, "reader entry unknowable",
				              instructions[index][0])
			answers, cycles = set(), False
			for way, inclusive in ways:
				if way >= index or way in visiting:
					# The reader's own entry has a back edge into it, which
					# is a loop like any other and was refused here only
					# because the fixpoint was not reachable from this
					# branch. Finding 197.
					cycles = True
					continue
				try:
					answer = reaching_definitions(
						instructions, way + 1 if inclusive else way,
						register, blocked, limit, sources, depth - 1,
						visiting | {index}, assume, why)
				except JoinCycle as cycle:
					if cycle.position != index:
						raise
					cycles, answer = True, set()
				if answer is None:
					return None
				answers |= answer
			if cycles:
				return loop_fixpoint(instructions, index, register, blocked,
				                     limit, sources, depth, visiting, assume,
				                     ways, why)
			return answers or refuse(why, "reader entry decided nothing",
			                         instructions[index][0])
	narrow = "%xmm" + register[len("%ymm"):]
	for step in range(1, limit + 1):
		position = index - step
		if position < 0:
			return refuse(why, "start of listing")
		address, _encoding, mnemonic, operands, _comment = \
			instructions[position]
		if mnemonic.startswith(CONTROL_PREFIXES) \
				and not conditional_branch(mnemonic):
			return refuse(why, f"control transfer: {mnemonic}", address)
		if mnemonic in UPPER_HALF_KILLERS:
			# It decides the upper half and names nothing, so the operand
			# test below cannot see it. Returning its position refuses both
			# callers, which is right for `constant_ymm` -- the upper half is
			# no longer the constant's -- and costs `zeroed_ymm` nothing it
			# was measured to have: zero of the 10,933 zero stores this scan
			# reaches have one between the idiom and the store, because MSVC
			# emits `vzeroupper` before a call or a return and the walk stops
			# at either.
			return {position}
		if narrow in operands or register in operands:
			# In AT&T the destination is the last operand, and the one family
			# that writes a non-last one is `vgather*`, which zeroes its mask.
			# There are none in `.text`, checked rather than assumed, so a
			# register named anywhere but last is read-only.
			fields = inplace.split_operands(operands)
			if fields and fields[-1] in (narrow, register):
				# **This instruction decides the value, however control
				# arrived**, so whether it is a branch target does not matter
				# and must not be asked -- the first version of this
				# recursion tested `blocked` before looking at the write,
				# which for a target that writes the register would have
				# answered about the value BEFORE it. Finding 84.
				return {position}
		if address in blocked:
			# **A branch target is only opaque if the value AT it is.** The
			# refusal here says another path reaches this point without
			# passing the write -- true, and it stops mattering when the
			# register is decided the same way on every path into that point
			# too, which is exactly what this function answers. Nothing
			# between there and the site writes it, or the walk would have
			# returned above.
			#
			# So recurse, and bound it. `depth` stops a chain of targets
			# walking the whole function: each step costs a full backward
			# walk, and the shapes this is for -- a memset loop whose head is
			# a store, and the stores after it -- need one or two.
			#
			# Exhausting the bound is a refusal, so an unresolved answer
			# stays "no definition", which is the safe direction.
			if depth <= 0:
				return refuse(why, "join depth exhausted", address)
			# **Every predecessor, not just the fall-through.** Recursing
			# here re-enters at the target and the `blocked` test at the
			# top refuses it, so this resolved almost nothing: 605 of the
			# 736 sources the stale-read gate cannot speak for stall on
			# exactly this, and 61 of the 736 are real stale reads it
			# therefore cannot see -- against 29 it does see. The answer
			# is the same however control arrived only if EVERY way in
			# agrees, so ask each and require agreement. Finding 190.
			#
			# `sources` maps a target to the addresses that branch to it;
			# the fall-through is the instruction before, when it does not
			# transfer control. 484 of the 605 joins have all their
			# predecessors known this way -- the rest are `.pdata` starts,
			# reachable by an indirect call nothing here enumerates, and
			# stay refused.
			ways = predecessors_of(instructions, position, sources)
			if ways is None:
				return refuse(why, "join entry unknowable", address)
			# **An assumed join answers from the assumption.** This is the
			# only way a loop can be walked at all: the fixpoint below
			# anchors on a join, assumes a value for it, and walks the back
			# edge -- which comes back down to this same join. Without the
			# assumption the walk re-enters and refuses, which is what made
			# every loop unanswerable except through the narrow induction.
			# Finding 195.
			if assume is not None and position in assume:
				return set(assume[position])
			if position in visiting:
				raise JoinCycle(position)
			try:
				return join_answer(instructions, position, register, blocked,
				                   limit, sources, depth, visiting, assume,
				                   ways, address, why)
			except JoinCycle as cycle:
				if cycle.position != position:
					raise
				# This join is the one the cycle returns to, so it is the
				# one that must be assumed. Finding 197.
				return loop_fixpoint(instructions, position, register,
				                     blocked, limit, sources, depth,
				                     visiting, assume, ways, why)
		# A pure source, or no mention at all: the value is unchanged.
	return refuse(why, "budget exhausted")


def join_answer(instructions, position, register, blocked, limit, sources,
                depth, visiting, assume, ways, address, why):
	"""Union the ways into a join, or None. Raises `JoinCycle`.

	Split out of `reaching_definitions` so the join's own body can be run
	under one `try`: a cycle detected anywhere below has to abandon this
	whole union, not just the way it was found on. Finding 197.
	"""
	answers, deferred = set(), []
	for way, inclusive in ways:
		if way > position or way in visiting:
			# **A back edge, and `value_survives_loop` already
			# answers it.** Findings 83 and 84 built that rule for
			# exactly this shape -- a loop head whose zero the body
			# cannot disturb -- and `check-pe`'s `zerochain` is its
			# positive control. Refusing every back edge instead
			# discards it: the fixture stopped returning 33,
			# because the body store could no longer prove the head
			# was zero. An edge the loop cannot disturb contributes
			# nothing and is skipped; one that might, refuses.
			if value_survives_loop(instructions, position, register,
			                       blocked, sources):
				continue
			# **And where it cannot, iterate rather than refuse.**
			# The induction above is one shape -- a memset head whose
			# body writes nothing -- and every other loop was a
			# refusal. Finding 195.
			deferred.append((way, inclusive))
			continue
		answer = reaching_definitions(
			instructions, way + 1 if inclusive else way, register,
			blocked, limit, sources, depth - 1,
			visiting | {position}, assume, why)
		if answer is None:
			return None
		answers |= answer
	# **The set, not one of it.** The ways into a join may reach
	# different definitions and that is an answer, not a refusal:
	# `stale_upper_reads` asks whether ANY of them is a site this
	# rewrite touched, and refusing on disagreement hid 128 of the
	# 248 unresolved sources. A caller needing one answer gets None
	# from the `reaching_definition` wrapper. Finding 194.
	#
	# **And an empty set is not an answer.** A chain of joins can
	# each contribute nothing and leave this empty, which reads to
	# `stale_upper_reads` as "resolved, and no producer was
	# rewritten" -- a silent clean for a register nothing was
	# established about. Refuse it. Finding 195.
	if not deferred:
		return answers or refuse(why, "join decided nothing", address)
	return loop_fixpoint(instructions, position, register, blocked,
	                     limit, sources, depth, visiting, assume,
	                     ways, why)


def zeroed_ymm(instructions, index, register, blocked, limit=640,
               sources=None, depth=None):
	"""True if every bit of `register` is zero when `index` executes.

	**A VEX.128 instruction zeroes bits [255:128] of its destination**, which
	is architecture rather than an idiom: `vpxor %xmm0,%xmm0,%xmm0` leaves the
	whole of ymm0 zero, upper half included. So a 256-bit store of that
	register has no 256-bit producer anywhere and needs none -- both halves
	are zero and one xmm stores both.

	Measured before it was written: 6,538 of the 22,347 surviving 256-bit
	stores, against 9,447 whose register was last written by a 256-bit load
	(the copy idiom, and the gapped case Finding 39 closed) and 6,095 where
	this scan reaches no definition at all.

	`reaching_definition` does the walking and says what wrote the register.
	What is left here is only whether that write was the idiom, and the
	answer has to be the same three-operand VEX.128 form the scan's own
	`ZEROING` set names -- `vpxor %xmm0,%xmm0,%xmm0` and not `vpxor` of two
	different registers, which computes something.
	"""
	depth = VALUE_DEPTH if depth is None else depth
	position = reaching_definition(instructions, index, register, blocked,
	                              limit, sources, depth)
	if position is None:
		return False
	_address, encoding, mnemonic, operands, _comment = instructions[position]
	if mnemonic not in scratch_finder.ZEROING:
		return False
	fields = inplace.split_operands(operands)
	if len(fields) != 3 or set(fields) != {"%xmm" + register[len("%ymm"):]}:
		return False
	vex = inplace.decode_vex(encoding)
	return vex is not None and not vex["L"]


def constant_load(instruction, readonly):
	"""(vex, tail, address, length) if this loads 256 bits that cannot
	change, or None.

	RIP-relative only, and only from a section the loader maps without
	`IMAGE_SCN_MEM_WRITE`. Both halves must lie inside one such section:
	the store's stub reads thirty-two bytes from here, so a constant that
	runs off the end of one is not one.

	The tuple is the shape `ymm_pair` returns its halves in, and for the same
	reason -- a RIP-relative displacement can only be recomputed from the
	address and length of the instruction that carried it, and this
	instruction is nowhere near the stub that will use it.
	"""
	address, encoding, mnemonic, operands, _comment = instruction
	move = wide_move(encoding, mnemonic, operands)
	if move is None or move[0] != "load":
		return None
	vex = inplace.decode_vex(encoding)
	tail = encoding[vex["length"]:]
	target = rip_target(tail, address, len(encoding))
	if target is None or not inside_readonly(readonly, target, 32):
		return None
	return (vex, tail, address, len(encoding))


def constant_reload(instructions, position, blocked, readonly, sources,
                    load):
	"""True if the 256-bit read at `position` fetches `load`'s constant.

	The exception `upper_half_read_later` is given when a constant load is
	being considered: a store that will be lowered by `conststore` reads the
	read-only bytes rather than the register's upper half, so it is not a use
	of the half the load's own lowering leaves stale.

	It compares the LOAD each end walked back to, not the constant's address.
	Two different loads of the same bytes are two different definitions, and
	only one of them is the one being lowered here.
	"""
	entry = instructions[position]
	what = wide_move(entry[1], entry[2], entry[3])
	if what is None or what[0] != "store":
		return False
	found = constant_ymm(instructions, position, what[1], blocked, readonly,
	                     sources=sources)
	return found is not None and found[2] == load[2]


def constant_ymm(instructions, index, register, blocked, readonly,
                 limit=640, sources=None, depth=None):
	"""The read-only load `register` still holds at `index`, or None.

	**A constant needs no shadow register, because memory is the shadow.**
	`long_pair_stores` carries an upper half from a load to a store in a
	register the original never names, and pays for it: a register has to be
	free across the whole span, any 128-bit use of the low half ends it, and
	the span is bounded because a reservation held too long is one nothing
	can verify. None of that is about the value. The store's stub loads both
	halves again from where the load got them, so nothing is carried and
	nothing is reserved, and the distance stops mattering.

	What is still needed is that the register holds THAT constant when the
	store executes, which is a reaching definition and nothing more.

	**A call still ends it, and being exact about why is the point.** The
	bytes cannot move; the REGISTER can. The upper half of every ymm is
	volatile across a call under Win64 -- that is what `vzeroupper` exists
	for -- so a callee may leave something else in it and the store would
	write that. `reaching_definition` refuses across one and this inherits
	the refusal rather than arguing with it. What a constant buys is the
	register pressure and the distance, not the call.

	The register cannot disagree with `constant_load`'s answer, so nothing
	here re-checks it: the walk stops at a write to `%ymmN` or `%xmmN`, and a
	`wide_move` load of the wide spelling is the only one of those two that
	gets past `constant_load` at all.
	"""
	depth = VALUE_DEPTH if depth is None else depth
	# **Ask the SET, because two ways into a join can carry one constant.**
	# `reaching_definition` returns an answer only when the set holds
	# exactly one position, so a value defined on both arms of a branch was
	# refused even where both arms load the identical read-only bytes --
	# `len(found) != 1` is agreement of POSITIONS, and what this needs is
	# agreement of the VALUE. That refusal is the largest bucket on the
	# frontier: 1,046 sites in `ymm value has no known upper half`, 988 of
	# them `vmovups`.
	#
	# The comparison is on the resolved absolute target rather than on the
	# tuple, which carries an unhashable dict and, more to the point,
	# describes the INSTRUCTION: two loads at different addresses with
	# different displacements can name one constant, and the stub only ever
	# needs the address it reads thirty-two bytes from. Any of the tuples
	# then serves, since each recomputes the same absolute target.
	# Finding 227.
	try:
		found = reaching_definitions(instructions, index, register, blocked,
		                             limit, sources, depth)
	except JoinCycle:
		return None
	if not found:
		return None
	answer, target = None, None
	for position in found:
		one = constant_load(instructions[position], readonly)
		if one is None:
			return None
		here = rip_target(one[1], one[2], one[3])
		if here is None:
			return None
		if target is None:
			answer, target = one, here
		elif here != target:
			return None
	return answer


# How many instructions `upper_half_read_later` may examine across all the
# paths it follows from one site. It is a safety valve rather than a tuning
# knob: the walk explores both edges of every branch it can resolve, so a
# branchy region costs exponentially in paths, and something has to stop it.
#
# 400 was a number with no measurement behind it and it was binding on 124
# sites. Raising it is very nearly free, because only those 124 walks ever
# reach it -- the other ~805,000 stop at a call, a full overwrite or a
# resolved branch long before. Measured end to end on the real binary,
# collect plus place_stubs:
#
#     budget       placed      gain    seconds
#        400      196,945         --       213
#      4,000      197,025        +80       214
#     40,000      197,051        +26       213
#    400,000      197,062        +11       215
#
# 40,000 was chosen off that curve as the knee, on the grounds that the last
# point buys only eleven more sites for a bound ten times looser. **That read
# the wrong column.** Sites are not fungible: eleven in code that never runs
# are worth nothing, and one in the loop the game executes during startup is
# worth the whole difference. The aggregate count cannot see which is which,
# and it was allowed to decide.
#
# The site Starfield actually dies on -- 0x1422d2f56, a copy pair inside a
# loop -- is one of the eleven. It is not path explosion: the walk answers
# "dead" after consuming 200,196 of the budget in 0.1 seconds, so it was only
# ever expensive. At 40,000 it is refused and the game stops there.
#
# So 400,000, and the cost side never moved: 215 seconds against 213, inside
# the noise, because the valve binds on barely a hundred walks out of 805,000.
# Finding 80.
#
# What is left after it is not a budget problem. 44 sites blew through 4,000
# and are genuine path explosion: the walk re-examines the same successors
# along different prefixes. Memoising would collapse that, and only in one
# direction -- caching "read" is sound, caching "dead" is not, because
# Finding 78 made a revisited branch terminate as dead and that answer
# depends on which branches were on the path when it was computed.
PATH_BUDGET = 400000


def upper_half_read_later(instructions, index, register, limit=40,
                          positions=None, budget=None, visiting=frozenset(),
                          covered=None):
	"""True if anything might still read the ymm's upper half.

	Conservative in the direction that matters: an unresolved answer is
	"yes, leave it alone". Only a 256-bit instruction can read the upper
	half, and every one of those is refused today, so in practice this is
	belt and braces -- but the pair rewrite is only correct where it holds.

	**`xsave` and `xrstor` are the one thing that would read an upper half
	without naming it.** There are none in `.text`, checked rather than
	assumed, which is what lets a scan over operand text be complete.

	`positions` is `{address: index}`; without it a branch is opaque and the
	answer is "read", which is what this did before the edges were followed.

	`covered` is asked about a 256-bit read that would otherwise end the walk,
	and answers whether that read is one the caller has already arranged to
	lower without consulting the upper half. Only `constant_ymm` passes one
	today. Without it nothing changes, which is how every other caller keeps
	the belt-and-braces answer above.
	"""
	if budget is None:
		budget = [PATH_BUDGET]
	narrow = "%xmm" + register[len("%ymm"):]
	for step in range(1, limit + 1):
		position = index + step
		if position >= len(instructions):
			return True		# off the end of what the listing describes
		if position in visiting:
			# **A revisit means the cycle carried no read.** `visiting` holds
			# the branches this path has already recursed through, and every
			# instruction between one of them and here has been examined --
			# a read would have returned True before the walk got back. Going
			# round again examines the same instructions and explores the same
			# successors, because this walk is path-insensitive and takes BOTH
			# edges at every branch it can resolve. So the cycle contributes
			# nothing and this path is dead.
			#
			# Answering "read" here instead was the largest refusal after a
			# genuine read: 487 of the 1,591 sites declined for `ymm upper
			# half read later`, which is a loop being treated as unknowable
			# rather than as examined. Finding 78.
			#
			# Termination is unaffected -- this returns without recursing, and
			# `limit` and `budget` bound the walk regardless.
			return False
		if budget[0] <= 0:
			return True
		budget[0] -= 1
		_address, encoding, mnemonic, operands, _comment = instructions[position]
		if mnemonic.startswith("ret") or mnemonic in ("call", "callq"):
			# Nobody can read it after either. **The upper half of every ymm
			# is volatile under Win64 without exception** -- xmm6 to xmm15
			# have their LOW halves preserved and their upper halves survive
			# nothing. That is the whole reason vzeroupper exists, and it is
			# why a call ends an upper half's life as firmly as a return
			# does: the callee may not read it, and the caller may not
			# expect it back.
			#
			# Measured: treating a call as opaque instead refused 7,151 of
			# the 7,395 pairs. Calls are simply too common for a scan that
			# stops at one to reach anything.
			return False
		if mnemonic.startswith(CONTROL_PREFIXES):
			# **Follow the edges, exactly as tool/scratch.py does, and for
			# the same reason: stopping here was the largest single bucket.**
			# 2,617 of the 5,200 refused pairs stopped at a branch, against
			# 1,052 that genuinely read the register.
			#
			# This builds no CFG. An unconditional jump has one successor and
			# the scan simply continues there; a conditional has two, and the
			# upper half is dead only if it is dead on BOTH. Anything that
			# cannot be resolved -- an indirect jump, a target outside the
			# listing, a back edge, an exhausted budget -- answers "read",
			# which is the conservative direction by construction.
			if positions is None:
				return True
			target = scratch_finder.branch_target(operands)
			if target is None or target not in positions:
				return True
			successors = [positions[target]]
			if not mnemonic.startswith(("jmp", "jmpq")):
				successors.append(position + 1)		# the branch not taken
			inside = visiting | {position}
			for successor in successors:
				if upper_half_read_later(instructions, successor - 1,
				                         register, limit, positions, budget,
				                         inside, covered):
					return True
			return False
		# **A VEX.128 write to the low half zeroes the upper one**, which is
		# architecture rather than an idiom -- the same fact Class Y1-zero is
		# built on -- and it ends the upper half's life as firmly as a call
		# does. Nothing downstream can read the half this lowering is about to
		# leave stale, because the original zeroed it here.
		#
		# The scan matched the `%ymm` spelling only, so a `vpxor
		# %xmm0,%xmm0,%xmm0` sitting between a pair and a later 256-bit store
		# of the same register read as "nothing happened", and the store beyond
		# it read as a live use of the upper half. 812 of the 998 sites blocked
		# by a later wide store are exactly this. Finding 79.
		#
		# **The VEX test is load-bearing.** A legacy SSE write to xmm leaves
		# bits [255:128] alone, so matching on the destination alone would be
		# wrong on precisely the instructions this project emits.
		# **The rewrite destroys this fact, and it is credited anyway --
		# deliberately, with the exposure measured.** A VEX.128 write
		# zeroes [255:128] in the ORIGINAL; the tool patches that very
		# instruction to legacy SSE, which does not, and 4,240 of 4,240
		# such killers are no longer VEX in the shipped image.
		#
		# It is still sound wherever the later 256-bit reader is ITSELF
		# lowered, because a lowered reader never touches the machine upper
		# half -- and that is the common case, because a read after a
		# zeroing write is exactly what `zeroed_ymm` recognises and the
		# zero store lowers. `check-pe`'s `lowwrite` is the positive
		# control for it: a pair, a `vpxor`, and a 256-bit store that must
		# land as 32 zeros. Withdrawing the credit outright refuses that
		# pair and the fixture returns 29 instead of 77 -- tried, and it is
		# how the limit of this reasoning was found.
		#
		# Where the reader SURVIVES it is wrong, and Finding 185 measured
		# that at 2 sites forward and 33 through plain in-place patches.
		# The correct guard is not "never credit" but "credit unless a
		# surviving reader follows", which needs the placer's answer at
		# collect time and is not built. Recorded rather than papered over.
		if narrow in operands:
			fields = inplace.split_operands(operands)
			if fields and fields[-1] == narrow:
				vex = inplace.decode_vex(encoding)
				if vex is not None and not vex["L"]:
					return False
		if register not in operands:
			continue
		# **A write that does not read it ends its life as firmly as a call
		# does.** The lowering leaves the upper half stale, and nothing can
		# observe that if the next instruction to mention the register
		# replaces all 256 bits of it without consulting them. An unrolled
		# copy is exactly this shape -- one 32-byte copy through a ymm, then
		# another through the same one -- and the first pair was being
		# refused because the second pair's load mentions the register.
		#
		# Measured: 1,531 of the 5,200 refused pairs stop here, against 1,052
		# that genuinely read it and 2,617 that stop at a branch first.
		#
		# The mnemonics are restricted to the moves for the reason
		# scratch.py's FULL_WRITE is: one missing from the list costs a pair
		# that was available, and one wrongly on it costs correctness.
		# **Same exposure, same reasoning**: 2,742 of the 2,829 killers
		# this credits are themselves lowered, and a lowered 256-bit move
		# writes the low half only. Sound where the later reader is lowered
		# too, wrong where it survives -- 4 sites, Finding 185.
		fields = inplace.split_operands(operands)
		if mnemonic in YMM_MOVES and fields[-1] == register \
				and register not in fields[:-1]:
			vex = inplace.decode_vex(encoding)
			if vex is not None and vex["L"]:
				return False
		# **A store the constant strategy claims reads no upper half**, so
		# the stale one this lowering leaves behind is not what reaches
		# memory: its stub loads both halves again from the read-only bytes
		# the value came from. A store writes the register nowhere, so the
		# walk carries on past it rather than ending here.
		#
		# The caller's predicate and the store's own lowering both come from
		# `constant_ymm`, so the two cannot disagree about which stores these
		# are -- there is one decision, asked twice.
		if covered is not None and covered(position):
			continue
		return True
	# **Running out of instructions is not a proof.** This reported "dead"
	# having examined `limit` of them and established nothing, which is
	# unsound against the original program, never mind the rewritten one --
	# and it disagreed with the budget exhaustion above, which returns True.
	# 21 constload sites shipped wrong bytes through here, the use sitting
	# eight instructions past the forty this looks at. Conservative now, in
	# the direction the docstring already claims: "an unresolved answer is
	# yes, leave it alone". Finding 185.
	return True


def emit_swallowed(entry, body, stub_address, pool, spill_base, reasons,
                   base, block=None, slot=0):
	"""One swallowed instruction, bracketed by a save and restore if it
	borrowed a register. Returns the bytes, or None.

	The bracket is tight by construction -- save, this one lowering, restore
	-- so no call and no movement of `rsp` can come between them whatever the
	window turns out to hold. See `swallowed_borrow`. Finding 93.
	"""
	borrowing = len(entry) > 6 and entry[6]
	# **Nothing between a save and its restore may transfer control.** A
	# call is the case `copy_reaches_home` leans on -- an escaped pointer
	# cannot be dereferenced while the borrow is live, because nothing else
	# runs -- and a swallowed `call` re-emitted by Finding 86 is exactly the
	# instruction that would break it. A swallowed BRANCH is the other half
	# and is worse: control leaving between the save and the restore means
	# the restore never runs at all, and the borrowed register stays
	# clobbered for the rest of the program. Neither can happen today, which
	# is why this is a refusal rather than a repair. Findings 127 and 129.
	if borrowing and (entry[4] or "").startswith(CONTROL_PREFIXES):
		if reasons is not None:
			reasons["a borrow bracket would wrap a control transfer"] += 1
		return None
	# **A per-thread slot where the window lends no frame slot.** A spill
	# SITE has fallen back to one since Finding 142; a passenger could not,
	# and was refused here instead. Measured: 29 of the 29 spill passengers
	# the rescue could not seat died on exactly this line, and on no other.
	# `block` is a register already holding the thread's block pointer --
	# planted by the caller, which knows whether the site's own spill put
	# one there. Finding 182.
	if borrowing and base is None and block is None:
		if reasons is not None:
			reasons["the window will not hold one borrow displacement"] += 1
		return None
	out = bytearray()
	if borrowing:
		# The same slot the site's own borrow uses, and safely: the
		# brackets are strictly sequential. `build_stub` closes the site's
		# borrow inside `body` and the displaced entries are appended
		# after, so no two saves are ever live at once -- checked over all
		# 53 brackets in the image at Finding 181.
		saved = (encode_tls_spill(entry[5], True, block, slot)
		         if block is not None else
		         encode_spill(entry[5], True, stub_address + len(body),
		                      spill_base, 0, base))
		if saved is None:
			if reasons is not None:
				reasons["the swallowed borrow could not be saved"] += 1
			return None
		out += saved
	fixed = moved_instruction(entry, stub_address + len(body) + len(out), pool,
	                          reasons)
	if fixed is None:
		return None
	out += fixed
	if borrowing:
		restored = (encode_tls_spill(entry[5], False, block, slot)
		            if block is not None else
		            encode_spill(entry[5], False,
		                         stub_address + len(body) + len(out),
		                         spill_base, 0, base))
		if restored is None:
			if reasons is not None:
				reasons["the swallowed borrow could not be restored"] += 1
			return None
		out += restored
	return bytes(out)


def redirect_half(vex, tail, register):
	"""The same operand, with its register field pointed at `register`.

	A 128-bit half names its register in two places -- the modrm `reg` field
	and the VEX `R` bit, which `decode_vex` has already un-inverted into the
	high bit of the number. Both have to move together, and `narrow_piece`
	reads them from exactly here.
	"""
	if len(tail) < 2:
		return None
	modrm = (tail[1] & 0xC7) | ((register & 7) << 3)
	return dict(vex, R=(register >> 3) & 1), tail[:1] + bytes([modrm]) \
		+ tail[2:]


def lower_long_half(vex, tail, address, length, at, shadow):
	"""The two 128-bit halves of one end of a long pair, or None.

	**The upper half goes to a register the original never names**, so that
	the stub lowering the OTHER end can find it. The low half keeps the
	ymm's own xmm, which is where the original program already keeps it, so
	every 128-bit read in between is untouched.

	Both ends emit the same shape and differ only in direction, the
	direction being a property of the encoding rather than of this: a load's
	operand writes the register, a store's reads it. That is why one
	function serves both, and why the pair must agree on `shadow` -- see
	`long_pair_store`.
	"""
	high = redirect_half(vex, tail, shadow)
	if high is None:
		return None
	body = bytearray()
	piece = narrow_piece(high[0], high[1], 16, address, length, at)
	if piece is None:
		return None
	body += piece
	piece = narrow_piece(vex, tail, 0, address, length, at + len(body))
	if piece is None:
		return None
	body += piece
	return bytes(body)


def long_partner_lowers(instructions, position, ranges, shadow):
	"""Whether a long pair's partner store will actually lower.

	**The load must ask this before it commits.** `lower_long_half` writes
	the upper half into a shadow register and leaves the ymm's own upper
	half stale, which is safe only because the partner store is going to
	read the shadow. A load that commits to a store which then declines
	leaves a surviving 256-bit store of a register whose top half nobody
	wrote -- sixteen correct bytes and sixteen stale, in the shipped image.

	24 sites were exactly that, all of them 4-byte stores refused by the
	length test the load never applied to them. `0x1402d70ad` detoured to a
	stub that put the upper half in `%xmm1` and returned to
	`0x1402d70b2`, still `c5 fc 11 03`, storing 32 bytes from `%ymm0`.

	The three tests are the store's own, asked in its words rather than
	restated: too short to detour, outside `.pdata`, or a half that will
	not encode. Finding 180.
	"""
	address, encoding, _m, _o, _c = instructions[position]
	if len(encoding) < 5:
		return False
	vex = inplace.decode_vex(encoding)
	if vex is None:
		return False
	if not inplace.covered_by(ranges, address, len(encoding)):
		return False
	return lower_long_half(vex, encoding[vex["length"]:], address,
	                       len(encoding), address, shadow) is not None


def long_pair_stores(instructions, index, blocked, end):
	"""Every store this 256-bit load's value reaches, or None.

	`ymm_pair` takes the adjacent case and `ymm_run` takes everything that
	fits one stub. Past that the upper half dies at the window edge and the
	store is declined for want of it. A register reserved from here to there
	carries it between two INDEPENDENT stubs, which is the whole increment.

	**What must hold, and each is a way the shadow goes stale:**

	  * nothing between may branch INTO the span -- control arriving there
	    would find the shadow holding whatever the last lifetime left, which
	    is how Finding 82's miscompilation happened one window over;
	  * no call, the upper half being volatile across one by the ABI;
	  * nothing else may write the value, or the two ends disagree.

	A target landing ON the load is fine: control entering there executes
	the definition. Only one landing after it is fatal, which is why the
	test is on the NEXT instruction's address rather than this one's.

	**A store does not end the value's life**, and stopping at the first one
	cost the executed path directly: Starfield's frontier moved from
	`0x14004E230` to `0x14004E250` -- the SECOND store of the same register,
	32 bytes on, left behind because only the first was given the shadow.
	`ymm_run` learned the same thing at 1,019 pairs. The walk therefore
	collects stores until something ends the value, and the caller records
	the reservation against every one of them.
	"""
	address, encoding, mnemonic, operands, _c = instructions[index]
	first = wide_move(encoding, mnemonic, operands)
	if first is None or first[0] != "load":
		return None
	register = first[1]
	number = register[len("%ymm"):]
	found = []
	for step in range(1, 200):
		position = index + step
		if position >= len(instructions):
			break
		next_address, bits, name, text, _d = instructions[position]
		if next_address >= end or next_address in blocked:
			break
		if name.startswith(CONTROL_PREFIXES) or name in ("call", "callq"):
			break
		if name in UPPER_HALF_KILLERS:
			break			# it clears the half the shadow is carrying
		what = wide_move(bits, name, text)
		if what is not None and what[0] == "store" and what[1] == register:
			found.append(position)
			continue
		if register in (text or "") or "%xmm" + number in (text or ""):
			break
	return found or None


def close_stub(body, displaced, stub_address, pool, spill_base, reasons,
               start, window, base):
	"""Whatever the window swallowed, then the jump home. Bytes, or None.

	**A stub that returns before this has deleted its passengers.** Every
	strategy branch in `build_stub` writes its own body and jumped straight
	home, and `place_stubs` may hand any of them a `displaced` list: the
	Finding 36 extension takes the next candidate along when its site sits
	exactly at the window's end, grows the window over it and retires its
	own candidate. The plain path emits it; the six strategy paths did not,
	so the instruction vanished with its boundary recorded as deliberate and
	every structural check satisfied -- the byte is not in the stub, and it
	does not survive in `.text` either, so neither `verify` nor `census` has
	anything to see. Finding 111.

	Measured on this binary at zero occurrences, which is why it had not
	been noticed: the passenger has to be a backward-widened candidate
	beginning inside a 256-bit window. Latent rather than live, and closed
	because it costs nothing to close.
	"""
	out = bytearray(body)
	for entry in displaced:
		fixed = emit_swallowed(entry, out, stub_address, pool, spill_base,
		                       reasons, base)
		if fixed is None:
			if reasons is not None:
				reasons["a displaced instruction will not move"] += 1
			return None
		out += fixed
	return bytes(out) + encode_jump(stub_address + len(out) + 5,
	                                start + window)


def build_stub(start, encoding, operands, mnemonic, window, displaced,
               stub_address, scratch=None, pool=0, preceding=(),
               strategy=None, spill_base=0, reasons=None, home=None,
               tls=None):
	"""The stub body for one window, placed at stub_address.

	`start` is the window's first byte, which is the site's own address
	unless the window was widened backwards -- in which case `preceding`
	holds the instructions that come before the site and must execute first.

	`strategy` names a lowering the plain rules cannot express, because it
	rests on something the collector proved about the surrounding code rather
	than on the instruction alone. `("pair", ...)` is a 256-bit copy and takes
	the whole window; `("zero", None)` is a 256-bit store of a register a
	VEX.128 zeroing idiom emptied, and is an ordinary one-site window in every
	other respect. `("spill", n)` is a site with no dead register, lowered by
	borrowing register n and giving it back.
	"""
	kind = strategy[0] if strategy is not None else None
	# Where a borrow in this stub saves and restores, as a displacement from
	# `rsp`. Zero is the callee home space, which is at `(%rsp)` for every
	# instruction in the window because the function lending it does not
	# move `rsp` at all. None means no borrow can be written here, and it
	# only matters where the strategy wants one.
	base = window_borrow(home, start, window) if home is not None else 0
	if kind == "run":
		# A run of 256-bit copies and whatever lies between them, all in one
		# stub. It carries its own instruction list rather than using
		# `displaced`, because they have to land BETWEEN the halves of the
		# copies rather than after a site.
		# **A borrowed helper is saved before the run and restored after
		# it**, so the bracket encloses the whole span -- which is why
		# `span_keeps_rsp` had to vouch for it. See Finding 95.
		borrowed = sorted(strategy[1][2]) if len(strategy[1]) > 2 else []
		# The run's bracket encloses the whole span, so the same rule
		# applies over every member. `ymm_run` breaks on every control
		# transfer, so this cannot fire -- which is the point: the property
		# is now refused rather than relied upon. See `emit_swallowed`.
		if borrowed and any(
				entry[6] is not None
				and (entry[6][4] or "").startswith(CONTROL_PREFIXES)
				for entry in strategy[1][1] if entry[0] == "plain"):
			if reasons is not None:
				reasons["a run borrow would wrap a control transfer"] += 1
			return None, 0
		if borrowed and base is None:
			if reasons is not None:
				reasons["the run will not hold one borrow displacement"] += 1
			return None, 0
		if len(borrowed) * SLOT > HOME_SPACE:
			# The home space is what the ABI reserved and nothing says what
			# lies past it. Refuse rather than reach. Finding 118.
			if reasons is not None:
				reasons["the run borrows more than the home space holds"] += 1
			return None, 0
		head = bytearray()
		for slot, register in enumerate(borrowed):
			saved = encode_spill(register, True, stub_address + len(head),
			                     spill_base, slot, base)
			if saved is None:
				if reasons is not None:
					reasons["the run borrow could not be saved"] += 1
				return None, 0
			head += saved
		body = lower_ymm_run(strategy[1], stub_address + len(head), pool)
		if body is None:
			if reasons is not None:
				reasons["the run would not lower"] += 1
			return None, 0
		out = bytearray(head) + body
		for slot, register in enumerate(borrowed):
			restored = encode_spill(register, False,
			                        stub_address + len(out), spill_base, slot,
			                        base)
			if restored is None:
				if reasons is not None:
					reasons["the run borrow could not be restored"] += 1
				return None, 0
			out += restored
		return close_stub(out, displaced, stub_address, pool, spill_base,
		                  reasons, start, window, base), 0
	if kind == "pair":
		# A 256-bit copy: both instructions become four 128-bit moves, so
		# neither is lowered on its own.
		body = lower_ymm_pair(strategy[1], stub_address)
		if body is None:
			if reasons is not None:
				reasons["the pair would not lower"] += 1
			return None, 0
		return close_stub(body, displaced, stub_address, pool, spill_base,
		                  reasons, start, window, base), 0
	if kind == "longload" or kind == "longstore":
		# One end of a long pair. The load's stub writes the upper half into
		# a reserved register and the store's reads it back, so the two are
		# lowered identically and only the encoding says which way the bytes
		# go. See `long_pair_store` for what keeps the reservation honest.
		vex, tail, shadow = strategy[1]
		body = lower_long_half(vex, tail, start, len(encoding), stub_address,
		                       shadow)
		if body is None:
			if reasons is not None:
				reasons["the long pair would not lower"] += 1
			return None, 0
		return close_stub(body, displaced, stub_address, pool, spill_base,
		                  reasons, start, window, base), 0
	if kind == "splat":
		# A `vinsertf128` that broadcasts the low half, and the store that
		# follows it. The insert itself emits nothing -- both halves are
		# the register the original already holds -- so the whole window
		# becomes the two 128-bit stores the value needs.
		body = lower_ymm_zero_store(*strategy[1], at=stub_address)
		if body is None:
			if reasons is not None:
				reasons["the splat store would not lower"] += 1
			return None, 0
		return close_stub(body, displaced, stub_address, pool, spill_base,
		                  reasons, start, window, base), 0
	if kind == "splatop":
		# A broadcast, one lane-wise operation on it, and the store of the
		# result -- six instructions, no helper register, and the insert
		# emitting nothing. See `splat_operation`.
		body = lower_splat_operation(*strategy[1], at=stub_address)
		if body is None:
			if reasons is not None:
				reasons["the splat operation would not lower"] += 1
			return None, 0
		return close_stub(body, displaced, stub_address, pool, spill_base,
		                  reasons, start, window, base), 0
	if kind == "splatrun":
		# A broadcast and every store that follows it. The insert emits
		# nothing -- the value it builds is already in the register the
		# lowered program keeps -- and each store becomes two 128-bit stores
		# of the same xmm.
		#
		# **These are `lower_zero_run`'s bytes exactly**, for the reason
		# Finding 108 gave when the single-store form borrowed
		# `lower_ymm_zero_store`: a splat has the zero's property one step
		# weaker, both halves being the same register rather than both being
		# zero. Identical bytes, different justification, and the strategy is
		# named separately so that the justification stays readable.
		body = lower_zero_run(strategy[1], stub_address)
		if body is None:
			if reasons is not None:
				reasons["the splat run would not lower"] += 1
			return None, 0
		return close_stub(body, displaced, stub_address, pool, spill_base,
		                  reasons, start, window, base), 0
	if kind == "construn":
		# Consecutive stores of read-only constants, taken together for the
		# reason the zero run below is taken together: a four-byte store at
		# the head of a loop can widen over neither neighbour, and the one
		# it would have to swallow is another 256-bit store that
		# `moved_instruction` refuses. See `store_run`.
		body = lower_constant_run(strategy[1], stub_address)
		if body is None:
			if reasons is not None:
				reasons["the constant run would not lower"] += 1
			return None, 0
		return close_stub(body, displaced, stub_address, pool, spill_base,
		                  reasons, start, window, base), 0
	if kind == "zerorun":
		# Consecutive stores of an all-zero register, taken together so that
		# none of them has to widen its window over another. See `zero_run`.
		body = lower_zero_run(strategy[1], stub_address)
		if body is None:
			if reasons is not None:
				reasons["the zero run would not lower"] += 1
			return None, 0
		return close_stub(body, displaced, stub_address, pool, spill_base,
		                  reasons, start, window, base), 0

	body = bytearray()
	prologue = 0
	# Hoisted, because the displaced loop asks whether the site's own spill
	# already planted a block pointer it can share. Inside the spill branch
	# alone it is undefined everywhere else.
	tls_pair = None
	for entry in preceding:
		fixed = emit_swallowed(entry, body, stub_address, pool,
		                       spill_base, reasons, base)
		if fixed is None:
			if reasons is not None:
				reasons["a preceding instruction will not move"] += 1
			return None, 0
		body += fixed

	site = start + sum(len(entry[1]) for entry in preceding)
	if kind == "spill":
		# Borrow a register the site does not name, and give it back. The
		# save has to come before the lowering and the restore after it, so
		# neither can live inside lower_vex.
		borrowed = strategy[1]
		# **The home space first, and a per-thread slot only where there is
		# none.** `tls` is `(index VA, slot offset)` when `--spill=tls` is
		# on and the image has a TLS directory. The two registers must be
		# dead across the WHOLE window for `window_borrow`'s reason: the
		# addressing is written once and the clobber lasts until the
		# restore, so a widened window that asked only about the site would
		# destroy a register its swallowed neighbour still wanted.
		if base is None and tls is not None:
			available = sorted(window_gpr_free(home, start, window))
			if len(available) >= 2:
				# r11 and r10 first where they are free: neither is ever an
				# argument or a return value, so taking them disturbs the
				# fewest other things this tool might later want.
				ordered = sorted(available, key=lambda n: -n)
				tls_pair = (ordered[0], ordered[1])
		# **The stack, where neither the home space nor a TLS pair is
		# available.** `--spill=tls` declines 386 sites for exactly this:
		# the home space cannot lend and TLS addressing wants two free
		# GPRs that are not live here. A stack slot needs no register to
		# address, and `--spill=stack` already emits one -- this reuses
		# that emission rather than inventing a second, so the unwind
		# offset below is the same measured `prologue` that mode has been
		# tested with.
		#
		# **A fallback is not a different default.** Measured: switching
		# wholesale to `stack` closes all 386 and ends with 194 FEWER
		# candidates, because it loses sites `tls` handles -- 333 of them
		# to `no register free across the ymm run` alone. Falling back only
		# where `tls` refused takes 349 of the 386 and loses none of that,
		# since those sites keep the store that works for them.
		# Finding 204.
		stack_borrow = base is None and tls_pair is None \
			and SPILL == SPILL_TLS and FALLBACK_RULE == FALLBACK_ON
		if base is None and tls_pair is None and not stack_borrow:
			if reasons is not None:
				reasons["the site will not hold one borrow displacement"] += 1
			return None, 0
		if SPILL == SPILL_STACK or stack_borrow:
			body += STACK_OPEN
			# Where the allocation is complete, which is what the unwind
			# code's offset means and why it is measured rather than assumed
			# to be zero: a backward-widened window emits its swallowed
			# instructions first.
			prologue = len(body)
		if stack_borrow:
			# The freshly allocated sixteen bytes, at `(%rsp)`: the same
			# place the callee home space is addressed from, which is why
			# `encode_spill` needs nothing new to reach it.
			base = 0
		if tls_pair is not None:
			index_va, slot_offset = tls
			block, scratch_gpr = tls_pair
			body += encode_tls_base(block, scratch_gpr, index_va,
			                        stub_address + len(body))
			saved = encode_tls_spill(borrowed, True, block, slot_offset)
		else:
			saved = encode_spill(borrowed, True, stub_address + len(body),
			                     spill_base, 0, base)
		if saved is None:
			if reasons is not None:
				reasons["the borrowed register could not be saved"] += 1
			return None, 0
		body += saved
		lowered = lower_vex(site, encoding, operands, mnemonic,
		                    stub_address + len(body), borrowed, pool, reasons)
		if lowered is None:
			if reasons is not None:
				reasons["the site itself will not lower"] += 1
			return None, 0
		body += lowered
		if tls_pair is not None:
			# The block pointer is still in `block`: nothing between the
			# save and here may touch it, which is what `window_gpr_free`
			# and the borrow bracket's no-control-transfer rule guarantee
			# between them.
			restored = encode_tls_spill(borrowed, False, tls_pair[0],
			                            tls[1])
		else:
			restored = encode_spill(borrowed, False,
			                        stub_address + len(body),
			                        spill_base, 0, base)
		if restored is None:
			if reasons is not None:
				reasons["the borrowed register could not be restored"] += 1
			return None, 0
		body += restored
		if SPILL == SPILL_STACK or stack_borrow:
			body += STACK_CLOSE
		lowered = b""
	elif kind in ("span", "region", "unit"):
		# **The upper halves live in the callee home space for the length
		# of the window**, which is why the displacement has to be one
		# number over all of it -- `window_borrow`'s argument, and the
		# reason a span holding a `push` is refused rather than restored
		# from somewhere the save never wrote.
		entries, helper, span_block, span_base, second_helper = \
			strategy[1]
		if span_block is not None:
			# **The block carries its own base**, worked out when the span
			# was collected, and `base` -- the frame displacement
			# `window_borrow` computes here -- does not apply to it. A span
			# backed by a block is refused nothing by a function that will
			# lend no frame, which is the whole point of offering it.
			lowered = lower_ymm_span(entries, span_base, helper,
			                         stub_address + len(body), pool,
			                         span_block, second_helper)
			if lowered is None:
				if reasons is not None:
					reasons["the span operand cannot be moved"] += 1
				return None, 0
			body += lowered
			lowered = b""
		else:
			# **The frame path is an `else` and not a fall-through.** The
			# first version left the block branch falling into this call,
			# which overwrote the bytes it had just emitted and then passed
			# `base` -- None for a block-backed span, because no frame
			# region was found -- straight into `encode_spill`. It crashed
			# on the first site rather than corrupting one, which is the
			# only reason it cost a build and not a binary.
			if base is None:
				if reasons is not None:
					reasons["the span will not hold one slot "
					        "displacement"] += 1
				return None, 0
			lowered = lower_ymm_span(entries, base, helper,
			                         stub_address + len(body), pool,
			                         None, second_helper)
			if lowered is None:
				if reasons is not None:
					reasons["the span operand cannot be moved"] += 1
				return None, 0
	elif kind == "zero":
		vex = inplace.decode_vex(encoding)
		lowered = lower_ymm_zero_store(vex, encoding[vex["length"]:], site,
		                               len(encoding), stub_address + len(body))
	elif kind == "conststore":
		# A 256-bit store whose value is a load of read-only memory. The
		# bytes are `lower_ymm_pair`'s exactly -- four 128-bit moves, high
		# half first so the register ends holding the low sixteen -- and the
		# only difference is where the load half comes from: not the
		# instruction before this one, but the one `constant_ymm` walked back
		# to, wherever it was.
		vex = inplace.decode_vex(encoding)
		lowered = lower_ymm_pair(
			(strategy[1], (vex, encoding[vex["length"]:], site,
			               len(encoding))),
			stub_address + len(body))
	elif kind == "constload":
		# The other end, and it emits one move rather than four: the low half
		# into the register's own xmm, which is where the original program
		# keeps it. The upper half is left stale on purpose -- every reader
		# of it is a `conststore`, checked by `upper_half_read_later` before
		# this was accepted.
		vex = inplace.decode_vex(encoding)
		lowered = narrow_piece(vex, encoding[vex["length"]:], 0, site,
		                       len(encoding), stub_address + len(body))
	else:
		# The site's own lowering, and the only lower_vex call whose failure
		# means the stub is refused -- a swallowed one is attributed to
		# `moved_instruction` above. Finding 89.
		lowered = lower_vex(site, encoding, operands, mnemonic,
		                    stub_address + len(body), scratch, pool, reasons)
	if lowered is None:
		if reasons is not None:
			reasons["the site itself will not lower"] += 1
		return None, 0
	body += lowered

	# **A block pointer for a borrowing passenger, where the window lends
	# no frame slot.** Two cases, measured at 5 and 24 of the 29 that were
	# refused here: the site's own spill already planted one and it is
	# still live -- nothing between there and here touches a GPR -- or the
	# site is not a spill at all and none exists, so one is planted now.
	# Either way the passenger uses the site's slot, which is free because
	# the brackets are sequential. Finding 182.
	passenger_block = None
	if base is None and tls is not None and any(
			len(entry) > 6 and entry[6] for entry in displaced):
		if tls_pair is not None:
			passenger_block = tls_pair[0]
		else:
			available = sorted(window_gpr_free(home, start, window))
			if len(available) >= 2:
				ordered = sorted(available, key=lambda n: -n)
				body += encode_tls_base(ordered[0], ordered[1], tls[0],
				                        stub_address + len(body))
				passenger_block = ordered[0]
	for entry in displaced:
		fixed = emit_swallowed(entry, body, stub_address, pool,
		                       spill_base, reasons, base,
		                       block=passenger_block,
		                       slot=tls[1] if tls is not None else 0)
		if fixed is None:
			if reasons is not None:
				reasons["a displaced instruction will not move"] += 1
			return None, 0
		body += fixed

	# Back to the instruction after the WINDOW, which is not the instruction
	# after the original once the window has been widened.
	body += encode_jump(stub_address + len(body) + 5, start + window)
	return bytes(body), prologue


CONTROL_PREFIXES = ("j", "call", "ret", "loop", "iret", "syscall", "sysret",
                    "int", "ud", "hlt")


def parse_with_comments(listing):
	"""Like patch.parse_listing, but keeps objdump's resolved-target comment.

	A displaced instruction that is RIP-relative has to have its
	displacement recomputed, and the comment is where the absolute target
	can be read without writing a full instruction decoder.
	"""
	pending = None
	for line in open(listing, "r", errors="replace"):
		parts = line.split("\t")
		if len(parts) == 2 and pending is not None:
			try:
				pending[1].extend(bytes.fromhex(parts[1].strip()))
			except ValueError:
				pass
			continue
		if pending is not None:
			yield (pending[0], bytes(pending[1]), pending[2], pending[3],
			       pending[4])
			pending = None
		if len(parts) < 3:
			continue
		head = parts[0]
		colon = head.rfind(":")
		if colon < 0:
			continue
		try:
			address = int(head[:colon].strip(), 16)
		except ValueError:
			continue
		try:
			encoding = bytes.fromhex(parts[1].strip())
		except ValueError:
			continue
		body = parts[2]
		comment = None
		hash_at = body.find("#")
		if hash_at >= 0:
			trailing = body[hash_at + 1:].strip()
			if trailing.startswith("0x"):
				try:
					comment = int(trailing.split()[0], 16)
				except ValueError:
					comment = None
			body = body[:hash_at]
		fields = body.strip().split(None, 1)
		if not fields:
			continue
		mnemonic = fields[0]
		operands = fields[1] if len(fields) > 1 else ""
		# The same REX-prefix correction `patch.parse_listing` makes, and it
		# has to be made twice because there are two parsers. Fixing only the
		# other one moved `verify`'s branch-target count by 35 and left the
		# collector reading `rex.W` as a mnemonic, which is the half that
		# decides anything. Finding 85.
		if inplace.REX_PREFIX.match(mnemonic) and operands:
			rest = operands.split(None, 1)
			mnemonic = rest[0]
			operands = rest[1] if len(rest) > 1 else ""
		pending = [address, bytearray(encoding), mnemonic, operands, comment]
	if pending is not None:
		yield (pending[0], bytes(pending[1]), pending[2], pending[3], pending[4])


def relocate(encoding, old_address, new_address, rip_target):
	"""An instruction copied to a new address, with its RIP displacement fixed.

	Locating the displacement without decoding the instruction: it is the
	four-byte little-endian value equal to `target - end`, and it is found
	by searching for exactly that. Where it appears more than once the
	position is ambiguous and the site is refused rather than guessed at.
	"""
	if rip_target is None:
		return encoding
	old = struct.pack("<i", rip_target - (old_address + len(encoding)))
	first = encoding.find(old)
	if first < 0 or encoding.find(old, first + 1) >= 0:
		return None
	new = struct.pack("<i", rip_target - (new_address + len(encoding)))
	return encoding[:first] + new + encoding[first + 4:]


def held_back(pair_reason, run_reason):
	"""Which of two refusals to record when the run strategy declines a site.

	The pair is tried first, because it needs no helper register, and the run
	is the fallback for the pair rather than the other way round. So a site
	that reaches the run at all has already been refused by the pair, and the
	pair's reason is the more specific of the two: it names the property of
	the code that stopped the cheaper lowering, where the run's names only the
	register pressure that stopped the more expensive one.

	`collect` said above the loop that the pair's reason is "held back and
	only recorded if the run declines too", and then did not do it -- all four
	run-decline branches recorded their own and returned to the top of the
	loop, taking the held-back one with them.

	**It cost no sites, which is why it survived.** Finding 75 measured the
	fallback it looks like it should have at zero of 2,101: the pair really
	had been tried, so there was nothing to fall back to. What it cost was the
	census. 1,587 sites were filed under register pressure when the collector
	already knew they were blocked on a later 256-bit read of a stale upper
	half -- pointing a reader at the helper allocator when the work is the Y1
	register representation. Finding 76.
	"""
	return run_reason if pair_reason is None else pair_reason


# The 64-bit name a 32-bit register belongs to, for reading a switch
# dispatch: the table load writes `%ecx` and the `add` that follows names
# `%rcx`, and matching them means knowing they are one register.
SWITCH_WIDE = dict(zip(
	["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
	+ [f"r{i}d" for i in range(8, 16)],
	["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
	+ [f"r{i}" for i in range(8, 16)]))
SWITCH_LOAD = re.compile(r"^(0x[0-9a-f]+)\(%(\w+),%(\w+),4\),%(\w+)$")
SWITCH_ADD = re.compile(r"^%(\w+),%(\w+)$")
SWITCH_BACK = 16			# how far back a dispatch may be spread


def require_qemu(qemu):
	"""qemu present, able to start, and able to run AVX2 -- or skip at 77.

	**One implementation, because four copies of this have now been wrong
	twice in the same way.** `vex_oracle`, `lane_oracle`, `span_oracle` and
	`shape_oracle` each carried their own: one asked presence and not
	capability, one left the probe outside its `try`, and all four blamed a
	missing AVX2 model for a qemu that had produced nothing at all.

	Three failures, three messages, because a diagnostic that names a cause
	the code never tested sends the reader after the wrong thing:

	- not on `$PATH` -- install it;
	- on `$PATH` and will not exec, or hangs -- `OSError` or a timeout;
	- exec'd and produced no model list -- typically a missing shared
	  library, where the loader writes to stderr and the child exits 127.
	  Empty stdout and no `OSError`, so this used to read as "no avx2".

	**The discriminator is stdout, not the exit status.** Real
	`qemu-x86_64 -cpu help` exits **1** on this machine while printing 219
	lines of models including avx2, so a `returncode` check would refuse
	the working case. What separates "could not tell us" from "told us no"
	is whether it said anything.
	"""
	import shutil
	if shutil.which(qemu[0]) is None:
		print(f"no {qemu[0]}: install qemu-user. SKIPPED, not passed.",
		      file=sys.stderr)
		raise SystemExit(77)
	try:
		probe = subprocess.run(qemu + ["-cpu", "help"], capture_output=True,
		                       text=True, timeout=60)
	except OSError as error:
		print(f"{qemu[0]} will not run ({error}). SKIPPED, not passed.",
		      file=sys.stderr)
		raise SystemExit(77)
	except subprocess.TimeoutExpired:
		print(f"{qemu[0]} -cpu help timed out. SKIPPED, not passed.",
		      file=sys.stderr)
		raise SystemExit(77)
	if "avx2" in probe.stdout:
		return
	if not probe.stdout.strip():
		first = (probe.stderr or "").strip().splitlines()
		why = first[0] if first else f"exit {probe.returncode}, no output"
		print(f"{qemu[0]} -cpu help produced no model list ({why}). "
		      f"SKIPPED, not passed.", file=sys.stderr)
	else:
		print(f"{qemu[0]} reports no avx2 model. SKIPPED, not passed.",
		      file=sys.stderr)
	raise SystemExit(77)


def switch_dispatch(window):
	"""The RVA of the table a dispatch reads, or None. Pure, so it is tested.

	`window` ends at the indirect `jmp`. The shape sought is the three
	instructions MSVC emits, in any order within the window and with other
	work between them:

	    mov  0x181d498(%r9,%rax,4),%ecx    # r9 = __ImageBase
	    add  %r9,%rcx
	    jmp  *%rcx

	The `add` names the register holding the image base; the `mov` must
	load through that same register into the 32-bit half of the jump's
	target. Both links matter: without the first this matches any scaled
	load, and without the second it matches a load into an unrelated
	register.

	**Split out because the enclosing function had no test.** A missing
	`import collections` in it passed `make style` and the selftest and
	would have surfaced only in a forty-minute build -- the same shape as
	the gate defects reported against this tree, in new code. The byte
	reading still needs a binary; this half does not, so this half is
	tested. Finding 177.
	"""
	rows = list(window)
	if not rows:
		return None
	operands = rows[-1][3] or ""
	if rows[-1][2] != "jmp" or not operands.startswith("*%"):
		return None
	register = operands[2:].strip()
	back = rows[-2::-1]			# most recent first, excluding the jmp
	holder = None
	for prior in back:
		match = SWITCH_ADD.match(prior[3] or "")
		if prior[2] == "add" and match and match.group(2) == register:
			holder = match.group(1)
			break
	if holder is None:
		return None
	for prior in back:
		match = SWITCH_LOAD.match(prior[3] or "")
		if not (prior[2] == "mov" and match):
			continue
		offset, holds, _index, into = match.groups()
		if holds == holder and SWITCH_WIDE.get(into) == register:
			return int(offset, 16)
	return None


def switch_targets(instructions, binary, starts):
	"""Where an indirect `jmp` through a switch table can land.

	**`targets.from_switch_tables` has the wrong base.** Its docstring says
	an MSVC x64 table holds `target - table`; that is the x86 form. This
	binary holds RVAs -- `target - __ImageBase` -- so the scan that looks
	for self-consistent runs of `table + value` finds noise. Measured: its
	targets land on an instruction boundary 24.67% of the time against a
	27.09% baseline, which is chance, and 3 of its 14,574 are real. See
	Finding 174.

	This reads the dispatch instead of guessing at the table, which is what
	makes it exact rather than statistical:

	    mov  0x181d498(%r9,%rax,4),%ecx    # r9 = __ImageBase
	    add  %r9,%rcx
	    jmp  *%rcx

	The table is at `__ImageBase + 0x181d498`, its entries are RVAs, and it
	runs until an entry stops naming an instruction. `starts` is what makes
	that terminator sound: a real code address begins an instruction and
	arithmetic noise does so only by chance.

	**Blocking too much is safe and blocking too little is not.** An
	address wrongly in `blocked` costs sites, because a window declines to
	widen past it; one wrongly absent lets a window swallow a place control
	arrives at, and the program jumps into the middle of a stub.
	"""
	data = open(binary, "rb").read()
	sections, base, _opt = target_set.sections_of(data)
	# **`targets.sections_of` returns the virtual address ALREADY
	# absolute** -- `base + vaddr` -- where `detour.sections_of` returns it
	# relative. Adding the base a second time here put every span
	# 0x140000000 too high, `at` resolved nothing, and the resolver found
	# zero tables where the same logic found 1,795 standalone. Caught only
	# because the count is printed: the build's totals were identical to
	# the previous one, which reads exactly like "this changed nothing".
	# Under sabotage the base is added a second time, which is exactly the
	# defect Finding 196's floor exists to catch: every span lands
	# 0x140000000 too high, `at` resolves nothing, and the resolver reports
	# zero tables while still recognising every dispatch. No corrupted image
	# can express that, so the check needs a code control. Finding 238.
	twice = base if CODE_SABOTAGE == "switchbase" else 0
	spans = [(v + twice, r, rs)
	         for v, _vs, r, rs in sections.values() if v and r]

	def at(va):
		for start, raw, size in spans:
			if start <= va < start + size:
				return raw + (va - start)
		return None

	found = set()
	tables = 0
	# **Dispatches recognised, which is a different question from tables
	# read.** A resolver that has broken still recognises the dispatch --
	# Finding 174's doubled base found every one of them and then read
	# noise out of the table -- so "no tables" means the resolver where a
	# dispatch exists, and means nothing at all where none does. Counting
	# both is what lets `verify` tell a broken read from a binary with no
	# switch statement in it. Finding 196.
	dispatches = 0
	# **A sliding window, not a list.** A dispatch spans at most
	# `SWITCH_BACK` instructions, so that is all this needs to remember --
	# and `verify` hands it the listing's own generator. Materialising the
	# rows instead cost several gigabytes on a 927 MB listing (16.5 million
	# tuples) and got `verify` killed twice before the cause was obvious.
	# Rows are indexed rather than unpacked so four-field `parse_listing`
	# output works as well as five-field `parse_with_comments`.
	window = deque(maxlen=SWITCH_BACK)
	for row in instructions:
		window.append(row)
		mnemonic, operands = row[2], row[3] or ""
		if mnemonic != "jmp" or not operands.startswith("*%"):
			continue
		offset = switch_dispatch(window)
		if offset is None:
			continue
		dispatches += 1
		where = at(base + offset)
		if where is None:
			continue
		# The table runs until an entry stops naming an instruction. Two
		# entries is the floor: a one-armed switch is not one, and a lone
		# coincidence should not become a table.
		entries, k = [], 0
		while where + k * 4 + 4 <= len(data):
			value = struct.unpack_from("<I", data, where + k * 4)[0]
			if base + value not in starts:
				break
			entries.append(base + value)
			k += 1
		if len(entries) >= 2:
			found.update(entries)
			tables += 1
	return found, tables, dispatches


# How far back a conservative scan looks for a producer when the walk could
# not name one. It stops at the first `call` regardless -- the Win64 ABI
# makes every ymm upper half volatile across one, so nothing before a call
# can be the producer -- and this is only the ceiling for a stretch with no
# call in it. Finding 198.
CONSERVATIVE_LIMIT = 640

# How far forward `chain_census` looks for the consumer of a result. It is a
# survey bound rather than a correctness one: a consumer further away than
# this is reported as "nothing found", which is honest and is not a claim
# that the value dies. Finding 200.
CHAIN_REACH = 64


def conservative_producers(instructions, position, field, patched, inside):
	"""Sites that could have decided this reader's upper half, or [].

	**For the readers the walk cannot speak for.** `reaching_definitions`
	returns None for 208 of them -- an indirect entry it cannot enumerate,
	a call it cannot see through, a join whose ways decide nothing -- and
	`stale_upper_reads` counts those apart rather than calling them clean,
	which is right and is where it stopped. Counting a risk is not
	carrying it.

	So ask the weaker question that can be answered: which sites this
	rewrite touched COULD be the producer. The Win64 ABI makes every ymm
	upper half volatile across a call, which is the fact this whole project
	rests on, so the producer must lie between the reader and the nearest
	preceding call. Every in-place-patched VEX.128 write to the register in
	that stretch is a candidate, and every one of them is kept in its VEX
	form.

	**It does not stop at the nearest write**, because the walk failed
	exactly where control can arrive by a path that skips one -- that is
	what a join it could not resolve means. All of them, or none.

	**The span is bounded by a call, not by a function.** A `.pdata` start
	is not always a function entry in this binary -- chained fragments are
	settled fact here -- so a per-function scan is narrower than the truth
	and would under-collect. The ABI bound needs no boundary at all.
	Finding 198.
	"""
	narrow = "%xmm" + field[len("%ymm"):]
	found = []
	for step in range(1, CONSERVATIVE_LIMIT + 1):
		at = position - step
		if at < 0:
			break
		address, encoding, mnemonic, operands, _comment = instructions[at]
		if mnemonic.startswith("call"):
			break
		if not operands:
			continue
		wide = inplace.decode_vex(encoding)
		if wide is None or wide["L"]:
			continue
		names = inplace.split_operands(operands)
		if names and names[-1] in (narrow, field) \
				and (address in patched or address in inside):
			found.append(address)
	return found


def stale_upper_reads(instructions, blocked, sources, placed, patched,
                      reasons=None, conservative=False):
	"""[(reader, register, producer)] -- reads of an upper half left stale.

	Asked from the READER's end, because the lowering's end cannot see the
	whole class: a per-strategy guard only covers registers some strategy
	claimed, and the producer here is usually a plain in-place patch that
	no strategy ever touched. Findings 185 and 186.

	A 256-bit instruction survives the rewrite unless a window swallowed
	it -- 256-bit sites are never patched in place -- so `placed` decides
	which readers are still there. `patched` is the set of addresses the
	in-place pass rewrote: a VEX.128 write among them stops zeroing bits
	255:128, which is the fact the original relied on.

	`None` from `reaching_definition` means "cannot tell", not "clean", so
	it is counted apart and returned to the caller to report rather than
	folded into a pass. That inversion is what made the first version of
	this silent exactly where the analysis is weakest.
	"""
	inside = set()
	for start, length, _stub, _size, _prologue in placed:
		inside.update(range(start, start + length))
	found, unknown, unsure = [], 0, []
	for position, row in enumerate(instructions):
		address, encoding, mnemonic, operands, _comment = row
		if address in inside or not operands:
			continue
		wide = inplace.decode_vex(encoding)
		if wide is None or not wide["L"]:
			continue
		for field in upper_half_sources(mnemonic, operands):
			# **The set, because the question is "any of them".** Where the
			# ways into a join reach different definitions, this read is
			# stale if ANY of them is a site the rewrite touched -- the
			# reader takes whatever that path left. Asking for a single
			# definition and refusing on disagreement filed 128 of the 248
			# sources as "cannot speak for". Finding 194.
			why = [] if reasons is not None else None
			try:
				where = reaching_definitions(instructions, position, field,
				                             blocked, sources=sources,
				                             depth=JOIN_DEPTH, why=why)
			except JoinCycle:
				where = refuse(why, "join cycle escaped")
			if where is None:
				unknown += 1
				if conservative:
					for producer in conservative_producers(
							instructions, position, field, patched, inside):
						unsure.append((address, field, producer))
				if reasons is not None:
					# The FIRST entry is the deepest refusal. Later ones are
					# the same refusal propagating out through the joins
					# above it, and counting those would report the shape of
					# the recursion rather than the shape of the gap.
					reasons.append((why[0] if why else ("unrecorded", None),
					                address, field))
				continue
			# **Every rewritten producer, not the first one.** A join
			# reaching two definitions has two ways to be stale, and
			# `apply` repairs a reader by reverting the producer this
			# names -- so naming one and stopping repaired one path and
			# left the other. Measured: `apply` found 52 readers and
			# reverted 45 producers, `verify` then found 5 of those same
			# readers again against the producer on the path nobody had
			# named, and the two reports were disjoint because each saw
			# the reader through a different definition. Finding 194.
			for one in sorted(where):
				producer = instructions[one][0]
				if producer in inside or producer in patched:
					found.append((address, field, producer))
	return found, unknown, unsure


def upper_half_sources(mnemonic, operands):
	"""The `%ymm` operands whose UPPER half this instruction reads.

	**Sources, and not the destination.** In AT&T the last field is written,
	so a reader's own destination is not a read of anything -- and counting
	it made 338 of 470 reports noise. A store's ymm is `fields[:-1]` and its
	memory operand is last, so the same rule reads a store correctly.

	**And not every source's upper half is read.** `vinsertf128 $0x1`
	replaces the destination's high lane and takes only src1's LOW half, so
	the stale bits are discarded rather than observed -- 101 more of the
	470. `vperm2f128 $0x20` selects both operands' low lanes, 2 more.
	Finding 186.
	"""
	fields = inplace.split_operands(operands or "")
	if len(fields) < 2:
		return []
	immediate = fields[0] if fields[0].startswith("$") else None
	sources = [f for f in fields[:-1] if f.startswith("%ymm")]
	# **A read-modify-write destination is a source too.** `fields[:-1]`
	# is right for everything that only writes its last operand, and wrong
	# for an FMA, whose accumulator is read as well -- the rule claimed
	# "sources" generally and these are the counterexample. It costs
	# nothing in this binary (no FMA reader has a stale field under any
	# operand rule) and it would cost correctness in one that did.
	if fields[-1].startswith("%ymm") and (
			mnemonic.startswith(("vfmadd", "vfmsub", "vfnmadd", "vfnmsub",
			                     "vfmaddsub", "vfmsubadd", "vpdp"))):
		sources.append(fields[-1])
	if mnemonic.startswith(("vinsertf128", "vinserti128")) \
			and immediate in ("$0x1", "$1"):
		return []
	if mnemonic.startswith("vperm2f128") and immediate in ("$0x20", "$32"):
		return []
	return sources


def analysis_context(binary, listing):
	"""(instructions, plain, blocked, sources) -- the walk's shared inputs.

	**One construction, because two would drift.** `verify` asks
	`reaching_definition` the same question `collect` asks, and a `blocked`
	set built twice is two answers to "can anything reach here" -- the
	failure `SPAN_EMITTABLE` exists to prevent between a survey and a
	lowering, and which this file has now met between the collector and the
	lowering, the survey and the collector, and the collector and the
	emitter. Finding 186.
	"""
	# Everything anything can branch to. A window may not contain one of
	# these anywhere but at its first byte.
	groups = target_set.collect(binary)
	blocked = set()
	for values in groups.values():
		blocked |= values
	instructions = list(parse_with_comments(listing))
	# The liveness scan wants the plain four-field shape.
	plain = [(a, e, m, o) for a, e, m, o, _c in instructions]
	# **Which instructions branch where, not merely that they do.** `blocked`
	# answers "can anything reach this address"; `sources` answers "and from
	# where", which is what tells a loop back edge from an arbitrary entry.
	# See `zero_survives_loop`.
	sources = {}
	for i, (address, _e, mnemonic, operands, comment) in enumerate(instructions):
		if mnemonic.startswith(("j", "call", "loop")) and operands:
			first = operands.split()[0]
			if first.startswith("0x"):
				try:
					target = int(first, 16)
				except ValueError:
					pass
				else:
					blocked.add(target)
					sources.setdefault(target, []).append(address)
		elif mnemonic == "lea" and isinstance(comment, int) \
				and "(%rip)" in operands:
			# A function address taken PC-relatively, so no relocation
			# records it and no call names it. It can still be called
			# through the pointer, which makes it a branch target like any
			# other -- see outside.lea_targets.
			blocked.add(comment)

	# **Where an indirect jump can land**, read from the dispatch rather
	# than guessed at. `targets.from_switch_tables` looks for runs of
	# `table + value` and this binary's tables hold RVAs, so it finds
	# noise; 12,869 real switch targets were absent from `blocked`
	# entirely, 147 of them with nothing else shielding them. Finding 174.
	starts = {a for a, *_rest in instructions}
	switched, switch_tables, _dispatches = switch_targets(
		instructions, binary, starts)
	fresh = switched - blocked
	blocked |= switched
	# **Said out loud, because a count nobody prints cannot be checked.**
	# The first version of this put the numbers in `stats`, which `apply`
	# discards as `_stats` -- so "the resolver found nothing" and "the
	# resolver never ran" produced identical output, which is the whole
	# defect this session has been removing from other people's gates.
	print(f"collect: {switch_tables:,} switch tables read, "
	      f"{len(switched):,} targets, {len(fresh):,} of them not already "
	      f"blocked", file=sys.stderr)

	return instructions, plain, blocked, sources, switch_tables, len(switched)


def data_islands(instructions, gap=None):
	"""Address spans objdump could not decode, clustered. Finding 225.

	**One authority for what an island is.** The collector refuses a
	candidate standing in one, `verify` checks that none of their bytes
	moved, and `vex_scan` names them with the same 256-byte gap -- so the
	three agree by construction rather than by three people picking the
	same number.

	Clustering over-covers, sweeping in real code that lies between two
	data runs. Measured on Starfield that costs exactly ONE site: 747
	islands hold a single cleanly-decoding VEX instruction between them,
	the `vphsubd` at 0x142c4079a, and that one is itself a constant pool's
	bytes. So the over-coverage is free here, which is why the collector
	can afford to refuse on it.
	"""
	if gap is None:
		gap = ISLAND_GAP
	islands = []
	for row in instructions:
		if row[2] != "(bad)" or not row[1]:
			continue
		low, high = row[0], row[0] + len(row[1])
		if islands and low - islands[-1][1] <= gap:
			islands[-1][1] = max(islands[-1][1], high)
		else:
			islands.append([low, high])
	return islands


def in_island(islands, address):
	"""Whether `address` falls inside one of `islands`, which are sorted."""
	low, high = 0, len(islands) - 1
	while low <= high:
		mid = (low + high) // 2
		if islands[mid][1] <= address:
			low = mid + 1
		elif islands[mid][0] > address:
			high = mid - 1
		else:
			return True
	return False


def collect(binary, listing, context=None):
	"""(in-place patches, class C detour candidates, statistics).

	`context` is `analysis_context`'s tuple, passed in by a caller that
	needs it as well -- `apply` reverts in-place patches with it and
	`verify` checks them. Building it twice parses a 927 MB listing twice
	and holds 16.5 million rows twice; the second copy is what ran `verify`
	out of memory before it was noticed. One build, shared.
	"""
	# A run reports its own numbers, not the previous one's.
	OVERLAP_REFUSED.clear()
	SAVED_XMM.clear()
	SAVED_XMM.update(saved_xmm_map(binary))
	REGION_REFUSED.clear()
	REGION_EXAMPLES.clear()
	COLLECT_SEEN.clear()
	UNIT_REFUSED.clear()
	UNIT_RUNG.clear()
	UNIT_EXAMPLES.clear()
	WIDE_SITES.clear()
	instructions, plain, blocked, sources, switch_tables, switch_seen = \
		context if context is not None else analysis_context(binary, listing)
	# The code oracle, in two parts. .pdata is the binary's own statement
	# about where its functions are and needs no disassembly to read, but the
	# x64 ABI lets a leaf function omit its unwind data -- and refusing those
	# was the largest single reason sites survived. tool/outside.py recovers
	# them, under conditions strict enough that data cannot pass: bracketed
	# by int3, entered by a call or jump, ending in a control transfer, and
	# containing no byte objdump failed to decode.
	described = inplace.function_ranges(binary)
	ranges = sorted(described + outside.leaf_ranges(plain, described, blocked))
	# What each function never touches, for the sites the forward scan
	# cannot get past. Computed once; it is a pass over the whole listing.
	scope = scratch_finder.function_scope(plain, ranges)
	# {address: index}, for following a branch rather than stopping at one.
	# Built from `plain` because that is the list the liveness scan already
	# indexes, and the two lists are the same instructions in the same order
	# -- `plain` is a comprehension over `instructions` -- so one mapping
	# serves both.
	positions = scratch_finder.address_index(plain)
	# Which store addresses a long-pair load has reserved a register for.
	# Written when the load commits, read when the store is reached.
	long_shadow = {}
	# Which functions can lend their callee home space, if asked to.
	home = home_space_map(binary, plain, ranges, blocked) \
		if SPILL in HOME_SPILLS else None
	# Where a per-thread slot would sit, if this image has a TLS directory
	# at all. `None` makes `--spill=tls` behave exactly as `--spill=home`,
	# which is the right answer for an image with no TLS: there is no index
	# for the loader to write and nowhere to put the bytes.
	tls_slot_offset = None
	if SPILL == SPILL_TLS:
		with open(binary, "rb") as image:
			found = tls_slot(image.read(), tls_block_slots() * SLOT)
		if found is not None:
			tls_slot_offset = found
	# Where a 256-bit load can be taken at its word. Only the headers are
	# read: the ranges come from the section table, and the bytes inside them
	# are the CPU's business rather than this tool's.
	with open(binary, "rb") as image:
		readonly = readonly_ranges(image.read(1 << 16))
	patches, stats, _blocked = inplace.build_patches(listing, ranges)
	stats["switch tables read"] = switch_tables
	stats["switch targets blocked"] = switch_seen

	# Anything already rewritten in place needs nothing further. Everything
	# else that HAS a lowering is a detour candidate -- not just Class C.
	#
	# The first version of this only considered Class C, which left 25,345
	# class A and B sites untouched for no better reason than that their
	# SSE encoding is one byte longer than the VEX one. A site that does
	# not fit in place and does have a lowering is exactly what a stub is
	# for, whichever class it belongs to.
	already = {address for address, *_rest in patches}

	candidates = []
	skipped = Counter()
	declined = {}
	islands = data_islands(instructions)
	for index, (address, encoding, mnemonic, operands,
	            _comment) in enumerate(instructions):
		if not encoding or encoding[0] not in (0xC4, 0xC5):
			continue
		# **A byte objdump could not decode is not an instruction.** The
		# test below rejects on LENGTH alone and never checks that the map
		# field is one of the three that exist, so a constant pool's
		# `c5 32 00` -- map 1, opcode 00 -- decodes as a VEX prefix and is
		# offered to every strategy. Nothing was ever lowered from one,
		# because each strategy is keyed on a mnemonic and none has an
		# entry for `(bad)`; that is the far wall of the room rather than
		# the door, and the 256-bit strategies already branch on `vex["L"]`
		# taken straight from the unvalidated prefix. Starfield carries 180
		# such sequences in the data islands of Finding 8, and 99 of them
		# reached this loop. Finding 222.
		if mnemonic == "(bad)" and CODE_SABOTAGE != "badrow":
			continue
		# **And a byte that decodes CLEANLY can still be data.** The guard
		# above refuses what objdump refused; it cannot see a constant pool
		# whose bytes happen to form a real instruction. Starfield holds
		# one: `c4 02 1a 05` at 0x142c4079a is a valid VEX.128 map-2
		# `vphsubd`, and it sits in a 4-byte-stride table of them. The
		# region strategy took it as a member and refused it for "lanereg3
		# source from outside the region" -- a shape reason having nothing
		# to do with standing in data, which is protection by luck.
		#
		# Refusing the island interior costs that one site and nothing
		# else, because it is the only cleanly-decoding VEX instruction
		# inside any of the 747. Finding 225.
		if in_island(islands, address):
			declined[address] = "standing in a data island"
			continue
		if address in already:
			continue
		COLLECT_SEEN.add(address)
		vex = inplace.decode_vex(encoding)
		if vex is None:
			continue
		if vex["L"]:
			# **The denominator for the uniform representation**, counted
			# where the loop decodes so it cannot drift from what is
			# offered. A deficit is only meaningful against the whole.
			WIDE_SITES["256-bit"] += 1

		# **Under the uniform representation the unconditional lowering
		# goes FIRST, and this is the same argument Finding 160 made for
		# the region, one step further.** `pair`, `run`, `zero`, `spill`
		# and `plain` are consumer-driven: each takes a site because it can
		# do something cheap with the shape in front of it, and none of them
		# maintains a slot. So under `--shadow-regs=all` every site one of
		# them takes is a HOLE in the invariant, and offering `unit` after
		# them means it only ever sees what they declined.
		#
		# Measured on Starfield: offered last, 1,329 of 35,844 sites are
		# lowered through a slot and the representation is 3.7% whole.
		# Offered first, 32,810 are and it is 91.5% whole. The frontier
		# falls 4,776 -> 3,384.
		#
		# **The correctness axes move with it, which is the part worth
		# keeping.** A slot-maintaining lowering leaves a live upper half
		# where a surviving 256-bit reader looks, so the conflicts that cost
		# windows fall rather than rise: patches reverted 176 -> 47, and the
		# upper-half sources the walk cannot resolve 149 -> 81. The cost is
		# the stub, 3,828,001 -> 4,582,697 bytes, about 24 bytes per site
		# for a slot that is maintained.
		#
		# It is gated on the rule because it is only right under it: with no
		# permanent slots there is no invariant to protect, and `unit` is
		# then simply the most expensive way to lower a site. Finding 260.
		if SHADOW_REGS_RULE == SHADOW_REGS_ALL and vex["L"]:
			lone = unit_shortening(instructions, plain, index, blocked,
			                       home, ranges, scope, tls_slot_offset)
			if lone is not None:
				candidates.append(lone)
				continue

		strategy = None
		y_reason = []
		# What a Y strategy said when it could not lower this site. **A
		# strategy that cannot lower a site must not consume it**, so the
		# reason is carried past the strategies that follow and recorded
		# only if none of them takes the site either. See Finding 125.
		carried = None
		# A 256-bit copy through one ymm, taken as a unit. Both halves of
		# it are refused individually -- there is no SSE form of either --
		# so this has to be seen before either is considered alone.
		# **The pair is tried first because it needs no helper register**,
		# and a failure here is not a refusal: the run below solves the same
		# problem differently and can take what the pair cannot. Its reason
		# is held back and only recorded if the run declines too -- one
		# source copied to two destinations was being refused for reading an
		# upper half that a run would have kept in a register.
		# **The region goes first among the 256-bit strategies**, which is
		# what Finding 160 measured the cost of not doing: offered last it
		# saw 920 eligible regions and became 70 candidates, because the
		# pair and the run had already taken the sites. Offered first it
		# competes for the 7,255 the pair places and the 2,050 the run
		# does.
		#
		# **This may be a regression and the measurement is the point.** A
		# pair lowers a 256-bit copy through a register helper; a region
		# routes the same value through a memory slot, which is slower per
		# site. If the site count rises and the stub section rises with it,
		# the region is buying sites at a price nobody has costed -- and
		# Finding 123's rule is that a strategy which SUCCEEDS can still
		# take work a better one was doing.
		if vex["L"] and REGION_PLACE == REGION_EARLY:
			regional = region_candidate(instructions, plain, positions,
			                            index, blocked, home, ranges,
			                            scope, tls_slot_offset)
			if regional is not None:
				candidates.append(regional)
				continue
		pair_reason = None
		if vex["L"] and index + 1 < len(instructions):
			following = instructions[index + 1]
			splat = splat_pair(instructions[index], following)
			if splat is not None and following[0] == address + len(encoding) \
					and following[0] not in blocked:
				# **A store does not end the value's life, and this is the
				# third time that has been the finding.** Finding 105 learned
				# it for the long pair and Finding 106 for the zero run;
				# `splat_pair` takes the insert and the ONE store after it,
				# and MSVC broadcasts a constant into eight consecutive
				# fields at a time. The rest were refused for having no known
				# upper half, which they do -- it is the same sixteen bytes
				# as the low one, which is the whole point of the insert.
				#
				# Nothing between the stores can disturb the register because
				# there is nothing between them: `store_run` takes only
				# address-adjacent members. So the predicate has just one
				# question to ask. Finding 113.
				held = inplace.split_operands(operands)[3]
				group = store_run(instructions, index + 1, blocked,
				                  lambda _position, name: name == held)
				window = len(encoding) + len(following[1])
				if group is not None:
					members, last = group
					tail_entry = instructions[last]
					span = tail_entry[0] + len(tail_entry[1]) - address
					entries = []
					for position in members:
						one = instructions[position]
						one_vex = inplace.decode_vex(one[1])
						entries.append((one_vex, one[1][one_vex["length"]:],
						                one[0], len(one[1])))
					# **The insert emits nothing, so the machine ymm's
					# upper half is never written.** The lowering stores
					# the low xmm twice -- memory gets the right 32 bytes
					# -- and the register keeps whatever preceded the
					# insert, where the original had the low half copied
					# up. A surviving 256-bit read of it therefore takes
					# sixteen stale bytes, which is the pair's obligation
					# (Finding 38), the run's (64), the span's (153), the
					# region's (173) and the long pair's (180). This path
					# never asked. Finding 184.
					if inplace.covered_by(ranges, address, span) \
							and lower_zero_run(entries, address) is not None \
							and not upper_half_read_later(
								instructions, last, held,
								positions=positions):
						candidates.append(
							(address, encoding, operands, mnemonic, span,
							 [], None, [], ("splatrun", entries)))
						continue
				# `index + 1` is the store, and the scan begins strictly
				# after the index it is given, so this asks about
				# everything past the window. Measured cost: one site,
				# `0x1434dc07b`, whose stub stored `%xmm0` twice and
				# returned to three surviving `vmovdqu %ymm0` readers on
				# two paths, each writing sixteen correct bytes and
				# sixteen stale. Finding 184.
				if inplace.covered_by(ranges, address, window) \
						and lower_ymm_zero_store(*splat, at=address) \
						is not None \
						and not upper_half_read_later(
							instructions, index + 1, held,
							positions=positions):
					candidates.append(
						(address, encoding, operands, mnemonic, window,
						 [], None, [], ("splat", splat)))
					continue
			# The splat used by one lane-wise operation and then stored.
			# All three instructions are refused today and none of them
			# needs a helper. See `splat_operation`.
			if index + 2 < len(instructions):
				third = instructions[index + 2]
				triple = splat_operation(instructions[index], following,
				                         third)
				if triple is not None and following[0] not in blocked \
						and third[0] not in blocked:
					window = (third[0] + len(third[1])) - address
					# **Two registers, not one.** The splat's own ymm
					# keeps a stale upper half exactly as above, and so
					# does the operation's destination: the lowering
					# writes its low sixteen and never its high. Both are
					# asked. Finding 184.
					# `following` is the operation and `third` the store:
					# the destination left holding only a low half is the
					# OPERATION's, and the first draft of this took the
					# store's last operand, which is a memory reference.
					# `check-pe`'s `splatop` fixture returned 29 for 69.
					splatted = inplace.split_operands(operands)[3]
					op_fields = inplace.split_operands(following[3] or "")
					op_dest = op_fields[-1] if op_fields else None
					if op_dest is not None and not op_dest.startswith("%ymm"):
						op_dest = None
					if inplace.covered_by(ranges, address, window) \
							and lower_splat_operation(*triple, at=address) \
							is not None \
							and not upper_half_read_later(
								instructions, index + 2, splatted,
								positions=positions) \
							and not (op_dest and upper_half_read_later(
								instructions, index + 2, op_dest,
								positions=positions)):
						candidates.append(
							(address, encoding, operands, mnemonic, window,
							 [], None, [], ("splatop", triple)))
						continue

			pair = ymm_pair(instructions[index], following)
			if pair is not None:
				window = len(encoding) + len(following[1])
				held = operands.rpartition(",")[2]
				if following[0] != address + len(encoding):
					pair_reason = "ymm pair not adjacent"
				elif following[0] in blocked:
					pair_reason = "ymm store is a branch target"
				elif upper_half_read_later(instructions, index + 1, held,
				                           positions=positions):
					pair_reason = "ymm upper half read later"
				elif not inplace.covered_by(ranges, address, window):
					pair_reason = "outside .pdata"
				# The stub's address decides a RIP displacement, and it is
				# not known yet; the site's own address stands in, which is
				# what the Class C probe below does for the same reason.
				elif lower_ymm_pair(pair, address) is None:
					pair_reason = "ymm pair operand cannot be offset"
				else:
					candidates.append((address, encoding, operands, mnemonic,
					                   window, [], None, [], ("pair", pair)))
					continue

		# The same copy with something in between, held in a second register
		# so that nothing between the two halves has to move. The whole span
		# goes into one stub, which is what keeps it an ordinary window.
		if vex["L"]:
			found = ymm_run(instructions, index, blocked, why=y_reason)
			if found is not None:
				# **The whole run first, then shorter ones.** `free_across`
				# wants a register dead from the load to the LAST store, so
				# a long span is harder to serve than a short one -- and a
				# run refused for want of a helper often has a prefix that
				# is not. See `run_prefixes`. The reason recorded is the
				# longest prefix's, because that is the run the walk found
				# and the one a reader of the census would go looking for.
				anchor = operands.rpartition(",")[2]
				taken, refusal = None, None
				for members, last in run_prefixes(anchor, found[0]):
					tail_entry = instructions[last]
					window = tail_entry[0] + len(tail_entry[1]) - address
					# The borrow is offered only where the function can lend
					# and the span leaves `rsp` alone -- see `span_keeps_rsp`
					# for why the second matters here and did not in
					# Finding 93.
					lendable = (SPILL in HOME_SPILLS
					            and borrow_offset(home, address) is not None
					            and span_keeps_rsp(instructions, index, last))
					assigned = assign_helpers(plain, positions, index,
					                          members, lendable)
					helpers, borrowed = assigned if assigned else (None, set())
					if helpers is None:
						refusal = refusal \
							or "no register free across the ymm run"
						continue
					# **A run leaves every one of its ymms with a stale upper
					# half**, exactly as a pair does: the low half is in the
					# register's own xmm and the high half is in a helper the
					# original code knows nothing about. The pair strategy
					# has guarded that since Finding 38 and the run did not,
					# which was a live defect for as long as runs have
					# existed -- a later 256-bit read of any register in the
					# run would take whatever was left in its upper half.
					# Finding 64.
					# Over the run's ymm registers, which `helpers` no longer
					# keys on: it keys on the position of each load and
					# store, so that one register can hold two values. See
					# `lifetimes`.
					held_open = {anchor}
					held_open |= {r for _k, _p, r in members if r is not None}
					if any(upper_half_read_later(instructions, last, register,
					                             positions=positions)
					       for register in held_open):
						refusal = refusal or "ymm run upper half read later"
						continue
					if not inplace.covered_by(ranges, address, window):
						refusal = refusal or "outside .pdata"
						continue
					entries = [("load", helpers[index], vex,
					            encoding[vex["length"]:], address,
					            len(encoding), None)]
					for kind, position, register in members:
						entry = instructions[position]
						if kind == "plain":
							entries.append((
								"plain", None, None, None, entry[0],
								len(entry[1]),
								(entry[0], entry[1], entry[4], entry[3],
								 entry[2],
								 swallowed_scratch(plain, position, entry[0],
								                   entry[1], entry[3],
								                   entry[2], scope))))
							continue
						one = inplace.decode_vex(entry[1])
						entries.append((kind, helpers[position], one,
						                entry[1][one["length"]:], entry[0],
						                len(entry[1]), None))
					run = (helpers, entries, borrowed)
					if lower_ymm_run(run, address, address) is None:
						refusal = refusal or "ymm run operand cannot be moved"
						continue
					taken = (address, encoding, operands, mnemonic, window,
					         [], None, [], ("run", run))
					break
				if taken is not None:
					candidates.append(taken)
					continue
				# This declined the site outright, so the zero store, the
				# long pair, the constant and the ordinary path never saw
				# it -- and Finding 123 measured the same fault from the
				# other side, where a run that SUCCEEDED took work the long
				# pair was doing. Carry the reason instead; `held_back`
				# already does exactly this for the pair one level up.
				carried = held_back(
					pair_reason,
					refusal or "no register free across the ymm run")
		# **The span, where the run did not take the site.** A run carries
		# copies and whatever lies between them; a span carries arithmetic
		# too, by keeping each upper half in a 16-byte slot rather than in a
		# helper register. Both anchor at a 256-bit load, so the span is
		# offered second -- Finding 125's rule, that a strategy which cannot
		# lower a site must not consume it, and its corollary that one which
		# CAN must not be reached only through one that did. Reaching here
		# at all means the run did not take it: every path that takes a site
		# continues.
		#
		# **Outside the run's own arm, deliberately.** The first wiring sat
		# inside `if found is not None`, so a load whose next instruction is
		# arithmetic -- which is exactly what stops a run, and exactly what
		# a span exists for -- never reached it. It took zero sites and
		# every gate stayed green, because a strategy nobody offers is
		# indistinguishable from one that refuses.
		if vex["L"]:
			spanned = span_candidate(instructions, plain, positions, index,
			                         blocked, home, ranges, scope,
			                         tls_slot_offset)
			if spanned is not None:
				candidates.append(spanned)
				continue

		# **The region in its middle position**, which `--region-place=middle`
		# selects and which is the default. The switch chooses BETWEEN
		# THREE PLACES and not between on and off: the first version of it
		# deleted this call and made the early one conditional, so turning
		# the switch back off did not restore the old order, it disabled
		# the region -- 100 sites, shipped in a commit whose message said
		# "put it back", and found only when a later verify came back 6,505
		# against a 6,405 baseline. Finding 166.
		if vex["L"] and REGION_PLACE == REGION_MID:
			regional = region_candidate(instructions, plain, positions,
			                            index, blocked, home, ranges,
			                            scope, tls_slot_offset)
			if regional is not None:
				candidates.append(regional)
				continue

		if carried is None:
			carried = pair_reason

		# A 256-bit store of a register a VEX.128 zeroing idiom emptied.
		# Both halves are zero, so it is two 128-bit stores of the same
		# register -- and unlike the copy it is one instruction, so it takes
		# the ordinary path below and may widen its window like any other.
		if vex["L"] and mnemonic in YMM_MOVES:
			fields = inplace.split_operands(operands)
			if (len(fields) == 2 and fields[0].startswith("%ymm")
					and "(" in fields[1]):
				if zeroed_ymm(instructions, index, fields[0], blocked,
				              sources=sources):
					if lower_ymm_zero_store(vex, encoding[vex["length"]:],
					                        address, len(encoding),
					                        address) is None:
						told = carried or \
							"ymm store operand cannot be offset"
						skipped[told] += 1
						declined[address] = told
						continue
					# **Consecutive zero stores compete for the same
					# padding**, so take the group as one window before
					# letting any of them widen. See `zero_run`.
					#
					# Only where the site is too short to detour on its own.
					# Grouping every zero store instead cost 1,888 placements
					# for 327 gained: one long window collides with
					# neighbouring candidates that would each have been
					# placed, and 9,468 of these lower perfectly well alone.
					# The overlap count rose by 2,199 and said so.
					found = None
					if len(encoding) < 5:
						found = store_run(
							instructions, index, blocked,
							lambda position, register: zeroed_ymm(
								instructions, position, register, blocked,
								sources=sources))
					if found is not None:
						members, last = found
						tail_entry = instructions[last]
						span = tail_entry[0] + len(tail_entry[1]) - address
						entries = []
						for position in members:
							one = instructions[position]
							one_vex = inplace.decode_vex(one[1])
							entries.append((one_vex,
							                one[1][one_vex["length"]:],
							                one[0], len(one[1])))
						if inplace.covered_by(ranges, address, span) \
								and lower_zero_run(entries, address) is not None:
							candidates.append(
								(address, encoding, operands, mnemonic, span,
								 [], None, [], ("zerorun", entries)))
							continue
					strategy = ("zero", None)
				elif address in long_shadow:
					# The load's own stub reserved a register and wrote the
					# upper half into it. Only a load that COMMITTED to the
					# long pair puts an entry here, so the two ends cannot
					# disagree: the listing is walked in address order and
					# the load is always reached first. Finding 104.
					#
					# **That guarded one direction only.** It rules out a
					# store with no load; it said nothing about a load whose
					# store then declines, and the refusal below was reached
					# 24 times with the load already committed -- leaving a
					# surviving 256-bit store of a register whose upper half
					# went to a shadow. The load now asks
					# `long_partner_lowers` of every partner before it
					# commits, so reaching the refusal below means the load
					# did not commit. Finding 180.
					tail = encoding[vex["length"]:]
					if len(encoding) >= 5 and inplace.covered_by(
							ranges, address, len(encoding)) \
							and lower_long_half(vex, tail, address,
							                    len(encoding), address,
							                    long_shadow[address]) \
							is not None:
						candidates.append(
							(address, encoding, operands, mnemonic,
							 len(encoding), [], None, [],
							 ("longstore", (vex, tail,
							                long_shadow[address]))))
						continue
					told = carried or "the long pair store would not lower"
					skipped[told] += 1
					declined[address] = told
					continue
				else:
					# **The value may be a constant, and then the store can
					# fetch it for itself.** Nothing is reserved and nothing
					# has to survive the distance: the stub loads both halves
					# from the read-only bytes the register was loaded from,
					# so a call, a loop or a branch target in between costs
					# nothing. See `constant_ymm`.
					constant = constant_ymm(instructions, index, fields[0],
					                        blocked, readonly,
					                        sources=sources)
					if constant is None:
						told = carried or \
							"ymm value has no known upper half"
						skipped[told] += 1
						declined[address] = told
						continue
					strategy = ("conststore", constant)
					# **Consecutive constant stores compete for the same
					# padding**, and harder than the zero stores of Finding
					# 81 do: the one Starfield stops in is at the head of a
					# loop, so it cannot widen backwards over an instruction
					# that is a branch target's predecessor, and forwards it
					# would have to swallow another 256-bit store, which
					# `moved_instruction` refuses. Grouping is the only way
					# either of them is reached.
					#
					# Only where the site is too short to detour alone, for
					# the reason `store_run`'s caller below gives: one long
					# window collides with neighbours that would each have
					# been placed.
					if len(encoding) < 5:
						group = store_run(
							instructions, index, blocked,
							lambda position, name: constant_ymm(
								instructions, position, name, blocked,
								readonly, sources=sources) is not None)
					else:
						group = None
					if group is not None:
						members, last = group
						tail_entry = instructions[last]
						span = tail_entry[0] + len(tail_entry[1]) - address
						entries = []
						for position in members:
							one = instructions[position]
							one_vex = inplace.decode_vex(one[1])
							entries.append((
								constant_ymm(
									instructions, position,
									wide_move(one[1], one[2], one[3])[1],
									blocked, readonly, sources=sources),
								(one_vex, one[1][one_vex["length"]:], one[0],
								 len(one[1]))))
						if inplace.covered_by(ranges, address, span) \
								and lower_constant_run(entries, address) \
								is not None:
							candidates.append(
								(address, encoding, operands, mnemonic, span,
								 [], None, [], ("construn", entries)))
							continue
		# There was a `mnemonic not in nds` test here, left over from when
		# this only handled Class C. It quietly excluded every mnemonic
		# that is DIRECT-only -- vcomiss and the rest -- as well as the
		# sequences, long after the code below had learned to handle them.
		needs_sequence = (mnemonic in SEQUENCE_MNEMONICS
		                  or FMA_PATTERN.match(mnemonic) is not None)
		# **A 256-bit site no Y strategy claimed cannot be lowered at all**,
		# and the collector has to say so rather than accept it and let the
		# stub fail. The test below asks whether the MNEMONIC has an SSE
		# form, which for `vmulps` and its kind it does; `sse_encoding`
		# refuses the ENCODING later, because VEX.L has none, and the site
		# lands in "stub not buildable" with 2,653 others reading as an
		# encoding bug worth chasing. It is the register model they want.
		#
		# The sequence and FMA mnemonics are excluded: those do not go
		# through `sse_encoding` at all, and refusing them here would decline
		# sites their own lowerings might yet take. Finding 90.
		if vex["L"] and strategy is None and not needs_sequence \
				and len(encoding) >= 5:
			partners = long_pair_stores(instructions, index, blocked,
			                            ranges[bisect.bisect_right(
			                                [r[0] for r in ranges], address)
			                                - 1][1] if ranges else 0)
			if partners is not None:
				own = scratch_finder.xmm_numbers(operands)
				free = free_across(plain, positions, index, partners[-1], own)
				tail = encoding[vex["length"]:]
				if free and inplace.covered_by(ranges, address,
				                               len(encoding)):
					shadow = min(free)
					# **Every partner, or none.** The comment on the store
					# side said the two ends cannot disagree because the
					# load is reached first -- which guards a store with no
					# load, and not a load whose store then declines. That
					# second case shipped 24 stale upper halves.
					# **And nothing may read the upper half afterwards.**
					# This path asked the question of no one: the load puts
					# the upper half in a SHADOW register, so a surviving
					# 256-bit read of the ymm itself takes sixteen stale
					# bytes. 56 sites shipped that way -- at `0x140470003`
					# the `pair` strategy refuses the very same site for
					# exactly this reason, because `vextractf128
					# $0x1,%ymm0,%xmm0` five bytes later reads it, and the
					# long pair took it without asking. The fourth strategy
					# to need the guard the other five have. Finding 185.
					held = inplace.split_operands(operands)[-1]
					if lower_long_half(vex, tail, address, len(encoding),
					                   address, shadow) is not None \
							and all(long_partner_lowers(instructions, one,
							                            ranges, shadow)
							        for one in partners) \
							and not upper_half_read_later(
								instructions, partners[-1], held,
								positions=positions):
						for partner in partners:
							long_shadow[instructions[partner][0]] = shadow
						candidates.append(
							(address, encoding, operands, mnemonic,
							 len(encoding), [], None, [],
							 ("longload", (vex, tail, shadow))))
						continue
		# The other end of the constant: a 256-bit load of read-only memory,
		# lowered to its low half alone and nothing else. The upper half is
		# left stale deliberately, which is only safe where every later read
		# of it is a store that will fetch the bytes again for itself -- so
		# the walk below asks exactly that, through the same `constant_ymm`
		# those stores are accepted by. One decision, asked from both ends.
		#
		# It is tried after the run rather than before it, and the order is
		# not arbitrary: a run lowers everything between its halves into the
		# one stub, where this leaves each store to detour on its own account.
		# Where both would work the run is worth more.
		if vex["L"] and strategy is None and mnemonic in YMM_MOVES:
			held = constant_load(instructions[index], readonly)
			if held is not None:
				if upper_half_read_later(
						instructions, index,
						wide_move(encoding, mnemonic, operands)[1],
						positions=positions,
						covered=lambda position: constant_reload(
							instructions, position, blocked, readonly,
							sources, held)):
					# Ahead of whatever the run said, by `held_back`'s rule:
					# this strategy is the cheaper one -- it reserves no
					# register and spans nothing -- so its refusal names the
					# property of the code rather than the register pressure.
					y_reason.insert(0, "256-bit: the constant is read by "
					                   "something that will not reload it")
				else:
					strategy = ("constload", held)

		# **The region in its last position**, which `--region-place=last`
		# selects: below the zero store, the zero run, the long halves and
		# the constants, with nothing under it but the refusal. Every
		# strategy that Finding 169 timed as cheaper than a region has had
		# its turn before this line is reached.
		if vex["L"] and strategy is None and REGION_PLACE == REGION_LATE:
			regional = region_candidate(instructions, plain, positions,
			                            index, blocked, home, ranges,
			                            scope, tls_slot_offset)
			if regional is not None:
				candidates.append(regional)
				continue

		# **The unconditional lowering, last of all.** Every strategy
		# above is consumer-driven and has had its turn; what reaches
		# here is a site whose upper half no walk could account for,
		# which is exactly the population the uniform representation
		# exists to take. Offered only under `--shadow-regs=all`, and
		# refusing there is a hole in the invariant rather than a miss.
		# Finding 246.
		if vex["L"] and strategy is None:
			lone = unit_shortening(instructions, plain, index, blocked,
			                       home, ranges, scope, tls_slot_offset)
			if lone is not None:
				candidates.append(lone)
				continue

		if vex["L"] and strategy is None and not needs_sequence:
			# The reason comes from `ymm_run` itself rather than from a
			# second walk beside it: two code paths answering one question
			# is how a collector and an encoder come to disagree.
			told = carried or (y_reason[0] if y_reason
			                   else "256-bit, no Y strategy took it")
			skipped[told] += 1
			declined[address] = told
			continue
		if not inplace.has_direct_sse_form(mnemonic) and not needs_sequence:
			skipped["no direct SSE form"] += 1
			declined[address] = "no direct SSE form"
			continue
		fields = inplace.split_operands(operands)
		registers = [o for o in fields if not o.startswith("$")]
		# One operand is `vldmxcsr` and `vstmxcsr` and nothing else here; the
		# in-place classifier takes those now, so this only matters for one
		# that could not be patched where it stood. Finding 110.
		if not needs_sequence and len(registers) not in (1, 2, 3):
			skipped["operand shape not A/B/C"] += 1
			declined[address] = "operand shape not A/B/C"
			continue

		# A sequence may need somewhere to put an intermediate. Ask the
		# liveness scan; a site with no dead register is left alone rather
		# than spilled, because a stub that moves rsp breaks stack walking
		# (see tool/scratch.py).
		# A Class C site whose src2 IS the destination needs one too, for the
		# reason spelled out in lower_vex: the movaps that sets up the
		# destination would destroy src2 first.
		#
		# This used to exclude DESTINATION_IN_VVVV wholesale, which is the
		# same mis-keying Finding 311 fixed one branch above: that set holds
		# MNEMONICS, and the shift group's variable-count encoding is an
		# ordinary three-operand instruction that can alias like any other.
		# The `len(registers) == 3` test already separates the two encodings
		# -- the immediate form renders two registers and an immediate -- so
		# the exclusion only ever suppressed a scratch request the variable
		# form was entitled to make. lower_vex refuses without one, so the
		# cost was a lost site rather than a wrong lowering; Starfield has
		# none, and the `varshift` fixture carries the case so the empty cell
		# is asserted rather than assumed.
		aliased = (not needs_sequence
		           and len(registers) == 3
		           and registers[-1] != registers[-2]
		           and registers[0] == registers[-1])
		scratch = None
		if needs_sequence or aliased:
			scratch = scratch_finder.find_scratch(plain, index, scope=scope)
			trial = lower_vex(address, encoding, operands, mnemonic,
			                  address, scratch, address)
			if trial is None and SPILL != SPILL_NONE:
				# No register is dead here, so borrow one that is live and
				# give it back. Which backing store the save uses is the
				# whole of the question Finding 46 measures -- and the home
				# space is the one that has to ask permission, because it
				# belongs to the function rather than to the rewriter.
				#
				# **Ask whether ANY register lowers it before asking where
				# to save one.** The home-space test used to come first and
				# short-circuit, so a site no register could ever lower was
				# declined `no home space to borrow` -- a register-pressure
				# label on a 256-bit ISA bound. 290 sites wore one:
				# `vbroadcastss %xmm,%ymm`, `vpbroadcastd`, `vfmadd213ps`
				# and friends, which have no SSE form at any of the sixteen
				# registers, sitting inside the bucket that five increments
				# of backing-store work were aimed at. The decline set is
				# unchanged; only the reason is now true. Finding 178.
				borrowed = borrow_that_lowers(address, encoding, operands,
				                              mnemonic, address, address)
				if borrowed is None:
					reason = ("aliased, and no SSE form at any register"
					          if aliased
					          else "no SSE form at any register")
					skipped[reason] += 1
					declined[address] = reason
					continue
				if SPILL in HOME_SPILLS \
						and borrow_offset(home, address) is None:
					# **The home space first, always.** It needs no
					# register to address and no directory raised, so
					# `--spill=tls` differs from `--spill=home` only where
					# the home space said no. Two registers, because the
					# addressing needs two and one is worth nothing to it.
					# **Under `tls` the stack is the fallback, so this no
					# longer declines.** `build_stub` allocates sixteen
					# bytes and spills there when neither the home space nor
					# a TLS pair is available, which is the same emission
					# `--spill=stack` uses. A site the emitter still cannot
					# take is refused there with its own reason, as every
					# other stub failure is -- the decline here existed to
					# save the attempt, and the attempt is now worth making.
					# Finding 204.
					if SPILL != SPILL_TLS or FALLBACK_RULE == FALLBACK_OFF:
						skipped["no home space to borrow"] += 1
						declined[address] = "no home space to borrow"
						continue
				strategy = ("spill", borrowed)
				trial = True
			if trial is None:
				if aliased:
					skipped["src2 aliases dst, no scratch"] += 1
					declined[address] = "src2 aliases dst, no scratch"
				else:
					reason = ("sequence with no usable scratch"
					          if scratch is None
					          else "sequence shape not handled")
					skipped[reason] += 1
					declined[address] = reason
				continue
		displaced = []
		preceding = []
		start = address
		window = len(encoding)

		if window < 5:
			# Too short for a jump on its own, so the window has to widen
			# over a neighbour. Which neighbour decides which address ends
			# up in the middle of the window, and the one in the middle is
			# the one nothing may branch to.
			reason = None
			ahead_told = behind_told = None
			if index + 1 >= len(instructions):
				reason = "nothing follows"
			else:
				nxt_address, nxt_encoding, nxt_mnemonic, nxt_operands, \
					nxt_comment = instructions[index + 1]
				if nxt_address != address + window:
					reason = "next instruction not adjacent"
				elif nxt_address in blocked:
					reason = "next instruction is a branch target"
				elif nxt_mnemonic.startswith(CONTROL_PREFIXES) \
						and not swallowable_transfer(
							nxt_encoding, nxt_mnemonic, nxt_operands,
							nxt_comment, nxt_address):
					reason = "next instruction transfers control"
				elif window + len(nxt_encoding) < 5:
					reason = "still too short"
				else:
					taken = swallowed_scratch(
						plain, index + 1, nxt_address, nxt_encoding,
						nxt_operands, nxt_mnemonic, scope)
					borrow = None
					if taken is None:
						borrow = swallowed_borrow(
							plain, nxt_address, nxt_encoding, nxt_operands,
							nxt_mnemonic, home)
					passenger = (nxt_address, nxt_encoding, nxt_comment,
					             nxt_operands, nxt_mnemonic,
					             taken if borrow is None else borrow,
					             borrow is not None)
					# **Ask whether the passenger lowers before committing
					# to it.** This appended unconditionally -- even where
					# `swallowed_scratch` AND `swallowed_borrow` both
					# returned nothing -- and left `reason` unset, so the
					# window was taken, backward widening was never tried,
					# and `build_stub` refused the whole thing later. 549
					# of the 595 stub refusals were the SWALLOWED NEIGHBOUR
					# refusing rather than the site: an instruction that
					# lowers perfectly well on its own account does not
					# lower as a passenger, and nobody asked. At
					# `0x1402add0a` the passenger is a `vpor` whose src2
					# aliases its destination -- and that same `vpor` is
					# separately placed as its own candidate with a `spill`
					# strategy. Finding 176.
					#
					# Asked at the site's own address, which is the
					# convention `lower_ymm_run` already uses here: the
					# displacement correction is smallest there, so this
					# errs toward accepting and never refuses a passenger
					# that a real stub address would have taken.
					told = Counter()
					if moved_instruction(passenger, address, address,
					                     reasons=told) is None:
						# **Held, not counted.** Forward widening is
						# attempted at EVERY short site and most of
						# those go on to succeed backward, so counting
						# here described attempts while the backward
						# counter described outcomes -- 647 against
						# 118, two denominators under one heading.
						# Folded in at the decline below, where both
						# halves are about the same sites. Caught by
						# the backward half reconciling to the unit
						# and the forward half not. Finding 299.
						ahead_told = told
						reason = "next instruction will not move"
					else:
						displaced.append(passenger)
						window += len(nxt_encoding)

			if reason is not None:
				# **Backwards instead.** Forward widening leaves the window
				# starting where the site already starts and swallows the
				# next instruction, so that instruction is the one that must
				# be unreachable. Putting the window's first byte on the
				# PREVIOUS instruction swallows the site itself instead --
				# and the site is frequently unreachable where its
				# successor is not, because a compiler branches to the top
				# of a block rather than into the middle of one.
				#
				# The previous instruction still has to fall through to
				# here, so anything that transfers control rules it out: a
				# call returns to the site, which would be a return into the
				# middle of a window.
				#
				# Worth 3,237 sites that forward widening cannot reach,
				# measured before it was written.
				#
				# **Each `no` is named, because the reason this site
				# ends up declined under is the FORWARD one.** Every
				# branch here used to be a bare `pass`, so a site that
				# failed forward for one cause and backward for a
				# quite different one was filed under the first, and
				# the operative half was never recorded anywhere.
				# Measured before this: 228 sites read `next
				# instruction is a branch target` and 106 read `next
				# instruction will not move`, and neither string says
				# why the fallback that exists for exactly those cases
				# did not fire. Finding 299.
				previous = instructions[index - 1] if index else None
				back = None
				if previous is None:
					back = "nothing precedes"
				elif previous[0] + len(previous[1]) != address:
					back = "previous not adjacent"
				elif address in blocked:
					back = "the site itself is a branch target"
				elif previous[2].startswith(CONTROL_PREFIXES) \
						and not swallowable_transfer(
							previous[1], previous[2], previous[3],
							previous[4], previous[0]):
					back = "previous does not fall through"
				elif len(previous[1]) + len(encoding) < 5:
					back = "the pair is still too short"
				else:
					taken = swallowed_scratch(
						plain, index - 1, previous[0], previous[1],
						previous[3], previous[2], scope)
					borrow = None
					if taken is None:
						borrow = swallowed_borrow(
							plain, previous[0], previous[1], previous[3],
							previous[2], home)
					passenger = (previous[0], previous[1], previous[4],
					             previous[3], previous[2],
					             taken if borrow is None else borrow,
					             borrow is not None)
					# Same question backwards, and here a `no` must LEAVE
					# `reason` set: this is the fallback, so a passenger
					# that will not move means the site is declined with a
					# reason rather than given a window whose stub cannot
					# be built.
					told = Counter()
					if moved_instruction(passenger, previous[0],
					                     previous[0],
					                     reasons=told) is not None:
						preceding.append(passenger)
						start = previous[0]
						window = len(previous[1]) + len(encoding)
						reason = None
					else:
						behind_told = told
						back = "previous will not move"

			if reason is not None:
				skipped[reason] += 1
				declined[address] = reason
				BACKWARD_REFUSED[(reason, back or "?")] += 1
				for way, seen in (("forward", ahead_told),
				                  ("backward", behind_told)):
					if seen is None:
						continue
					WIDEN_SITES[way] += 1
					for why, count in seen.items():
						WIDEN_REFUSED[(way, why)] += count
					if not seen:
						WIDEN_REFUSED[(way, "no reason given")] += 1
				continue

		if not inplace.covered_by(ranges, start, window):
			skipped["outside .pdata"] += 1
			declined[address] = "outside .pdata"
			continue
		candidates.append((start, encoding, operands, mnemonic, window,
		                   displaced, scratch, preceding, strategy))
	return patches, candidates, stats, skipped, declined, home


EXCEPTION_DIRECTORY = 3			# index into the data directory
UNW_FLAG_CHAININFO = 4
UWOP_ALLOC_SMALL = 2
PDATA_NAME = b".avxpdat"
XDATA_NAME = b".avxxdat"
# INITIALIZED_DATA | READ.
UNWIND_FLAGS = 0x40000040


def sections_of(data):
	"""(vaddr, vsize, raddr, rsize) for every section, in table order.

	The header stores VirtualSize BEFORE VirtualAddress, which is the
	opposite of how they are useful and exactly the transposition that made
	the first version of this read an empty function table.
	"""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	count = struct.unpack_from("<H", data, pe + 6)[0]
	opt_size = struct.unpack_from("<H", data, pe + 20)[0]
	table = pe + 24 + opt_size
	out = []
	for i in range(count):
		vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data,
		                                               table + i * 40 + 8)
		out.append((vaddr, vsize, raddr, rsize))
	return out


def section_named(data, name):
	"""(vaddr, vsize, raddr, rsize) for a section, by name, or None."""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	count = struct.unpack_from("<H", data, pe + 6)[0]
	table = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
	for i in range(count):
		off = table + i * 40
		if data[off:off + 8].rstrip(b"\0") == name.rstrip(b"\0"):
			return sections_of(data)[i]
	return None


# A section the loader maps without IMAGE_SCN_MEM_WRITE cannot change under
# a running program, which is the whole premise of `constant_ymm`. The second
# flag is here because a section with no bytes in the file has nothing to
# reload: .bss is read from nowhere and is writable anyway, but the pair is
# what "the bytes are fixed and they are there" means.
SECTION_WRITABLE = 0x80000000
SECTION_UNINITIALISED = 0x00000080


def readonly_ranges(data):
	"""(start, end) for every section whose bytes cannot change, absolute.

	Decided on the section characteristics rather than on the name. `.rdata`
	is the one this is for and `.text` qualifies too, but the loader goes by
	the flag and so does this -- a binary that puts its constants somewhere
	else is not a case to guess at.
	"""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	count = struct.unpack_from("<H", data, pe + 6)[0]
	opt = pe + 24
	base = struct.unpack_from("<Q", data, opt + 24)[0]
	table = opt + struct.unpack_from("<H", data, pe + 20)[0]
	out = []
	for i in range(count):
		off = table + i * 40
		vsize, vaddr, rsize, _raddr = struct.unpack_from("<IIII", data,
		                                                off + 8)
		flags = struct.unpack_from("<I", data, off + 36)[0]
		if flags & (SECTION_WRITABLE | SECTION_UNINITIALISED) or not rsize:
			continue
		out.append((base + vaddr, base + vaddr + (vsize or rsize)))
	return sorted(out)


def inside_readonly(ranges, start, size):
	"""True if all `size` bytes from `start` lie in one unchanging range."""
	return any(low <= start and start + size <= high for low, high in ranges)


def rva_to_offset(data, rva):
	"""Where an RVA's bytes live in the file, or None if nowhere."""
	for vaddr, vsize, raddr, rsize in sections_of(data):
		if raddr and vaddr <= rva < vaddr + max(vsize, rsize):
			at = raddr + (rva - vaddr)
			return at if at < len(data) else None
	return None


def existing_pdata(data):
	"""Sorted (begin, end, unwind) for every RUNTIME_FUNCTION in the image.

	Read through the exception directory rather than by section name,
	because that is what the loader reads and what this replaces.
	"""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	rva, size = struct.unpack_from("<II", data,
	                               pe + 24 + 112 + EXCEPTION_DIRECTORY * 8)
	at = rva_to_offset(data, rva) if rva and size else None
	if at is None:
		return []
	out = []
	for i in range(size // 12):
		begin, end, unwind = struct.unpack_from("<III", data, at + i * 12)
		if end > begin:
			out.append((begin, end, unwind))
	out.sort()
	return out


def stub_unwind(extents, prologues, image_base, existing, xdata_rva):
	"""Unwind data for every stub. Returns (xdata bytes, pdata bytes).

	**A stub is a piece of the function it was cut out of, not a function.**
	So its `UNWIND_INFO` carries `UNW_FLAG_CHAININFO` and ends with the
	primary's own `RUNTIME_FUNCTION`, which is what tells the unwinder to
	compute the frame from that function's prologue. Without it the stub has
	no entry at all, the unwinder assumes a leaf, and reads a return address
	out of `[rsp]` that was never one -- measured, and it is why an exception
	raised inside a stub is never dispatched (Finding 46).

	Stubs in the same function share one block, since the chain is all a
	block holds. On Starfield that is the difference between 3.1 MB of
	`.xdata` and a few hundred kilobytes.

	A stub whose site sits in a range `.pdata` does not describe gets a plain
	empty `UNWIND_INFO` instead of a chain. That is not a fallback: the x64
	ABI lets a function omit unwind data only when it is a leaf that neither
	moves `rsp` nor calls anything, so for those the unwinder's leaf
	assumption is exactly right and `[rsp]` really is the return address.

	Where the stub spilled, the block also carries a `UWOP_ALLOC_SMALL` at
	the offset the `sub` ends, so the sixteen bytes are described rather than
	silently missing.
	"""
	starts = [begin for begin, _e, _u in existing]
	blocks, xdata, pdata = {}, bytearray(), []
	for (stub_rva, stub_end, site_rva), prologue in zip(extents, prologues):
		position = bisect.bisect_right(starts, site_rva) - 1
		primary = None
		if position >= 0 and site_rva < existing[position][1]:
			primary = existing[position]
		key = (primary, prologue)
		offset = blocks.get(key)
		if offset is None:
			offset = len(xdata)
			blocks[key] = offset
			codes = bytearray()
			if prologue:
				# UWOP_ALLOC_SMALL encodes size = info * 8 + 8, so sixteen
				# bytes is info 1. The offset is the END of the instruction
				# that did it, which is what makes the allocation apply only
				# to the part of the stub that is past it.
				codes += struct.pack("<BB", prologue,
				                     UWOP_ALLOC_SMALL | (1 << 4))
			count = len(codes) // 2
			flags = UNW_FLAG_CHAININFO if primary is not None else 0
			xdata += struct.pack("<BBBB", 1 | (flags << 3), prologue, count, 0)
			xdata += codes
			if count & 1:
				xdata += b"\0\0"	# the code array is padded to an even count
			if primary is not None:
				xdata += struct.pack("<III", *primary)
		pdata.append((stub_rva, stub_end, xdata_rva + offset))
	merged = sorted(existing + pdata)
	out = bytearray()
	for entry in merged:
		out += struct.pack("<III", *entry)
	return bytes(xdata), bytes(out)


def header_problems(data):
	"""Everything wrong with this PE's headers, as a list of strings.

	Three sections are appended and a data directory repointed, and until
	now nothing checked the result was still a loadable image. `add_section`
	writes `SizeOfImage` and refuses when the header has no room for another
	entry, but writing a field is not the same as the field being right, and
	the only evidence was that wine loads the small PEs -- which have three
	sections where Starfield has ten, and a header with room to spare.

	Cheap, and it is the one check that would catch a malformed image
	before a loader does.
	"""
	out = []
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	count = struct.unpack_from("<H", data, pe + 6)[0]
	opt_size = struct.unpack_from("<H", data, pe + 20)[0]
	opt = pe + 24
	alignment = struct.unpack_from("<I", data, opt + 32)[0]
	file_alignment = struct.unpack_from("<I", data, opt + 36)[0]
	image_size = struct.unpack_from("<I", data, opt + 56)[0]
	headers_size = struct.unpack_from("<I", data, opt + 60)[0]
	entry = struct.unpack_from("<I", data, opt + 16)[0]
	table = opt + opt_size
	if table + count * 40 > headers_size:
		out.append(f"the section table ends past SizeOfHeaders "
		           f"({table + count * 40:#x} > {headers_size:#x})")

	sections, highest = [], 0
	for i in range(count):
		off = table + i * 40
		name = data[off:off + 8].rstrip(b"\0").decode("latin-1", "replace")
		vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off + 8)
		sections.append((vaddr, vsize, raddr, rsize, name))
		if raddr and raddr + rsize > len(data):
			out.append(f"{name}: raw data runs past the end of the file")
		if vaddr % alignment:
			out.append(f"{name}: virtual address is not section-aligned")
		if raddr % file_alignment:
			out.append(f"{name}: raw pointer is not file-aligned")
		highest = max(highest, vaddr + vsize)

	ordered = sorted(sections)
	if ordered != sections:
		out.append("sections are not in ascending virtual-address order")
	for (va, vs, _r, _s, name), (nva, _nvs, _nr, _ns, nxt) in zip(ordered,
	                                                              ordered[1:]):
		if va + vs > nva:
			out.append(f"{name} overlaps {nxt} in virtual space")
	if image_size < highest:
		out.append(f"SizeOfImage {image_size:#x} does not cover the highest "
		           f"section end {highest:#x}")

	def inside(rva):
		return any(va <= rva < va + max(vs, rs)
		           for va, vs, _r, rs, _n in sections)

	if entry and not inside(entry):
		out.append("the entry point is not inside any section")
	for i in range(struct.unpack_from("<I", data, opt + 108)[0]):
		rva, size = struct.unpack_from("<II", data, opt + 112 + i * 8)
		if rva and size and not inside(rva):
			out.append(f"data directory {i} points outside every section")
	return out


def next_section_rva(data):
	"""Where `add_section` would put the next one."""
	alignment = struct.unpack_from(
		"<I", data, struct.unpack_from("<I", data, 0x3C)[0] + 24 + 32)[0]
	highest = 0
	for vaddr, vsize, _raddr, _rsize in sections_of(data):
		highest = max(highest, vaddr + vsize)
	return (highest + alignment - 1) // alignment * alignment


# Data directory 9 of a PE32+ optional header, which begins at 112.
TLS_DIRECTORY = 9
# IMAGE_TLS_DIRECTORY64: two VAs bounding the template, the VA of the index
# the loader writes, the VA of the callback list, then the zero fill and the
# characteristics.
TLS_FIELDS = "<QQQQII"


def tls_directory(data):
	"""`(file offset of the directory, fields)` or None if there is no TLS.

	The directory is addressed by RVA and lives in some section's raw data,
	so finding it is the same walk `sections_of` does for everything else.
	A binary with no TLS directory has no index for the loader to write and
	nowhere to put a slot, and `--spill=tls` is simply unavailable there.
	"""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	opt = pe + 24
	count = struct.unpack_from("<I", data, opt + 108)[0]
	if count <= TLS_DIRECTORY:
		return None
	rva, size = struct.unpack_from("<II", data,
	                               opt + 112 + TLS_DIRECTORY * 8)
	if not rva or size < struct.calcsize(TLS_FIELDS):
		return None
	for vaddr, vsize, raddr, _rsize in sections_of(data):
		if vaddr <= rva < vaddr + vsize:
			offset = raddr + (rva - vaddr)
			return offset, struct.unpack_from(TLS_FIELDS, data, offset)
	return None


def tls_directory_span(data):
	"""`(first VA, last VA + 1)` of the TLS directory, or None.

	**Data inside `.text` that this rewrite deliberately edits.** `verify`
	compares instruction boundaries before and after, and a linear sweep
	decodes the directory's bytes as instructions like anything else -- so
	raising `SizeOfZeroFill`, which `verify` sanctions two checks earlier,
	re-synchronises the sweep and three boundaries that were never
	instructions vanish. Two of the 35 PE fixtures put their TLS directory
	in `.text` and both failed on it. Finding 196.
	"""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	opt = pe + 24
	count = struct.unpack_from("<I", data, opt + 108)[0]
	if count <= TLS_DIRECTORY:
		return None
	rva, size = struct.unpack_from("<II", data, opt + 112 + TLS_DIRECTORY * 8)
	if not rva or size < struct.calcsize(TLS_FIELDS):
		return None
	base = struct.unpack_from("<Q", data, opt + 24)[0]
	return base + rva, base + rva + struct.calcsize(TLS_FIELDS)


def tls_slot(data, want=SLOT):
	"""Where a borrowed register may be saved, per thread.

	Returns `(index VA, offset of the slot in the block, new zero fill)` or
	None. The slot sits past the module's own template, at the alignment the
	directory asks for, and `SizeOfZeroFill` is raised to cover it.

	**This is the whole of the file-format half, and `make check-tls` is
	what says the loader honours it** -- the directory asks for the bytes,
	the loader allocates and zeroes them per thread, and Finding 138 swept
	the field to prove the answer depends on its value rather than on the
	template being copied. Nothing here is remembered from a manual.
	"""
	found = tls_directory(data)
	if found is None:
		return None
	_offset, fields = found
	start, end, index_va, _callbacks, zero_fill, characteristics = fields
	if not index_va or end < start:
		return None
	# IMAGE_SCN_ALIGN_* lives in bits 20-23 and encodes 2^(n-1) bytes.
	shift = (characteristics >> 20) & 0xF
	alignment = 1 << (shift - 1) if shift else 1
	# Recorded for `slot_arithmetic_safe`, because this is the only place the
	# field is read and an emitter cannot see the image.
	global TLS_BLOCK_ALIGNMENT
	TLS_BLOCK_ALIGNMENT = alignment
	template = end - start
	slot = (template + alignment - 1) // alignment * alignment
	return index_va, slot, max(zero_fill, slot - template + want)


def set_tls_zero_fill(data, zero_fill):
	"""Raise `SizeOfZeroFill` so the loader gives every thread the slot."""
	found = tls_directory(data)
	if found is None:
		raise SystemExit("no TLS directory to raise")
	offset, fields = found
	if fields[4] >= zero_fill:
		return bytes(data)
	image = bytearray(data)
	struct.pack_into("<I", image, offset + 32, zero_fill)
	return bytes(image)


def add_section(data, name, payload, flags):
	"""Append a section to a PE image. Returns (new image, virtual address)."""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	sections = struct.unpack_from("<H", data, pe + 6)[0]
	opt_size = struct.unpack_from("<H", data, pe + 20)[0]
	opt = pe + 24
	alignment = struct.unpack_from("<I", data, opt + 32)[0]
	file_alignment = struct.unpack_from("<I", data, opt + 36)[0]
	headers_size = struct.unpack_from("<I", data, opt + 60)[0]
	table = opt + opt_size
	end_of_table = table + sections * 40
	if end_of_table + 40 > headers_size:
		raise SystemExit("no room in the header for another section entry")

	highest_va = highest_raw = 0
	for i in range(sections):
		off = table + i * 40
		vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off + 8)
		highest_va = max(highest_va, vaddr + vsize)
		highest_raw = max(highest_raw, raddr + rsize)

	def align(value, to):
		return (value + to - 1) // to * to

	vaddr = align(highest_va, alignment)
	raddr = align(max(highest_raw, len(data)), file_alignment)
	raw = payload + b"\0" * (align(len(payload), file_alignment) - len(payload))

	image = bytearray(data)
	image.extend(b"\0" * (raddr - len(image)))
	image.extend(raw)

	struct.pack_into("<8s", image, end_of_table, name)
	struct.pack_into("<IIII", image, end_of_table + 8,
	                 len(payload), vaddr, len(raw), raddr)
	# PointerToRelocations, PointerToLinenumbers, NumberOfRelocations,
	# NumberOfLinenumbers, Characteristics. The entry is 40 bytes and
	# Characteristics is the last four: one field too many here writes it
	# past the end and leaves the section unmarked as code.
	struct.pack_into("<IIHHI", image, end_of_table + 24, 0, 0, 0, 0, flags)
	struct.pack_into("<H", image, pe + 6, sections + 1)
	struct.pack_into("<I", image, opt + 56, align(vaddr + len(payload), alignment))
	return bytes(image), vaddr


# Enough of the operand shapes to exercise every path: commutative and not,
# scalar and packed, float and integer, with an immediate and without. Each
# is written with src2 AND the destination as %xmm2, which is the aliasing
# case, plus the two shapes it must not disturb.
SELFTEST = [
	"vsubss %xmm2,%xmm1,%xmm2",	"vsubps %xmm2,%xmm1,%xmm2",
	"vdivss %xmm2,%xmm1,%xmm2",	"vdivps %xmm2,%xmm1,%xmm2",
	"vmulss %xmm2,%xmm1,%xmm2",	"vaddps %xmm2,%xmm1,%xmm2",
	"vmaxss %xmm2,%xmm1,%xmm2",	"vminss %xmm2,%xmm1,%xmm2",
	"vandps %xmm2,%xmm1,%xmm2",	"vxorps %xmm2,%xmm1,%xmm2",
	"vpand %xmm2,%xmm1,%xmm2",	"vpor %xmm2,%xmm1,%xmm2",
	"vunpcklps %xmm2,%xmm1,%xmm2",	"vsubsd %xmm2,%xmm1,%xmm2",
	"vshufps $0x1b,%xmm2,%xmm1,%xmm2",
	"vsubss %xmm3,%xmm1,%xmm2",	# plain Class C, must be unaffected
	"vsubss %xmm3,%xmm2,%xmm2",	# Class B, must stay a single instruction
	"vsubss %xmm9,%xmm1,%xmm9",	# aliasing, and needs REX
]

REGISTER = re.compile(r"%xmm(\d+)")


def selftest():
	"""Prove no lowering reads a register it has already overwritten.

	The condition is one sentence and it covers every class: **at the final
	operation, the reg operand must still hold the original src1 and the rm
	operand the original src2.** Class A and B satisfy it by emitting nothing
	first; Class C has to satisfy it while inserting a movaps, and the
	aliasing case has to satisfy it while inserting two.

	Checking it needs no execution and no AVX machine, which matters because
	this one has neither. Each lowering is disassembled back and the register
	moves are simulated symbolically, so what is tested is the bytes that
	would actually be written rather than a rule table's description of them.
	"""
	import tempfile
	from pathlib import Path

	source = ".text\n" + "".join(f"\t{text}\n" for text in SELFTEST)
	failures = 0
	with tempfile.TemporaryDirectory() as tmp:
		asm, obj, raw = (Path(tmp) / n for n in ("t.s", "t.o", "t.txt"))
		asm.write_text(source)
		done = subprocess.run(["as", "--64", "-o", str(obj), str(asm)],
		                      capture_output=True, text=True)
		if done.returncode != 0:
			print(done.stderr.rstrip(), file=sys.stderr)
			return 1
		raw.write_text(subprocess.run(["objdump", "-d", str(obj)],
		                              capture_output=True, text=True).stdout)
		sites = list(inplace.parse_listing(str(raw)))

		for address, encoding, mnemonic, operands in sites:
			registers = [o for o in inplace.split_operands(operands)
			             if not o.startswith("$")]
			source2, source1, destination = (int(REGISTER.search(r).group(1))
			                                 for r in (registers[0],
			                                           registers[-2],
			                                           registers[-1]))
			# 15 is free by construction here; the real allocator asks the
			# liveness scan instead.
			body = lower_vex(address, encoding, operands, mnemonic, 0,
			                 scratch=15)
			if body is None:
				print(f"selftest: {mnemonic} {operands}: refused",
				      file=sys.stderr)
				failures += 1
				continue

			(Path(tmp) / "b.bin").write_bytes(body)
			text = subprocess.run(
				["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
				 "-M", "att", str(Path(tmp) / "b.bin")],
				capture_output=True, text=True).stdout
			steps = []
			for line in text.splitlines():
				parts = line.split("\t")
				if len(parts) < 3:
					continue
				name, _, arguments = parts[2].strip().partition(" ")
				steps.append((name, REGISTER.findall(arguments)))
			if not steps:
				print(f"selftest: {mnemonic}: emitted nothing readable",
				      file=sys.stderr)
				failures += 1
				continue

			state = {n: n for n in range(16)}
			for name, arguments in steps[:-1]:
				if name != "movaps" or len(arguments) != 2:
					print(f"selftest: {mnemonic}: unexpected setup {name}",
					      file=sys.stderr)
					failures += 1
					break
				state[int(arguments[1])] = state[int(arguments[0])]
			name, arguments = steps[-1]
			if len(arguments) < 2:
				continue
			rm, reg = int(arguments[-2]), int(arguments[-1])
			if state[reg] != source1 or state[rm] != source2:
				print(f"selftest: {mnemonic} {operands} -> {name}: reg holds "
				      f"xmm{state[reg]} (want src1 xmm{source1}), rm holds "
				      f"xmm{state[rm]} (want src2 xmm{source2})",
				      file=sys.stderr)
				failures += 1
			elif reg != destination:
				print(f"selftest: {mnemonic}: result lands in xmm{reg}, not "
				      f"xmm{destination}", file=sys.stderr)
				failures += 1

	failures += reach_selftest()
	failures += shadow_selftest()
	failures += reader_selftest()
	failures += span_selftest()
	failures += region_selftest()
	failures += switch_selftest()
	failures += rescue_selftest()
	failures += upper_source_selftest()
	failures += join_selftest()
	failures += loop_selftest()
	failures += conservative_selftest()
	failures += isa_bound_selftest()
	failures += gpr_selftest()
	failures += xmm_selftest()
	failures += tls_selftest()
	failures += borrow_selftest()
	failures += splat_selftest()
	failures += constant_selftest()
	failures += passenger_selftest()
	failures += prefix_selftest()
	failures += extract_selftest()
	failures += spill_slot_selftest()

	if failures:
		# **Not "lowerings".** Every selftest above adds to this counter,
		# so a failure in any of them was reported as a wrong lowering --
		# which sent a reader to `SELFTEST` for a bad case in
		# `REFERENCE_CASES`. The failing case has already printed itself.
		print(f"selftest: {failures} case(s) failed, listed above",
		      file=sys.stderr)
		return 1
	print(f"selftest: {len(SELFTEST)} lowerings, none reads a register it "
	      f"has overwritten")
	return 0


# Each case is (what it is, the body, whether the copy reaches the region).
# The frame is 0x28 throughout, so the region the borrow wants lies at
# entry-0x28 through entry-0x9.
REACH_CASES = [
	("a store the copy does reach",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"),
	  ("mov", "%rcx,-0x28(%rax)")], True),
	("a store eight bytes above the region",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"),
	  ("mov", "%rcx,-0x8(%rax)")], False),
	("the MSVC idiom writing the caller's shadow",
	 [("mov", "%rsp,%rax"), ("mov", "%rcx,0x8(%rax)"), ("push", "%rbx"),
	  ("sub", "$0x20,%rsp"), ("mov", "%rcx,0x10(%rax)")], False),
	("a byte write, which mangles a pointer without destroying it",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("add", "$0x1,%al"),
	  ("mov", "%rcx,(%rax)")], True),
	("a 32-bit write, which zeroes the pointer away",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("xor", "%eax,%eax"),
	  ("mov", "%rcx,(%rax)")], False),
	("a lea deriving a pointer into the region",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"),
	  ("lea", "-0x28(%rax),%rbx"), ("mov", "%rcx,(%rbx)")], True),
	("immediate arithmetic walking a copy into the region",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("sub", "$0x28,%rax"),
	  ("mov", "%rcx,(%rax)")], True),
	# **The pointer's migration, which this walk followed for its
	# arithmetic and not for its moves.** All five of these reached the
	# region and were allowed until Finding 135, and the last two are here
	# so that the fix is not merely "refuse anything that moves".
	("through a register-to-register copy of the copy",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("mov", "%rax,%rbx"),
	  ("mov", "%rcx,-0x28(%rbx)")], True),
	("through a second-hand copy, the first killed after",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("mov", "%rax,%rbx"),
	  ("xor", "%eax,%eax"), ("mov", "%rcx,-0x28(%rbx)")], True),
	("a lea deriving from a second-hand copy",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("mov", "%rax,%rbx"),
	  ("lea", "0x0(%rbx),%rdx"), ("mov", "%rcx,-0x28(%rdx)")], True),
	("adding a tainted register into an untainted one",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("add", "%rax,%rbx"),
	  ("mov", "%rcx,(%rbx)")], True),
	("a second-hand copy dereferenced clear of the region",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("mov", "%rax,%rbx"),
	  ("mov", "%rcx,-0x8(%rbx)")], False),
	("a 32-bit move, which cannot carry a stack pointer at all",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("mov", "%eax,%ebx"),
	  ("mov", "%rcx,-0x28(%rbx)")], False),
	("a copy stored to memory while pointing INTO the region",
	 [("sub", "$0x28,%rsp"), ("mov", "%rsp,%rax"),
	  ("mov", "%rax,0x100(%rsp)")], True),
	("a copy stored to memory from above the region",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"),
	  ("mov", "%rax,0x100(%rsp)")], False),
	("arithmetic that cannot be followed",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("add", "%rdx,%rax"),
	  ("mov", "%rcx,(%rax)")], True),
	# **A pointer whose offset is lost is still a pointer**, and until
	# Finding 136 losing the offset refused the function outright. It is
	# tracked as unlocated instead: any dereference through it is a hazard
	# wherever it points, and anything that overwrites it ends the matter.
	# Measured over a collect, 374 of 2,290 such pointers are overwritten
	# before they are dereferenced and 10 are never used again.
	("arithmetic that cannot be followed, then the register overwritten",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("add", "%rdx,%rax"),
	  ("mov", "%r8,%rax"), ("mov", "%rcx,(%rax)")], False),
	("arithmetic that cannot be followed, and never used again",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("add", "%rdx,%rax"),
	  ("mov", "%r8,%r9")], False),
	("an unlocated pointer pushed, which leaves the text",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("add", "%rdx,%rax"),
	  ("push", "%rax")], True),
	("an unlocated pointer stored to memory",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("add", "%rdx,%rax"),
	  ("mov", "%rax,0x100(%rsp)")], True),
	("a cmov from a tainted register, never dereferenced",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("cmove", "%rax,%rbx"),
	  ("mov", "%r8,%r9")], False),
	("a cmov from a tainted register, then dereferenced",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("cmove", "%rax,%rbx"),
	  ("mov", "%rcx,(%rbx)")], True),
	("an indexed access through the copy",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"),
	  ("mov", "%rcx,(%rax,%rdx,1)")], True),
	# **This case answered True until Finding 127, then False, and the
	# reason has changed under it twice.** Finding 127 allowed it because
	# nothing runs between a borrow's save and its restore, so an escaped
	# pointer cannot be dereferenced while the borrow is live. True, and
	# beside the point: the region keeps the borrowed value afterwards, so
	# the damage outlives the bracket. What holds it now is narrower and
	# checked -- the pointer that leaves does not point into the region,
	# and the two ways one INTO it is formed are refused above. The case
	# below is the same store from a pointer that does. Finding 132.
	("the copy stored to memory, which no longer escapes the argument",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"),
	  ("mov", "%rax,(%rdi)")], False),
	# What did NOT change: where the pointer is stored is a dereference
	# like any other. Storing it THROUGH a copy that lands in the region is
	# still refused, and that is the case the relaxation must not reach.
	("the copy stored through a pointer into the region",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"),
	  ("mov", "%rax,-0x28(%rax)")], True),
	# `cmp` needs BOTH directions: giving up and reaching the region both
	# answer True, so a single case would pass while the walk was aborting.
	("a cmp writes no register, and the copy stays clear of the region",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("cmp", "$0x10,%rax"),
	  ("mov", "%rcx,-0x8(%rax)")], False),
	("a cmp writes no register, and the copy is still tracked after it",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("cmp", "$0x10,%rax"),
	  ("mov", "%rcx,-0x28(%rax)")], True),
	("a test writes no register either, and it is a separate mnemonic",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"), ("test", "%rax,%rax"),
	  ("mov", "%rcx,-0x8(%rax)")], False),
	("a lea overwrites the copy rather than deriving from it",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"),
	  ("lea", "0x10(%rdi),%rax"), ("mov", "%rcx,-0x28(%rax)")], False),
	("an unknown frame",
	 [("mov", "%rsp,%rax"), ("mov", "%rcx,-0x28(%rax)")], True),
]


# `vblendvps %xmm4,%xmm3,%xmm2,%xmm1`, which names four registers and not
# %xmm0. Assembled rather than hand-encoded.
BLENDV = (bytes.fromhex("c4e3694acb40"), "%xmm4,%xmm3,%xmm2,%xmm1",
          "vblendvps")


# A splat and the store that follows it, then the shapes that look like one
# and are not. `$0x0` writes the LOW half and keeps the upper, so treating it
# as a splat would store the wrong sixteen bytes twice -- and this binary
# contains none, so no PE test would ever have exercised it.
SPLAT_STORE = (0, bytes.fromhex("c5fc110500000000"), "vmovups",
               "%ymm0,0x0(%rip)", 0)


def splat_selftest():
	"""Prove `splat_pair` accepts a broadcast and nothing that resembles one.
	"""
	cases = [
		("a genuine splat", "$0x1,%xmm0,%ymm0,%ymm0", True),
		("$0x0 writes the LOW half, keeping the upper",
		 "$0x0,%xmm0,%ymm0,%ymm0", False),
		("the high half from a different register",
		 "$0x1,%xmm3,%ymm0,%ymm0", False),
		("the low half from a different ymm",
		 "$0x1,%xmm0,%ymm2,%ymm0", False),
	]
	failures = 0
	for what, operands, expected in cases:
		site = (0, bytes.fromhex("c4e37d18c001"), "vinsertf128", operands, 0)
		got = splat_pair(site, SPLAT_STORE) is not None
		if got != expected:
			print(f"selftest: {what}: splat_pair said {got}, want {expected}",
			      file=sys.stderr)
			failures += 1
	# and a store of a register the insert did not build
	site = (0, bytes.fromhex("c4e37d18c001"), "vinsertf128",
	        "$0x1,%xmm0,%ymm0,%ymm0", 0)
	other = (0, bytes.fromhex("c5fc110d00000000"), "vmovups",
	         "%ymm1,0x0(%rip)", 0)
	if splat_pair(site, other) is not None:
		print("selftest: a store of another ymm was taken as the splat's",
		      file=sys.stderr)
		failures += 1
	failures += splat_operation_selftest()
	if not failures:
		print(f"selftest: {len(cases) + 1} splat shapes, one accepted and "
		      f"four refused")
	return failures


def splat_operation_selftest():
	"""Prove `splat_operation` takes the triple and nothing resembling it.

	The binary contains nineteen of these and every one is the same shape --
	a lane-wise operation against memory, into a register the splat does not
	name. So the refusals below are shapes no execution test here can reach,
	which is Finding 108's rule and the reason they are unit cases.
	"""
	insert = (0x140001000, bytes.fromhex("c4e36d18d201"), "vinsertf128",
	          "$0x1,%xmm2,%ymm2,%ymm2", 0)
	operation = (0x140001006, bytes.fromhex("c5ec54442440"), "vandps",
	             "0x40(%rsp),%ymm2,%ymm0", 0)
	store = (0x14000100c, bytes.fromhex("c5fc11442460"), "vmovups",
	         "%ymm0,0x60(%rsp)", 0)

	def altered(entry, **fields):
		address, encoding, mnemonic, operands, comment = entry
		return (fields.get("address", address),
		        fields.get("encoding", encoding),
		        fields.get("mnemonic", mnemonic),
		        fields.get("operands", operands), comment)

	cases = [
		("the triple as it occurs", insert, operation, store, True),
		# The destination is the splat: computing the high half destroys the
		# sixteen bytes the low half still needs.
		("the destination aliases the splat", insert,
		 altered(operation, operands="0x40(%rsp),%ymm2,%ymm2"),
		 altered(store, operands="%ymm2,0x60(%rsp)"), False),
		# A second ymm source has an upper half nobody knows.
		("a second register source", insert,
		 altered(operation, operands="%ymm3,%ymm2,%ymm0"), store, False),
		# Horizontal: the upper half of the result depends on both halves.
		("an operation that is not lane-wise", insert,
		 altered(operation, mnemonic="vhaddps"), store, False),
		# The splat feeds it but something else is stored.
		("a store of another register", insert, operation,
		 altered(store, operands="%ymm1,0x60(%rsp)"), False),
		# A gap: something between could be reordered across a half.
		("the operation is not adjacent to the insert", insert,
		 altered(operation, address=0x140001008), store, False),
		("the store is not adjacent to the operation", insert, operation,
		 altered(store, address=0x14000100e), False),
	]
	failures = 0
	for what, one, two, three, expected in cases:
		got = splat_operation(one, two, three) is not None
		if got != expected:
			print(f"selftest: {what}: splat_operation said {got}, "
			      f"want {expected}", file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(cases)} splat-operation shapes, one accepted "
		      f"and {len(cases) - 1} refused")
	return failures


def constant_selftest():
	"""Prove `constant_load` takes bytes that cannot change, and only those.

	Every case here is a shape the real binary either does not contain or
	contains too rarely to reach by running it -- which is exactly the gap
	Finding 108 named. `check-pe` executes the accepted shape twice, in
	`constant` and `constloop`; nothing executes the refusals, so they are
	unit cases or they are untested.
	"""
	readonly = [(0x140002000, 0x140003000)]

	def site(target, encoding, operands, mnemonic="vmovups", at=0x140001000):
		"""One instruction whose RIP displacement lands on `target`."""
		bits = bytes.fromhex(encoding)
		if target is not None:
			bits += struct.pack("<i", target - (at + len(bits) + 4))
		return (at, bits, mnemonic, operands, target)

	cases = [
		("read-only, both halves inside",
		 site(0x140002000, "c5fc1005", "0x0(%rip),%ymm0"), True),
		("the second half is the last sixteen bytes of the range",
		 site(0x140002fe0, "c5fc1005", "0x0(%rip),%ymm0"), True),
		("the second half runs off the end of the range",
		 site(0x140002ff0, "c5fc1005", "0x0(%rip),%ymm0"), False),
		("a section the loader lets the program write",
		 site(0x140004000, "c5fc1005", "0x0(%rip),%ymm0"), False),
		# Not RIP-relative: `vmovups (%rax),%ymm0`. The address is computed
		# at run time, so nothing here can say what is at it.
		("through a register rather than RIP",
		 site(None, "c5fc1000", "(%rax),%ymm0"), False),
		# 128 bits, so it defines the low half and says nothing about the
		# upper one -- which is the half the store needs.
		("128-bit, which is not a definition of the whole register",
		 site(0x140002000, "c5f81005", "0x0(%rip),%xmm0"), False),
		# A store reads the register; it does not decide it.
		("a store of the constant rather than a load of it",
		 site(0x140002000, "c5fc1105", "%ymm0,0x0(%rip)"), False),
	]
	failures = 0
	for what, instruction, expected in cases:
		got = constant_load(instruction, readonly) is not None
		if got != expected:
			print(f"selftest: {what}: constant_load said {got}, "
			      f"want {expected}", file=sys.stderr)
			failures += 1

	# **A `vzeroupper` between the load and the store takes the upper half
	# away, and names nothing while doing it.** The backward walk decides
	# what wrote a register by reading operand text, so without a test on
	# the mnemonic it scans straight past and the store's stub writes the
	# constant's high sixteen bytes where the program wrote zeros.
	#
	# There are none of these in the binary -- measured at zero, of 10,791
	# 256-bit loads and 10,933 zero stores, because MSVC emits `vzeroupper`
	# before a call or a return and the walk stops at either. A shape the
	# input does not contain is one no execution test can reach.
	load = site(0x140002000, "c5fc1005", "0x0(%rip),%ymm3")
	killer = (0x140001008, bytes.fromhex("c5f877"), "vzeroupper", "", None)
	store = (0x140001010, bytes.fromhex("c5fc291f"), "vmovaps",
	         "%ymm3,(%rdi)", None)
	if constant_ymm([load, store], 1, "%ymm3", set(), readonly) is None:
		print("selftest: a plain load and store was refused", file=sys.stderr)
		failures += 1
	if constant_ymm([load, killer, store], 2, "%ymm3", set(),
	                readonly) is not None:
		print("selftest: a vzeroupper between the two was scanned past",
		      file=sys.stderr)
		failures += 1

	# **Two arms, one constant: the case the singular wrapper refused.**
	# `reaching_definition` answers only when the reaching SET holds one
	# position, so a ymm defined on both sides of a branch was declined even
	# where both sides load the identical read-only bytes. This pair is the
	# control for that fix: the first must be accepted and the second must
	# not, and without the second the first proves only that something was
	# returned. Finding 227.
	const, elsewhere = 0x140002000, 0x140002100
	merge = [
		(0x140001000, bytes.fromhex("750a"), "jne", "0x14000100c", None),
		site(const, "c5fc1005", "0x0(%rip),%ymm3", at=0x140001002),
		(0x14000100a, bytes.fromhex("eb08"), "jmp", "0x140001014", None),
		site(const, "c5fc1005", "0x0(%rip),%ymm3", at=0x14000100c),
		(0x140001014, bytes.fromhex("c5fc291f"), "vmovaps", "%ymm3,(%rdi)",
		 None),
	]
	where = {0x14000100c: [0x140001000], 0x140001014: [0x14000100a]}
	stops = {0x14000100c, 0x140001014}
	if constant_ymm(merge, 4, "%ymm3", stops, readonly,
	                sources=where) is None:
		print("selftest: two arms loading ONE constant were refused",
		      file=sys.stderr)
		failures += 1
	apart = list(merge)
	apart[3] = site(elsewhere, "c5fc1005", "0x0(%rip),%ymm3", at=0x14000100c)
	if constant_ymm(apart, 4, "%ymm3", stops, readonly,
	                sources=where) is not None:
		print("selftest: two arms loading DIFFERENT constants were accepted",
		      file=sys.stderr)
		failures += 1

	if not failures:
		accepted = sum(1 for _w, _i, e in cases if e)
		print(f"selftest: {len(cases)} constant shapes, {accepted} accepted "
		      f"and {len(cases) - accepted} refused, and a vzeroupper "
		      f"between the ends is not")
	return failures


def passenger_selftest():
	"""Prove a strategy stub emits the instruction its window swallowed.

	`place_stubs` may hand any stub a `displaced` list -- the Finding 36
	extension grows a window over the next candidate along and retires that
	candidate -- and every strategy branch used to jump home without
	emitting it. The instruction vanished, its boundary was recorded as
	deliberate, and no structural check could see the loss: it is not in the
	stub and it does not survive in `.text` either.

	Measured at zero occurrences on the real binary, so this is the only
	thing standing between the defect and its return. Finding 111.
	"""
	load = bytes.fromhex("c5fc1006")		# vmovups (%rsi),%ymm0
	store = bytes.fromhex("c5fc1107")		# vmovups %ymm0,(%rdi)
	pair = ((inplace.decode_vex(load), load[2:], 0x140001000, len(load)),
	        (inplace.decode_vex(store), store[2:], 0x140001004, len(store)))
	# vmovaps %xmm1,%xmm0, which lowers to movaps %xmm1,%xmm0 -- 0f 28 c1.
	carried = (0x140001008, bytes.fromhex("c5f828c1"), None, "%xmm1,%xmm0",
	           "vmovaps", None)
	body, _prologue = build_stub(
		0x140001000, load, "(%rsi),%ymm0", "vmovups", 12, [carried],
		0x141000000, strategy=("pair", pair))
	if body is None:
		print("selftest: the pair stub with a passenger would not build",
		      file=sys.stderr)
		return 1
	if bytes.fromhex("0f28c1") not in body:
		print("selftest: a strategy stub dropped the instruction its window "
		      "swallowed", file=sys.stderr)
		return 1
	print("selftest: a strategy stub emits the passenger its window took")
	return 0


def prefix_selftest():
	"""Prove `run_prefixes` offers the whole run first and nothing invalid.

	It emits no bytes of its own -- `lower_ymm_run` does that, and the run
	samples in `check-pe` execute it -- so what is worth testing is which
	truncations it is willing to hand back.
	"""
	# load %ymm0 (the anchor, not in members), store it, load %ymm1, store
	# it. Truncating after the first store is valid; truncating between
	# %ymm1's load and its store is not, and neither is a truncation that
	# does not end at a store.
	members = [("store", 1, "%ymm0"), ("load", 2, "%ymm1"),
	           ("plain", 3, None), ("store", 4, "%ymm1")]
	offered = list(run_prefixes("%ymm0", members))
	failures = 0
	if [last for _m, last in offered] != [4, 1]:
		print(f"selftest: run_prefixes offered {[l for _m, l in offered]}, "
		      f"want [4, 1]", file=sys.stderr)
		failures += 1
	if offered and offered[0][0] != members:
		print("selftest: the longest prefix is not the run itself",
		      file=sys.stderr)
		failures += 1
	# A run whose anchor is never stored has no valid prefix at all, which
	# is `ymm_run`'s own condition and must survive truncation.
	if list(run_prefixes("%ymm3", members)):
		print("selftest: a prefix was offered that never stores the anchor",
		      file=sys.stderr)
		failures += 1
	if not failures:
		print("selftest: run_prefixes offers the whole run, then the one "
		      "valid shorter end")
	return failures


def extract_selftest():
	"""Prove `extract_upper` takes only the shape a run can hand a helper to.

	Every one of the 375 register-form extracts in this binary is `$0x1`
	into a register the run does not track, so the refusals below are shapes
	no execution test here can reach.
	"""
	encoding = bytes.fromhex("c4e37d19c201")	# vextractf128 $0x1,%ymm0,%xmm2
	cases = [
		("the shape as it occurs", "$0x1,%ymm0,%xmm2", {"%ymm0"}, "%ymm2"),
		# $0x0 takes the LOW half; handing over the helper would be the
		# wrong sixteen bytes and nothing downstream would look wrong.
		("$0x0, which takes the low half", "$0x0,%ymm0,%xmm2",
		 {"%ymm0"}, None),
		("a source the run does not track", "$0x1,%ymm3,%xmm2",
		 {"%ymm0"}, None),
		# Writing a tracked register's xmm destroys the low half the run
		# still owes a store.
		("the destination is the source", "$0x1,%ymm0,%xmm0",
		 {"%ymm0"}, None),
		("the destination is another tracked register", "$0x1,%ymm0,%xmm1",
		 {"%ymm0", "%ymm1"}, None),
		# The memory form is a store of the upper half; 20 of those here and
		# this rule does not claim them.
		("a memory destination", "$0x1,%ymm0,0x10(%rsp)", {"%ymm0"}, None),
	]
	failures = 0
	for what, operands, tracked, expected in cases:
		got = extract_upper(encoding, "vextractf128", operands, tracked)
		if got != expected:
			print(f"selftest: {what}: extract_upper said {got!r}, "
			      f"want {expected!r}", file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(cases)} extract shapes, one accepted and "
		      f"{len(cases) - 1} refused")
	return failures


def spill_slot_selftest():
	"""Prove two borrowed registers do not share sixteen bytes.

	They did. `encode_spill` emitted `(%rsp)` with no displacement whatever
	the register, so a run borrowing two helpers saved both to the same slot
	and restored both from it -- the first came back holding the second's
	value, and every structural check was clean. Finding 118.
	"""
	failures = 0
	saved = [encode_spill(2, True, 0, 0, slot, 0) for slot in (0, 1)]
	if saved[0] == saved[1]:
		print("selftest: two spill slots encode identically", file=sys.stderr)
		failures += 1
	# mod 01 with a disp8 of 16, base rsp: 0f 11 54 24 10.
	if saved[1] != bytes.fromhex("0f11542410"):
		print(f"selftest: slot 1 encodes {saved[1].hex()}, want 0f11542410",
		      file=sys.stderr)
		failures += 1
	# The restore must address the same bytes as the save it pairs with, so
	# the two encodings differ in the opcode byte and nowhere else.
	for register in (2, 9):
		for slot in (0, 1):
			store = encode_spill(register, True, 0, 0, slot, 0)
			load = encode_spill(register, False, 0, 0, slot, 0)
			apart = sum(1 for a, b in zip(store, load) if a != b)
			if len(store) != len(load) or apart != 1:
				print(f"selftest: xmm{register} slot {slot} restores from a "
				      f"different address ({apart} bytes apart)",
				      file=sys.stderr)
				failures += 1
	# Two slots is what the home space holds; a third would reach past what
	# the ABI reserved, and `build_stub` refuses rather than encoding it.
	if HOME_SPACE // SLOT != 2:
		print(f"selftest: the home space holds {HOME_SPACE // SLOT} slots, "
		      f"and the refusal in build_stub says two", file=sys.stderr)
		failures += 1
	if not failures:
		print("selftest: two borrowed registers get two slots, and a third "
		      "is refused")
	return failures


def borrow_selftest():
	"""Prove the borrow does not offer a register the lowering refuses.

	SSE `blendvps` reads its mask from an implicit `%xmm0`, so `lower_blendv`
	rejects a scratch of 0 -- and 0 is the first register a site not naming
	it leaves free. Offering only that one and giving up refused 600 of this
	binary's `vblendv` instructions with a register they could never use,
	while another would have lowered them. Finding 100.
	"""
	encoding, operands, mnemonic = BLENDV
	registers = [o for o in inplace.split_operands(operands)
	             if not o.startswith("$")]
	failures = 0
	first = spill_register(registers)
	if first != 0:
		print(f"selftest: the first free register is {first}, not 0 -- this "
		      f"case no longer reproduces the bug", file=sys.stderr)
		failures += 1
	if lower_vex(0, encoding, operands, mnemonic, 0, first) is not None:
		print("selftest: blendv accepted %xmm0 as a scratch, which it "
		      "cannot use", file=sys.stderr)
		failures += 1
	taken = borrow_that_lowers(0, encoding, operands, mnemonic, 0)
	if taken is None:
		print("selftest: the borrow found no register for the blendv",
		      file=sys.stderr)
		failures += 1
	elif taken == 0:
		print("selftest: the borrow took %xmm0, which blendv cannot use",
		      file=sys.stderr)
		failures += 1
	if not failures:
		print(f"selftest: the blendv borrow skips %xmm0 and takes "
		      f"%xmm{taken}")
	return failures


# The rows of `REACH_CASES` are reused here on purpose. The MSVC prologue
# idiom is the one that makes the point: `copy_reaches_home` proves it does
# NOT reach the callee home space -- which is what Finding 96 rests on -- and
# the same rows, the same walk, must say it DOES reach the caller's shadow,
# because reaching the shadow is the whole reason the compiler writes it. A
# region parameter that did nothing would pass one of these and fail the
# other.
SHADOW_CASES = [
	("the MSVC idiom writing the caller's shadow",
	 [("mov", "%rsp,%rax"), ("mov", "%rcx,0x8(%rax)"), ("push", "%rbx"),
	  ("sub", "$0x20,%rsp"), ("mov", "%rcx,0x10(%rax)")], True),
	("a store into the callee home space, a frame below the shadow",
	 [("mov", "%rsp,%rax"), ("sub", "$0x28,%rsp"),
	  ("mov", "%rcx,-0x28(%rax)")], False),
	("a copy that walks up into the shadow",
	 [("mov", "%rsp,%rax"), ("add", "$0x10,%rax"),
	  ("mov", "%rcx,(%rax)")], True),
	("a copy that stops below the return address",
	 [("mov", "%rsp,%rax"), ("mov", "%rcx,(%rax)")], False),
]

# `rsp_depths` walks straight through branches, so what makes it sound is
# the pair of rules that refuse the cases where walking straight through
# would be a guess. Each case below is one of those rules, plus the two
# shapes it must NOT refuse: MSVC's large-frame epilogue, which no walk can
# follow and which every site precedes, and a leaf with no unwind data.
DEPTH_CASES = [
	("a plain frame, known throughout",
	 [(0x10, "sub", "$0x28,%rsp"), (0x14, "vaddss", "%xmm0,%xmm1,%xmm0"),
	  (0x18, "add", "$0x28,%rsp"), (0x1c, "ret", "")], 0x28, 0x14, -0x28),
	("a return that does not balance the frame",
	 [(0x10, "sub", "$0x28,%rsp"), (0x14, "ret", "")], 0x28, None,
	 "a return does not balance the frame"),
	("a branch taken at a depth the walk never modelled",
	 [(0x10, "sub", "$0x28,%rsp"), (0x14, "push", "%rbx"),
	  (0x18, "jne", "0x10")], 0x28, None,
	 "a branch leaves at an unmodelled depth"),
	("MSVC restoring a large frame from r11, which ends at the return",
	 [(0x10, "vaddss", "%xmm0,%xmm1,%xmm0"), (0x14, "mov", "%r11,%rsp"),
	  (0x18, "ret", ""), (0x1c, "vmulss", "%xmm0,%xmm1,%xmm0")],
	 0x28, 0x1c, -0x28),
	("a leaf with no unwind data, which must not move rsp",
	 [(0x10, "vaddss", "%xmm0,%xmm1,%xmm0"), (0x14, "ret", "")],
	 0, 0x10, 0),
	("no unwind data and a push, which the ABI does not permit",
	 [(0x10, "push", "%rbx"), (0x14, "pop", "%rbx"), (0x18, "ret", "")],
	 0, None, "no unwind data and rsp moves"),
]


# One instruction per row, four bytes apart, in the shape `plain` holds.
# The reference is always at 0x14, the site always at 0x20, and what
# changes is the control flow between and around them. `expected` is
# whether the SITE can still reach the reference -- True means refuse.
def _addressed(rows):
	"""`REACH_CASES` and `SHADOW_CASES` name no addresses, because what
	they test is the walk rather than where it is. `copy_reaches_home`
	takes them now so that it can report a hazard's position, so they are
	laid out four bytes apart here.
	"""
	return [(0x1000 + 4 * i, mnemonic, operands)
	        for i, (mnemonic, operands) in enumerate(rows)]


def _row(address, mnemonic, operands=""):
	return (address, b"\x90", mnemonic, operands)


READER_CASES = [
	("a reference before the site, straight through",
	 [_row(0x10, "mov", "%rcx,%rax"), _row(0x14, "mov", "%rcx,0x8(%rsp)"),
	  _row(0x18, "mov", "0x8(%rsp),%rdx"), _row(0x20, "vaddss", "%xmm0"),
	  _row(0x24, "ret")], (), False),
	("a reference after the site",
	 [_row(0x10, "mov", "%rcx,%rax"), _row(0x20, "vaddss", "%xmm0"),
	  _row(0x24, "mov", "0x8(%rsp),%rdx"), _row(0x28, "ret")],
	 (), True),
	("a loop that carries the reference back over the site",
	 [_row(0x10, "mov", "%rcx,%rax"), _row(0x14, "mov", "%rcx,0x8(%rsp)"),
	  _row(0x20, "vaddss", "%xmm0"), _row(0x24, "jne", "0x14"),
	  _row(0x28, "ret")], (), True),
	("a loop that closes below the reference",
	 [_row(0x10, "mov", "%rcx,%rax"), _row(0x14, "mov", "%rcx,0x8(%rsp)"),
	  _row(0x18, "nop"), _row(0x20, "vaddss", "%xmm0"),
	  _row(0x24, "jne", "0x18"), _row(0x28, "ret")], (), False),
	("a forward conditional that steps over the reference",
	 [_row(0x10, "je", "0x20"), _row(0x14, "mov", "%rcx,0x8(%rsp)"),
	  _row(0x20, "vaddss", "%xmm0"), _row(0x24, "ret")], (), False),
	("an indirect branch that can reach the reference",
	 [_row(0x10, "mov", "%rcx,%rax"), _row(0x14, "mov", "%rcx,0x8(%rsp)"),
	  _row(0x20, "vaddss", "%xmm0"), _row(0x24, "jmp", "*%rax"),
	  _row(0x28, "ret")], (0x14,), True),
	("an indirect branch whose targets are all past the reference",
	 [_row(0x10, "mov", "%rcx,%rax"), _row(0x14, "mov", "%rcx,0x8(%rsp)"),
	  _row(0x20, "vaddss", "%xmm0"), _row(0x24, "jmp", "*%rax"),
	  _row(0x28, "ret")], (0x28,), False),
	("a range that falls off its own end",
	 [_row(0x10, "mov", "%rcx,0x8(%rsp)"), _row(0x20, "vaddss", "%xmm0"),
	  _row(0x24, "nop")], (), True),
	("a tail call, which takes its edge out of the function",
	 [_row(0x10, "mov", "%rcx,0x8(%rsp)"), _row(0x20, "vaddss", "%xmm0"),
	  _row(0x24, "jmp", "0x900000")], (), False),
]


# `(rows, depths, expected references, expected pointer)`, against
# `CALLER_SHADOW` at entry-relative [8, 40). **Every case but the first
# sits at a NON-ZERO depth**, because that is the only place the sign of
# the arithmetic shows: at depth zero `d + k` and `k - d` are the same
# number, which is why a wrong one passed every fixture in the tree.
REFERENCE_CASES = [
	("the prologue spill, at depth zero",
	 [(0x10, "mov", "%rcx,0x8(%rsp)")], {0x10: 0}, [0x10], False),
	("the same shadow byte through a settled frame",
	 [(0x20, "mov", "%rcx,0x30(%rsp)")], {0x20: -0x28}, [0x20], False),
	("a local at the bottom of the frame, which is not the shadow",
	 [(0x20, "mov", "%rcx,0x8(%rsp)")], {0x20: -0x28}, [], False),
	("one past the top of the shadow",
	 [(0x20, "mov", "%rcx,0x50(%rsp)")], {0x20: -0x28}, [], False),
	("the top byte of the shadow, which is inside it",
	 [(0x20, "mov", "%rcx,0x4c(%rsp)")], {0x20: -0x28}, [0x20], False),
	("the return address, one below the shadow",
	 [(0x20, "mov", "%rcx,0x28(%rsp)")], {0x20: -0x28}, [], False),
	("a lea forming a pointer into it",
	 [(0x20, "lea", "0x30(%rsp),%rbx")], {0x20: -0x28}, [], True),
	("an unknown depth, which could be anywhere",
	 [(0x20, "mov", "%rcx,0x30(%rsp)")], {0x20: None}, [0x20], False),
]


# Instructions in the five-field shape `ymm_span` walks, laid out
# contiguously so that no case fails for a gap. The encodings are real: a
# VEX.256 load, store, `vaddps`, `vpermq` and a narrow `vmovaps`, since the
# walk decodes `L` and the mnemonic and would be answering about nothing if
# the bytes did not decode.
SPAN_LOAD0 = bytes.fromhex("c5fc1006")		# vmovups (%rsi),%ymm0
SPAN_LOAD1 = bytes.fromhex("c5fc104e20")	# vmovups 0x20(%rsi),%ymm1
SPAN_STORE0 = bytes.fromhex("c5fc1107")		# vmovups %ymm0,(%rdi)
SPAN_ADD = bytes.fromhex("c5f458c0")		# vaddps %ymm0,%ymm1,%ymm0
SPAN_PERM = bytes.fromhex("c4e3fd00c001")	# vpermq $1,%ymm0,%ymm0
SPAN_NARROW = bytes.fromhex("c5f828c8")		# vmovaps %xmm0,%xmm1
SPAN_ADD2 = bytes.fromhex("c5f458d0")		# vaddps %ymm0,%ymm1,%ymm2
SPAN_COPY = bytes.fromhex("c5fc10c8")		# vmovups %ymm0,%ymm1
SPAN_COPY2 = bytes.fromhex("c5fc10da")		# vmovups %ymm2,%ymm3
SPAN_SPLAT = bytes.fromhex("c4e27d18cb")	# vbroadcastss %xmm3,%ymm1
SPAN_STORE1 = bytes.fromhex("c5fc110f")		# vmovups %ymm1,(%rdi)


def _flow(rows):
	"""Lay `(mnemonic, operands)` out four bytes apart from 0x1000.

	Four bytes because `gpr_live_out` reads a branch target as an address
	and has to find an instruction there; one byte apart would make every
	target land mid-instruction and every case answer the unresolved
	question instead of the one it asks.
	"""
	return [(0x1000 + 4 * i, b"\x90\x90\x90\x90", mnemonic, operands)
	        for i, (mnemonic, operands) in enumerate(rows)]


# `(what, rows, position, register, expected)` -- is `register` live after
# `rows[position]`? Every case is here in both directions where the shape
# admits one, because a liveness answer that is always "live" is sound,
# useless, and passes any test that only checks for corruption.
GPR_CASES = [
	("a later read makes it live",
	 [("mov", "$0x1,%r10"), ("nop", ""), ("add", "%r10,%rax"),
	  ("ret", "")], 1, "r10", True),
	("nothing reads it again",
	 [("mov", "$0x1,%r10"), ("nop", ""), ("add", "%rcx,%rax"),
	  ("ret", "")], 1, "r10", False),
	# The kill. Without it every later mention reads back to the start of
	# the function and the analysis frees almost nothing.
	("a full write kills what was there",
	 [("nop", ""), ("mov", "$0x2,%r10"), ("add", "%r10,%rax"),
	  ("ret", "")], 0, "r10", False),
	("a 32-bit write kills, because it zero-extends",
	 [("nop", ""), ("mov", "$0x2,%r10d"), ("add", "%r10,%rax"),
	  ("ret", "")], 0, "r10", False),
	("an 8-bit write does NOT kill, it leaves the rest",
	 [("nop", ""), ("mov", "$0x2,%r10b"), ("add", "%r10,%rax"),
	  ("ret", "")], 0, "r10", True),
	("a write whose source names it reads it too",
	 [("nop", ""), ("mov", "(%r10),%r10"), ("ret", "")], 0, "r10", True),
	("a memory destination is not a write of its base",
	 [("nop", ""), ("mov", "%rax,(%r10)"), ("ret", "")], 0, "r10", True),
	# The call. Reads the argument registers, kills nothing -- see
	# `gpr_effect`, where the binary's own __chkstk is the argument.
	("a call reads the argument registers",
	 [("nop", ""), ("call", "0x2000"), ("ret", "")], 0, "r8", True),
	("a call does not read r10",
	 [("nop", ""), ("call", "0x2000"), ("ret", "")], 0, "r10", False),
	("a call does not kill, so a value survives it",
	 [("mov", "$0x1,%rax"), ("call", "0x2000"), ("sub", "%rax,%rsp"),
	  ("ret", "")], 0, "rax", True),
	# A ret is modelled exactly rather than treated as an unknown exit.
	("a ret reads the return value",
	 [("nop", ""), ("ret", "")], 0, "rax", True),
	("a ret does not read the scratch registers",
	 [("nop", ""), ("ret", "")], 0, "r11", False),
	# Leaving the range is a tail call, and its callee reads what it likes.
	("a jump out of the range is a tail call, so everything is live",
	 [("nop", ""), ("jmp", "0x9000")], 0, "r10", True),
	("falling off the end of the range is not modelled",
	 [("nop", ""), ("nop", "")], 0, "r10", True),
	# **The pair address order gets wrong**, and the reason this is a
	# fixpoint over edges rather than a scan. The read is at a LOWER
	# address than the site in both, so nothing looking forward from the
	# site can see it; only the loop's back edge reaches it. The first
	# version of this case put the read one instruction after the site,
	# where address order finds it too -- so it passed against a sabotage
	# that replaced reachability with "the next instruction", and the
	# whole rule was resting on nothing.
	("a loop closing above the read carries it back",
	 [("add", "%r10,%rax"), ("nop", ""), ("jne", "0x1000"),
	  ("ret", "")], 1, "r10", True),
	("a loop closing below the read does not",
	 [("add", "%r10,%rax"), ("nop", ""), ("nop", ""), ("jne", "0x1008"),
	  ("ret", "")], 1, "r10", False),
	("a forward branch does not carry it backwards",
	 [("add", "%r10,%rax"), ("nop", ""), ("jne", "0x100c"),
	  ("ret", "")], 1, "r10", False),
	("live on one path of two is live",
	 [("jne", "0x100c"), ("nop", ""), ("ret", ""),
	  ("add", "%r10,%rax"), ("ret", "")], 0, "r10", True),
	("a narrow spelling is the same register",
	 [("nop", ""), ("add", "%r10b,%al"), ("ret", "")], 0, "r10", True),
]


# **The assembler's own bytes**, taken from `as` on the sequence spelled out
# in `encode_tls_base` and `encode_tls_spill` and pasted here. Every other
# encoder in this file is exercised by something that RUNS it; these two are
# emitted only where a site has two dead general-purpose registers, which no
# fixture is guaranteed to contain, so the encoding is pinned directly.
# `(what, bytes, call)` with the call spelled as arguments.
# **Each row names the `INDEX_CONST` it is asserting**, because the two
# forms are both live and the table used to assume one of them. When the
# constant index became the default in `6737453` these rows went on
# asserting the three-instruction form and `make check` was not run, so
# the suite was red from that commit until 2026-09-20. A frozen encoding
# is exactly the kind of check that a default flip makes wrong in
# silence, since nothing else in the tree reads these bytes.
#
# Every expectation below came out of `as`, re-taken for the two new rows
# rather than copied from what the emitter produced: a vector generated by
# running the code under test is the same hand twice. Finding 297.
TLS_ENCODINGS = [
	("movq %gs:0x58,%rax / mov (%rip),%edx / movq (%rax,%rdx,8),%rax",
	 "65488b0425580000008b155f332211488b04d0",
	 ("base", 0, 2, 0x1122336e, 0), False),
	("the same with r10 and r11, which need every REX bit",
	 "654c8b142558000000448b1d653322114f8b14da",
	 ("base", 10, 11, 0x11223375, 0), False),
	("movq %gs:0x58,%rax / movq 0x5a5a5a5a(%rax),%rax, the constant index",
	 "65488b042558000000488b805a5a5a5a",
	 ("base", 0, 2, 0x1122336e, 0), True),
	("the same in r10, REX.W, REX.R and REX.B on the second",
	 "654c8b1425580000004d8b925a5a5a5a",
	 ("base", 10, 11, 0x11223375, 0), True),
	("movups %xmm2,0x3260(%rax)", "0f119060320000",
	 ("spill", 2, True, 0, 0x3260), None),
	("movups %xmm2,0x3260(%r10), which needs REX.B", "410f119260320000",
	 ("spill", 2, True, 10, 0x3260), None),
	("movups %xmm9,0x3260(%r10), REX.R and REX.B", "450f118a60320000",
	 ("spill", 9, True, 10, 0x3260), None),
	("and the restore, which differs by one opcode byte",
	 "450f108a60320000", ("spill", 9, False, 10, 0x3260), None),
]


def tls_selftest():
	"""Prove the TLS encodings still say what `as` said. Failures, or 0."""
	global INDEX_CONST
	was, failures = INDEX_CONST, 0
	for what, want, call, mode in TLS_ENCODINGS:
		INDEX_CONST = was if mode is None else mode
		try:
			got = (encode_tls_base(*call[1:]) if call[0] == "base"
			       else encode_tls_spill(*call[1:])).hex()
		finally:
			INDEX_CONST = was
		if got != want:
			print(f"selftest: {what}: encoded {got}, want {want}",
			      file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(TLS_ENCODINGS)} tls encodings match the "
		      f"assembler byte for byte")
	return failures


# `(what, rows, position, register, expected)` -- is xmm`register` live
# after `rows[position]`? Half assert DEAD, because a liveness pass that
# answered "live" everywhere would be sound, would free nothing, and would
# pass every case that only checks for corruption.
XMM_CASES = [
	("a later read makes it live",
	 [("movaps", "%xmm1,%xmm4"), ("nop", ""), ("addps", "%xmm4,%xmm0"),
	  ("ret", "")], 1, 4, True),
	("nothing reads it again",
	 [("movaps", "%xmm1,%xmm4"), ("nop", ""), ("addps", "%xmm1,%xmm0"),
	  ("ret", "")], 1, 4, False),
	("a plain move kills what was there",
	 [("nop", ""), ("movaps", "%xmm1,%xmm4"), ("addps", "%xmm4,%xmm0"),
	  ("ret", "")], 0, 4, False),
	("an arithmetic write does NOT kill, it reads too",
	 [("nop", ""), ("addps", "%xmm1,%xmm4"), ("ret", "")], 0, 4, True),
	("a move whose source names it reads it",
	 [("nop", ""), ("movaps", "%xmm4,%xmm5"), ("ret", "")], 0, 4, True),
	("a memory destination is not a write of the register",
	 [("nop", ""), ("movaps", "%xmm4,(%rax)"), ("ret", "")], 0, 4, True),
	# **The same register under its wider name.** A helper holds sixteen
	# bytes and %ymm4 is those bytes; a scan keyed on the xmm spelling
	# alone would hand out a register the program is using.
	("the ymm spelling is the same register",
	 [("nop", ""), ("vaddps", "%ymm4,%ymm1,%ymm1"), ("ret", "")],
	 0, 4, True),
	# The call. Reads the argument registers, kills nothing -- xmm_effect's
	# argument, which is gpr_effect's and rests on the same __chkstk
	# evidence.
	("a call reads the argument registers",
	 [("nop", ""), ("call", "0x2000"), ("ret", "")], 0, 1, True),
	("a call does not read xmm4",
	 [("nop", ""), ("call", "0x2000"), ("ret", "")], 0, 4, False),
	# **In xmm4 and not xmm0**, which the first version got wrong. xmm0 is
	# an argument register, so a call reads it whatever else is true, and
	# the case passed against a sabotage that killed every volatile
	# register at a call -- the very rule it was written to defend. A
	# register the call does not read is the only one that can show a kill.
	("a call does not kill, so a value survives it",
	 [("movaps", "%xmm1,%xmm4"), ("call", "0x2000"),
	  ("addps", "%xmm4,%xmm2"), ("ret", "")], 0, 4, True),
	("a ret reads the return register",
	 [("nop", ""), ("ret", "")], 0, 0, True),
	("a ret does not read the scratch ones",
	 [("nop", ""), ("ret", "")], 0, 5, False),
	("a jump out of the range is a tail call",
	 [("nop", ""), ("jmp", "0x9000")], 0, 4, True),
	("falling off the end of the range is not modelled",
	 [("nop", ""), ("nop", "")], 0, 4, True),
	# The pair address order gets wrong, as for the GPRs: the read is at a
	# LOWER address than the site and only the back edge reaches it.
	("a loop closing above the read carries it back",
	 [("addps", "%xmm4,%xmm0"), ("nop", ""), ("jne", "0x1000"),
	  ("ret", "")], 1, 4, True),
	("a loop closing below the read does not",
	 [("addps", "%xmm4,%xmm0"), ("nop", ""), ("nop", ""),
	  ("jne", "0x1008"), ("ret", "")], 1, 4, False),
]


def xmm_selftest():
	"""Prove `xmm_live_out` frees a register only where it is dead. 0 or n."""
	failures = 0
	for what, rows, position, register, expected in XMM_CASES:
		plain = _flow(rows)
		live = xmm_live_out(plain, 0, len(plain), ())
		got = register in live[position]
		if got != expected:
			print(f"selftest: {what}: xmm{register} after "
			      f"{plain[position][2]} {plain[position][3]} is "
			      f"{'live' if got else 'dead'}, want "
			      f"{'live' if expected else 'dead'}", file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(XMM_CASES)} xmm liveness shapes, live and "
		      f"dead in both directions")
	return failures


def gpr_selftest():
	"""Prove `gpr_live_out` frees a register only where it is dead. 0 or n.

	**The direction that matters is the False answers.** A liveness pass
	that answered "live" everywhere would be sound, would free nothing, and
	would pass every case here that asserts a register is live -- so half
	of these assert the opposite, and the sabotage runs take out one rule
	at a time to show which case is holding which.
	"""
	failures = 0
	for what, rows, position, register, expected in GPR_CASES:
		plain = _flow(rows)
		live = gpr_live_out(plain, 0, len(plain), ())
		got = register in live[position]
		if got != expected:
			print(f"selftest: {what}: {register} after "
			      f"{plain[position][2]} {plain[position][3]} is "
			      f"{'live' if got else 'dead'}, want "
			      f"{'live' if expected else 'dead'}", file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(GPR_CASES)} gpr liveness shapes, live and "
		      f"dead in both directions")
	return failures


def _span(rows):
	"""Lay `(encoding, mnemonic, operands)` out end to end from 0x1000,
	and end with a `ret`.

	The `ret` is not decoration. `upper_half_read_later` answers "still
	read" when it walks off the end of the listing, so a fixture without a
	terminator refuses every span for a reason that is about the fixture
	rather than about the code -- which is how the first run of this
	selftest reported three failures that were its own.
	"""
	out, at = [], 0x1000
	for encoding, mnemonic, operands in rows + [(b"\xc3", "ret", "")]:
		out.append((at, encoding, mnemonic, operands, None))
		at += len(encoding)
	return out


SPAN_CASES = [
	("a load, an add and a store, which is the whole point",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_LOAD1, "vmovups", "0x20(%rsi),%ymm1"),
	  (SPAN_ADD, "vaddps", "%ymm0,%ymm1,%ymm0"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)")], 2),
	("an add whose source this span never defined",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_ADD, "vaddps", "%ymm0,%ymm7,%ymm0"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)")], None),
	("a 256-bit form that does not split lane-wise",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_PERM, "vpermq", "$1,%ymm0,%ymm0"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)")], None),
	("the value touched by something narrower",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_NARROW, "vmovaps", "%xmm0,%xmm1"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)")], None),
	("a load nothing consumes",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0")], None),
	# **The case the closure rule exists for**, and it was missing until a
	# sabotage run removed the rule and nothing went red. Every other case
	# closes by reaching the `ret`, so "the value must be dead at the end"
	# was being asserted over spans where it was true anyway.
	("a value still read after the span ends",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)"),
	  (SPAN_ADD2, "vaddps", "%ymm0,%ymm1,%ymm2")], None),
	("a memory source, which needs no slot of its own",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_ADD, "vaddps", "0x40(%rsi),%ymm0,%ymm0"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)")], 1),
	# **The three shapes Finding 140 added, each with the refusal it must
	# still make.** A copy is representable only from a source the span
	# holds, a broadcast from nothing at all, and a store of a value the
	# span never defined is a correct refusal that had been wearing the
	# lane-wise label.
	("a copy of a tracked value, which the destination inherits",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_COPY, "vmovups", "%ymm0,%ymm1"),
	  (SPAN_STORE1, "vmovups", "%ymm1,(%rdi)")], 2),
	("a copy of a value this span never defined",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_COPY2, "vmovups", "%ymm2,%ymm3"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)")],
	 "a 256-bit copy of a value this span never defined"),
	("a broadcast, whose two lanes are the same sixteen bytes",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_SPLAT, "vbroadcastss", "%xmm3,%ymm1"),
	  (SPAN_STORE1, "vmovups", "%ymm1,(%rdi)"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)")], 2),
	("a store of a value this span never defined",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_STORE1, "vmovups", "%ymm1,(%rdi)"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)")],
	 "a 256-bit store of a value this span never defined"),
	("two values whose lifetimes do not overlap need one slot",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)"),
	  (SPAN_LOAD1, "vmovups", "0x20(%rsi),%ymm1"),
	  (SPAN_STORE0, "vmovups", "%ymm1,(%rdi)")], 1),
]


def reach_selftest():
	"""Prove `copy_reaches_home` still discriminates. Failures, or 0.

	**A zero from a probe that cannot find a hit reads exactly like a zero
	from a program that has none**, and Finding 96 rests on a zero: not one
	function in the binary reaches its callee home space through a copy of
	`rsp`. An earlier revision of that measurement returned the same zero
	because a bad narrow-write rule had killed the pointer early, so the
	cases below fix both directions -- what must be caught, and what must
	not be refused for nothing.
	"""
	failures = 0
	for what, rows, expected in REACH_CASES:
		got = copy_reaches_home(_addressed(rows),
		                        None if "unknown frame" in what else 0x28)
		if got != expected:
			print(f"selftest: {what}: copy_reaches_home said {got}, "
			      f"want {expected}", file=sys.stderr)
			failures += 1
	# **A refusal turned into a position must not go missing.** Asked for
	# `hazards`, two of the six refusals report an address and carry on
	# instead of returning True -- so every case that refuses must now
	# either still refuse or name at least one place, and no case that was
	# allowed may start naming one. That is the invariant, and it is
	# checkable without classifying which refusal each case trips.
	for what, rows, expected in REACH_CASES:
		hazards = []
		got = copy_reaches_home(_addressed(rows),
		                        None if "unknown frame" in what else 0x28,
		                        hazards=hazards)
		if expected and not got and not hazards:
			print(f"selftest: {what}: refused whole, and named no place "
			      f"when asked for one", file=sys.stderr)
			failures += 1
		if not expected and (got or hazards):
			print(f"selftest: {what}: was allowed, and now refuses or names "
			      f"{[hex(a) for a in hazards]}", file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(REACH_CASES)} rsp-copy cases, caught in both "
		      f"directions and none lost when asked where")
	return failures


def reader_selftest():
	"""Prove `readers_reachable` refuses exactly what can still read the
	region. Failures, or 0.

	The reference sits at 0x14 and the site at 0x20 in every case, so what
	is being tested is the control flow and nothing else. **Two of the
	cases exist to fail in opposite directions**: a loop closing above the
	reference must refuse and one closing below it must not, and a rule
	that gave up on backward branches would pass the first and fail the
	second while looking careful.
	"""
	failures = 0
	for what, rows, targets, expected in READER_CASES:
		site = next(i for i, row in enumerate(rows) if row[0] == 0x20)
		refs = {i for i, row in enumerate(rows)
		        if "0x8(%rsp)" in (row[3] or "")}
		if not refs:
			print(f"selftest: {what}: the case names no reference",
			      file=sys.stderr)
			failures += 1
			continue
		inside = tuple(i for i, row in enumerate(rows) if row[0] in targets)
		reaching = readers_reachable(rows, 0, len(rows), refs, inside)
		got = site in reaching
		if got != expected:
			print(f"selftest: {what}: the site "
			      f"{'reaches' if got else 'does not reach'} the reference, "
			      f"want {'reaches' if expected else 'does not'}",
			      file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(READER_CASES)} region-reader shapes, "
		      f"refused and allowed in both directions")
	return failures


# **The region's closure rule, which had no test and no row in Finding 65's
# table.** Every sibling lowering must leave no ymm whose upper half is read
# later -- the pair since Finding 38, the run since Finding 64, the span
# since Finding 153 -- and the region shipped without the check for 166
# regions, 150 of which were wrong. `region_members` decides only what a
# region can REPRESENT; closure is `region_candidate`'s question, so the
# cases below ask both, the way the strategy does.
# The third field is the row whose address is a BRANCH TARGET, which is
# what ends the region before the rows after it -- the only way to put a
# reader outside a region in a fixture, since `region_end` otherwise runs
# to the `ret` and swallows everything. `None` means no target.
REGION_CASES = [
	("a load and a store, closed by the ret",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)")], None, True),
	# **The case the bug was**, and it only bites where the reader is
	# outside the region: a rule asserted over regions that close anyway
	# is asserted where it holds already, which is how the span's own
	# closure case came to be missing until a sabotage run removed the
	# rule and nothing went red. Finding 111, met a second time -- and
	# met again here, because the first draft of this case put the reader
	# INSIDE the region, where `region_members` refused it for an
	# unrelated reason and the closure rule was never consulted.
	("a value read as 256-bit after the region ends",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)"),
	  (SPAN_ADD2, "vaddps", "%ymm0,%ymm1,%ymm2")], 2, False),
	("a region whose value nothing reads after it ends",
	 [(SPAN_LOAD0, "vmovups", "(%rsi),%ymm0"),
	  (SPAN_STORE0, "vmovups", "%ymm0,(%rdi)"),
	  (SPAN_LOAD1, "vmovups", "0x20(%rsi),%ymm1")], 2, True),
]


# A dispatch is three instructions that need not be adjacent, so the cases
# below vary what sits between them and which register each names. The
# rows are (address, encoding, mnemonic, operands); only the last two are
# read, which is what lets `verify` pass `parse_listing` output straight in.
SWITCH_CASES = [
	("the ordinary MSVC form",
	 [("mov", "0x181d498(%r9,%rax,4),%ecx"),
	  ("add", "%r9,%rcx"),
	  ("jmp", "*%rcx")], 0x181d498),
	("with unrelated work between the parts",
	 [("mov", "0x2000(%r11,%rdx,4),%r8d"),
	  ("nop", ""),
	  ("add", "%r11,%r8"),
	  ("test", "%eax,%eax"),
	  ("jmp", "*%r8")], 0x2000),
	# **Both links are load-bearing.** Without the `add` this matches any
	# scaled load; without the register agreement it matches a load into a
	# register the jump never uses.
	("the add names a different base register",
	 [("mov", "0x181d498(%r9,%rax,4),%ecx"),
	  ("add", "%rbx,%rcx"),
	  ("jmp", "*%rcx")], None),
	("the load goes to a register the jump does not use",
	 [("mov", "0x181d498(%r9,%rax,4),%edx"),
	  ("add", "%r9,%rcx"),
	  ("jmp", "*%rcx")], None),
	("a scaled load with no add at all",
	 [("mov", "0x181d498(%r9,%rax,4),%ecx"),
	  ("jmp", "*%rcx")], None),
	("an indirect jump through memory, not a register",
	 [("mov", "0x181d498(%r9,%rax,4),%ecx"),
	  ("add", "%r9,%rcx"),
	  ("jmp", "*(%rcx)")], None),
	("not an indirect jump",
	 [("mov", "0x181d498(%r9,%rax,4),%ecx"),
	  ("add", "%r9,%rcx"),
	  ("jmp", "0x140001000")], None),
]


# **Which refusals are about a register and which are about the ISA.**
# `borrow_that_lowers` returning None means no borrowable register lowers
# the site, so no backing store could ever help it; a site that lowers at
# some registers and not others is the register question the spill
# machinery exists for. The two were reported in one bucket until Finding
# 178, so 290 sites wore a register-pressure label on a 256-bit ISA bound.
ISA_BOUND_CASES = [
	("a 256-bit broadcast has no SSE form at all",
	 "c4e27d18d4", "%xmm4,%ymm2", "vbroadcastss", False),
	("nor does the AVX2 integer broadcast",
	 "c4e27d58d4", "%xmm4,%ymm2", "vpbroadcastd", False),
	("nor 256-bit lane-wise arithmetic, which needs the upper half",
	 "c5fc58c1", "%ymm1,%ymm0,%ymm0", "vaddps", False),
	# The control, and the reason this is a discriminator rather than a
	# label: a 128-bit site whose src2 is its destination DOES lower, given
	# a register the operands do not name.
	("a 128-bit aliased site lowers, given a register",
	 "c5f9ebd2", "%xmm2,%xmm0,%xmm2", "vpor", True),
]


def isa_bound_selftest():
	"""Prove the ISA bound and the register bound are told apart. 0 or n."""
	failures = 0
	for what, hexenc, operands, mnemonic, expected in ISA_BOUND_CASES:
		encoding = bytes.fromhex(hexenc)
		got = borrow_that_lowers(0x1000, encoding, operands, mnemonic,
		                         0x2000, 0x2000) is not None
		if got != expected:
			print(f"selftest: {what}: borrow_that_lowers "
			      f"{'found' if got else 'found no'} register, want "
			      f"{'one' if expected else 'none'}", file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(ISA_BOUND_CASES)} refusals sorted into ISA "
		      f"bound and register bound")
	return failures


# **Which `%ymm` operands a surviving reader actually reads the upper half
# of.** `verify`'s stale-read check reported 470 where 39 were expected:
# 338 named the reader's own destination and 101 an insert that discards
# the half it names. The rule below is the fix, and these are its cases --
# including a `vperm2f128 $0x1`, which is a lane SWAP and does read the
# high half, so a rule that skipped every `vperm2f128` would be wrong.
UPPER_SOURCE_CASES = [
	("a store: the ymm is a source, the memory the destination",
	 "vmovups", "%ymm0,(%rdi)", ["%ymm0"]),
	("a load: the ymm is written, not read",
	 "vmovups", "(%rsi),%ymm0", []),
	("a destination is overwritten, never read",
	 "vmulps", "0xf0(%rbp),%ymm4,%ymm0", ["%ymm4"]),
	("src2 that is also the destination is still a source",
	 "vaddps", "%ymm1,%ymm0,%ymm0", ["%ymm1", "%ymm0"]),
	("insert at lane 1 takes src1's LOW half only",
	 "vinsertf128", "$0x1,%xmm4,%ymm4,%ymm4", []),
	("perm2f128 $0x20 selects both low lanes",
	 "vperm2f128", "$0x20,%ymm1,%ymm0,%ymm0", []),
	("perm2f128 $0x1 is a lane swap and DOES read the high half",
	 "vperm2f128", "$0x1,%ymm0,%ymm0,%ymm0", ["%ymm0", "%ymm0"]),
	# An FMA accumulates into its destination, so that destination is read
	# as well as written -- the one shape `fields[:-1]` gets wrong.
	("an FMA reads its accumulator as well as writing it",
	 "vfmadd231ps", "(%rdx),%ymm4,%ymm3", ["%ymm4", "%ymm3"]),
	("and so does the fused multiply-subtract",
	 "vfnmadd213ps", "%ymm1,%ymm2,%ymm0", ["%ymm1", "%ymm2", "%ymm0"]),
]


# **A join is answerable when every way in agrees.** `reaching_definition`
# used to refuse at any branch target, which left 605 of the 736 sources
# the stale-read gate cannot speak for -- and 61 real stale reads inside
# them. The cases below are the three answers it must give.
JOIN_CASES = [
	("both ways in reach the same write", True, False, 0),
	("the ways disagree, so nothing is decided", False, False, None),
	("the predecessors are not knowable", True, True, None),
]
# **An UNCONDITIONAL branch predecessor is walked back FROM, not through.**
# A conditional one is not refused as a control transfer, so it does not
# discriminate -- the first draft of this case used `je` and passed with the
# bug restored. `jmp` is the shape that cost 73 of the 248 unresolved
# sources. Finding 193.
BRANCH_EDGE_CASE = ("an unconditional branch edge is walked back from", 0)


def join_selftest():
	"""Prove a join resolves only when every way in agrees. 0 or n."""
	vpxor = bytes.fromhex("c5f9efc0")
	branch = bytes.fromhex("7401")
	store = bytes.fromhex("c5fc1107")
	load = bytes.fromhex("c5fc1006")
	failures = 0
	for what, agree, opaque, expected in JOIN_CASES:
		middle = (b"\x90", "nop", "") if agree \
			else (load, "vmovups", "(%rsi),%ymm0")
		rows, at = [], 0x1000
		for encoding, mnemonic, operands in [
				(vpxor, "vpxor", "%xmm0,%xmm0,%xmm0"),
				(branch, "je", "0x1007"), middle, (b"\x90", "nop", ""),
				(store, "vmovups", "%ymm0,(%rdi)")]:
			rows.append((at, encoding, mnemonic, operands, None))
			at += len(encoding)
		join = rows[3][0]
		sources = None if opaque else {join: [rows[1][0]]}
		got = reaching_definition(rows, 4, "%ymm0", {join}, sources=sources)
		if got != expected:
			print(f"selftest: {what}: reaching_definition gave {got}, want "
			      f"{expected}", file=sys.stderr)
			failures += 1
	# The branch edge, whose predecessor IS the `je`: the walk must start
	# behind it and reach the `vpxor`, not stop on it.
	what, expected = BRANCH_EDGE_CASE
	rows, at = [], 0x1000
	for encoding, mnemonic, operands in [
			(vpxor, "vpxor", "%xmm0,%xmm0,%xmm0"),
			(bytes.fromhex("eb00"), "jmp", "0x1006"),
			(b"\x90", "nop", ""), (store, "vmovups", "%ymm0,(%rdi)")]:
		rows.append((at, encoding, mnemonic, operands, None))
		at += len(encoding)
	# The `jmp` is the join's ONLY way in: it does not fall through, so
	# `predecessors_of` offers the branch edge alone and the case turns
	# entirely on whether the walk starts on that `jmp` or behind it.
	join = rows[2][0]
	got = reaching_definition(rows, 3, "%ymm0", {join},
	                          sources={join: [rows[1][0]]})
	if got != expected:
		print(f"selftest: {what}: reaching_definition gave {got}, want "
		      f"{expected}", file=sys.stderr)
		failures += 1
	# **The set the disagreeing join reaches is an answer, not a refusal.**
	# The wrapper says None above, which is what a caller wanting one
	# definition needs; the plural walk must still name both, because
	# `stale_upper_reads` is stale if EITHER way was rewritten. A walk that
	# refused here would pass the case above and cost 128 sources.
	# Finding 194.
	rows, at = [], 0x1000
	for encoding, mnemonic, operands in [
			(vpxor, "vpxor", "%xmm0,%xmm0,%xmm0"),
			(branch, "je", "0x1007"), (load, "vmovups", "(%rsi),%ymm0"),
			(b"\x90", "nop", ""), (store, "vmovups", "%ymm0,(%rdi)")]:
		rows.append((at, encoding, mnemonic, operands, None))
		at += len(encoding)
	join = rows[3][0]
	got = reaching_definitions(rows, 4, "%ymm0", {join},
	                           sources={join: [rows[1][0]]})
	if got != {0, 2}:
		print(f"selftest: the disagreeing join names every way's write: "
		      f"reaching_definitions gave {got}, want {{0, 2}}",
		      file=sys.stderr)
		failures += 1
	# **The reader's own address is a join like any other.** Here the store
	# IS the branch target, and the walk used to refuse at the top rather
	# than enumerate the one way in. Both ways reach the `vpxor`, so a
	# single answer survives. Finding 194.
	rows, at = [], 0x1000
	for encoding, mnemonic, operands in [
			(vpxor, "vpxor", "%xmm0,%xmm0,%xmm0"),
			(branch, "je", "0x1006"), (store, "vmovups", "%ymm0,(%rdi)")]:
		rows.append((at, encoding, mnemonic, operands, None))
		at += len(encoding)
	reader = rows[2][0]
	got = reaching_definition(rows, 2, "%ymm0", {reader},
	                          sources={reader: [rows[1][0]]})
	if got != 0:
		print(f"selftest: the reader is itself a branch target: "
		      f"reaching_definition gave {got}, want 0", file=sys.stderr)
		failures += 1
	# ... and it stays refused where that reader's ways are NOT knowable,
	# which is the sabotage half: without it the clause above would pass by
	# answering every blocked reader from its fall-through alone.
	got = reaching_definition(rows, 2, "%ymm0", {reader}, sources=None)
	if got is not None:
		print(f"selftest: the reader's ways are not knowable: "
		      f"reaching_definition gave {got}, want None", file=sys.stderr)
		failures += 1
	if not failures:
		print(f"selftest: {len(JOIN_CASES) + 4} joins, resolved only where "
		      f"every way in agrees")
	return failures


LOOP_CASES = [
	("a loop the body cannot disturb resolves to the write above it",
	 False, {0}),
	("a loop whose body rewrites the register names that write too",
	 True, {0, 8}),
]


def loop_selftest():
	"""Prove the loop fixpoint, and that it is not the skip. 0 or n.

	The body is 40 instructions so `value_survives_loop` refuses both cases
	on its 32-step budget -- otherwise the narrow induction would answer
	first and neither case would reach the fixpoint at all.

	**The second case is the whole point.** An implementation that skips a
	back edge instead of iterating answers `{0}` for it: the pre-loop zero,
	which is what the register holds on the first iteration and not on any
	later one. The fixpoint walks the back edge with what it has and the
	body's write comes back, so the answer names both. Finding 195.
	"""
	vpxor = bytes.fromhex("c5f9efc0")
	store = bytes.fromhex("c5fc1107")
	load = bytes.fromhex("c5fc1006")
	failures = 0
	for what, body_writes, expected in LOOP_CASES:
		spec = [(vpxor, "vpxor", "%xmm0,%xmm0,%xmm0"),
		        (b"\x90", "nop", ""),
		        (store, "vmovups", "%ymm0,(%rdi)")]
		for i in range(40):
			if body_writes and i == 5:
				spec.append((load, "vmovups", "(%rsi),%ymm0"))
			else:
				spec.append((b"\x90", "nop", ""))
		spec.append((bytes.fromhex("0f8500000000"), "jne", "0x1004"))
		rows, at = [], 0x1000
		for encoding, mnemonic, operands in spec:
			rows.append((at, encoding, mnemonic, operands, None))
			at += len(encoding)
		head, back = rows[1][0], rows[-1][0]
		if value_survives_loop(rows, 1, "%ymm0", {head}, {head: [back]}):
			print(f"selftest: {what}: the narrow induction answered first, "
			      f"so this case does not reach the fixpoint",
			      file=sys.stderr)
			failures += 1
			continue
		got = reaching_definitions(rows, 2, "%ymm0", {head},
		                           sources={head: [back]})
		if got != expected:
			print(f"selftest: {what}: reaching_definitions gave {got}, want "
			      f"{expected}", file=sys.stderr)
			failures += 1
	# **A cycle visible only as recursion.** Join B is reached from the
	# reader; walking B's ways reaches join A, whose own back edge walks
	# forward again through B -- so B is re-entered while it is being
	# evaluated, which is not a back edge in listing order and was refused
	# outright. B catches the signal and re-runs itself as a fixpoint. 27 of
	# the 230 unresolved sources at depth 16 were this. Finding 197.
	spec = [
		(vpxor, "vpxor", "%xmm0,%xmm0,%xmm0"),
		(b"\x90", "nop", ""),
		(bytes.fromhex("7401"), "je", "0x1008"),
		(b"\x90", "nop", ""),
		(b"\x90", "nop", ""),
		(store, "vmovups", "%ymm0,(%rdi)"),
		(bytes.fromhex("ebf4"), "jmp", "0x1004"),
	]
	rows, at = [], 0x1000
	for encoding, mnemonic, operands in spec:
		rows.append((at, encoding, mnemonic, operands, None))
		at += len(encoding)
	head, second = rows[1][0], rows[4][0]
	sources = {head: [rows[6][0]], second: [rows[2][0]]}
	fired = []
	born = JoinCycle.__init__

	def watch(self, position):
		fired.append(position)
		born(self, position)

	JoinCycle.__init__ = watch
	try:
		got = reaching_definitions(rows, 5, "%ymm0", {head, second},
		                           sources=sources)
	finally:
		JoinCycle.__init__ = born
	if not fired:
		# Without this the case passes for the wrong reason: any future
		# shape that resolves without a cycle would satisfy the assertion
		# below and the path would go untested.
		print("selftest: the recursion-only cycle never raised JoinCycle, so "
		      "this case does not reach the path it is for", file=sys.stderr)
		failures += 1
	elif got != {0}:
		print(f"selftest: a cycle visible only as recursion: "
		      f"reaching_definitions gave {got}, want {{0}}", file=sys.stderr)
		failures += 1
	if not failures:
		print(f"selftest: {len(LOOP_CASES) + 1} loops, and the body's own "
		      f"write is not lost to the back edge")
	return failures


CONSERVATIVE_CASES = [
	("a patched VEX.128 write to the register is a candidate",
	 False, True, "%ymm0", [0]),
	("a call between them is not: the ABI makes the upper half volatile",
	 True, True, "%ymm0", []),
	("an unpatched write is nothing this rewrite did", False, False,
	 "%ymm0", []),
	("a write to another register is not a candidate", False, True,
	 "%ymm3", []),
]


def conservative_selftest():
	"""Prove the conservative scan, and its ABI bound. 0 or n.

	**The `call` case is the whole rule.** Without it the scan would run
	back to the start of the listing and collect writes that cannot
	possibly be the producer, because every ymm upper half is volatile
	across a call. Finding 198.
	"""
	vpxor = bytes.fromhex("c5f9efc0")
	wide = bytes.fromhex("c5fc57c0")
	store = bytes.fromhex("c5fc1107")
	failures = 0
	for what, with_call, patch_it, field, expected in CONSERVATIVE_CASES:
		spec = [(vpxor, "vpxor", "%xmm0,%xmm0,%xmm0")]
		if with_call:
			spec.append((bytes.fromhex("e800000000"), "call", "0x100a"))
		spec.append((store, "vmovups", "%ymm0,(%rdi)"))
		rows, at = [], 0x1000
		for encoding, mnemonic, operands in spec:
			rows.append((at, encoding, mnemonic, operands, None))
			at += len(encoding)
		patched = {rows[0][0]} if patch_it else set()
		got = conservative_producers(rows, len(rows) - 1, field, patched,
		                             set())
		want = [rows[i][0] for i in expected]
		if got != want:
			print(f"selftest: {what}: conservative_producers gave "
			      f"{[hex(a) for a in got]}, want {[hex(a) for a in want]}",
			      file=sys.stderr)
			failures += 1
	# **It does not stop at the nearest write.** The walk failed exactly
	# where control can arrive by a path that skips one, so all of them are
	# candidates or none is.
	rows, at = [], 0x1000
	for encoding, mnemonic, operands in [
			(vpxor, "vpxor", "%xmm0,%xmm0,%xmm0"),
			(b"\x90", "nop", ""),
			(vpxor, "vpxor", "%xmm0,%xmm0,%xmm0"),
			(store, "vmovups", "%ymm0,(%rdi)")]:
		rows.append((at, encoding, mnemonic, operands, None))
		at += len(encoding)
	got = conservative_producers(rows, 3, "%ymm0",
	                             {rows[0][0], rows[2][0]}, set())
	if got != [rows[2][0], rows[0][0]]:
		print(f"selftest: two writes, both candidates: gave "
		      f"{[hex(a) for a in got]}", file=sys.stderr)
		failures += 1
	# A 256-bit write is never patched in place, so it cannot be one.
	rows, at = [], 0x1000
	for encoding, mnemonic, operands in [
			(wide, "vxorps", "%ymm0,%ymm0,%ymm0"),
			(store, "vmovups", "%ymm0,(%rdi)")]:
		rows.append((at, encoding, mnemonic, operands, None))
		at += len(encoding)
	got = conservative_producers(rows, 1, "%ymm0", {rows[0][0]}, set())
	if got:
		print(f"selftest: a 256-bit write is not a candidate: gave "
		      f"{[hex(a) for a in got]}", file=sys.stderr)
		failures += 1
	if not failures:
		print(f"selftest: {len(CONSERVATIVE_CASES) + 2} conservative scans, "
		      f"bounded by the nearest call")
	return failures


def upper_source_selftest():
	"""Prove the reader rule names sources and not destinations. 0 or n."""
	failures = 0
	for what, mnemonic, operands, expected in UPPER_SOURCE_CASES:
		got = upper_half_sources(mnemonic, operands)
		if got != expected:
			print(f"selftest: {what}: upper_half_sources gave {got}, want "
			      f"{expected}", file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(UPPER_SOURCE_CASES)} reader shapes, sources "
		      f"told from destinations")
	return failures


def rescue_selftest():
	"""Prove the rescue chains, and stops. Failures, or 0.

	The second seat exists only because the first was taken -- the window's
	end moves by the first passenger's length and the next candidate's site
	lands there. The loop used to `break` after one and never look again,
	which cost two sites. Finding 183.
	"""
	vex = bytes.fromhex("c5f9ebd2")

	def candidate(at, strategy):
		return (at, vex, "%xmm2,%xmm0,%xmm2", "vpor", 8, [], None,
		        [(at, b"\x90\x90\x90\x90", "nop", "", None)], strategy)

	entries = [None, candidate(0x2004, ("spill", 5)),
	           candidate(0x2008, ("spill", 6))]
	failures = 0
	chain, reach = [], 8
	while len(chain) < RESCUE_CHAIN:
		seat = rescue_seat(entries, 0, 0x2000, reach, chain)
		if seat is None:
			break
		chain.append(seat)
		reach += seat[2]
	if len(chain) != 2:
		print(f"selftest: the rescue seated {len(chain)} passenger(s), want 2",
		      file=sys.stderr)
		failures += 1
	elif not all(entry[6] for _j, entry, _n in chain):
		print("selftest: a spill passenger rode without its borrow flag",
		      file=sys.stderr)
		failures += 1
	# **And it stops.** A seat that is not at the window's end is not a
	# seat: without this the chain would walk down the candidate list.
	if rescue_seat(entries, 0, 0x2000, 8 + 4 + 4, chain) is not None:
		print("selftest: the rescue found a seat past the last passenger",
		      file=sys.stderr)
		failures += 1
	if not failures:
		print("selftest: the rescue chains two passengers and then stops")
	return failures


def switch_selftest():
	"""Prove the dispatch matcher reads the table address. Failures, or 0.

	`switch_targets` needs a binary to read table bytes from and so cannot
	run here; `switch_dispatch` is the half that holds the logic and needs
	nothing. It was split out after a missing import in the combined
	function passed `make style` AND the selftest, because neither reached
	it -- a defect only a forty-minute build could have found. Finding 177.
	"""
	failures = 0
	for what, rows, expected in SWITCH_CASES:
		window = [(0, b"", mnemonic, operands) for mnemonic, operands in rows]
		got = switch_dispatch(window)
		if got != expected:
			shown = "None" if got is None else hex(got)
			want = "None" if expected is None else hex(expected)
			print(f"selftest: {what}: switch_dispatch gave {shown}, "
			      f"want {want}", file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(SWITCH_CASES)} switch dispatches, read and "
		      f"refused")
	return failures


def region_selftest():
	"""Prove a region closes before it is offered. Failures, or 0.

	Asks the two questions `region_candidate` asks in the order it asks
	them: can `region_members` represent this, and is every register it
	slotted dead as a 256-bit value at the end. A region that fails the
	second cannot be repaired by an epilogue -- writing a ymm's upper half
	needs `vinsertf128`, which is itself VEX-256 -- so the only answer is
	to refuse it. Finding 173.
	"""
	failures = 0
	for what, rows, target, expected in REGION_CASES:
		instructions = _span(rows)
		positions = {a: i for i, (a, *_r) in enumerate(instructions)}
		blocked = set() if target is None else {instructions[target][0]}
		last = region_end(instructions, 0, blocked)
		# `region_candidate` trims a trailing transfer off the window
		# before asking either question, so the fixture must too -- with
		# the `ret` left in, the region's last member IS the terminator
		# and the scan starts off the end of the listing, which
		# `upper_half_read_later` conservatively calls a read. That is a
		# property of the fixture, not of the code under test.
		if instructions[last - 1][2].startswith(CONTROL_PREFIXES):
			last -= 1
		found = region_members(instructions, 0, last)
		if found is None:
			closes = False
		else:
			_members, slots = found
			closes = not any(
				upper_half_read_later(instructions, last - 1, register,
				                      positions=positions)
				for register in slots)
		if closes != expected:
			print(f"selftest: {what}: region "
			      f"{'closes' if closes else 'does not close'}, want "
			      f"{'closes' if expected else 'a refusal'}",
			      file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(REGION_CASES)} regions, and one is refused "
		      f"for a value read after it ends")
	return failures


def span_selftest():
	"""Prove `ymm_span` closes only where it can. Failures, or 0.

	The number checked is the SLOT DEMAND, not merely whether a span was
	found, because the demand is what Finding 133's whole argument turns
	on -- a span that reported one slot where it needs two would be priced
	as buildable and would corrupt a value the day it was built.

	**A string expectation checks the REASON instead**, and exists because
	one of Finding 140's cases cannot fail without it. A store of a value
	the span never defined was refused before that change and is refused
	after it; all that moved is which bucket it is reported in. A case
	asserting the refusal would therefore have passed against the code it
	was written to exercise -- a test nobody could see fail, which is
	Finding 111's rule and the reason this branch is here.
	"""
	failures = 0
	for what, rows, expected in SPAN_CASES:
		instructions = _span(rows)
		positions = {a: i for i, (a, *_r) in enumerate(instructions)}
		why = []
		found = ymm_span(instructions, 0, set(), positions, why=why)
		got = None if found is None else found[2]
		if isinstance(expected, str):
			if found is None and any(expected in reason for reason in why):
				continue
			print(f"selftest: {what}: ymm_span answered "
			      f"{got if got is not None else 'a refusal'} saying "
			      f"{why}, want a refusal naming {expected!r}",
			      file=sys.stderr)
			failures += 1
			continue
		if got != expected:
			print(f"selftest: {what}: ymm_span wanted "
			      f"{got if got is not None else 'nothing'} slot(s), want "
			      f"{expected if expected is not None else 'a refusal'}",
			      file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(SPAN_CASES)} ymm spans, closed and refused "
		      f"with their slot demand")
	return failures


def shadow_selftest():
	"""Prove the shadow is a second region and the depth walk is sound.

	Failures, or 0. See `CALLER_SHADOW` and `rsp_depths`.
	"""
	failures = 0
	for what, rows, expected in SHADOW_CASES:
		got = copy_reaches_home(_addressed(rows), None, CALLER_SHADOW)
		if got != expected:
			print(f"selftest: {what}: the shadow walk said {got}, "
			      f"want {expected}", file=sys.stderr)
			failures += 1
	for what, rows, frame, address, expected in DEPTH_CASES:
		# A frame of zero stands for a function with no unwind data, which
		# is the case `rsp_depths` checks the code agrees with.
		seen, body = rsp_depths(rows, frame, None if not frame else rows[0][0])
		# **A refusal is checked by its reason, not by a missing depth.**
		# Asking `seen.get(address)` for a case that must be refused reads
		# None from a refusal and None from an address the walk simply does
		# not hold, so it passed with the balance check taken out -- caught
		# by sabotaging the check the case exists to prove.
		if isinstance(expected, str):
			if seen is not None or body != expected:
				print(f"selftest: {what}: the walk returned "
				      f"{'a depth map' if seen is not None else repr(body)}, "
				      f"want the refusal {expected!r}", file=sys.stderr)
				failures += 1
			continue
		got = None if seen is None else seen.get(address)
		if got != expected:
			print(f"selftest: {what}: depth at {address:#x} was {got}, "
			      f"want {expected}"
			      f"{'' if seen is not None else f' (refused: {body})'}",
			      file=sys.stderr)
			failures += 1
	for what, rows, depths, refs, pointer in REFERENCE_CASES:
		got, formed = region_references(rows, depths, CALLER_SHADOW)
		if got != refs or formed != pointer:
			print(f"selftest: {what}: region_references said "
			      f"{[hex(a) for a in got]}/{formed}, want "
			      f"{[hex(a) for a in refs]}/{pointer}", file=sys.stderr)
			failures += 1
	# The displacement the shadow needs, against the two encodings it uses.
	for base, want in ((0, "0f110c24"), (0x20, "0f114c2420"),
	                   (0x1234, "0f118c2434120000")):
		got = encode_spill(1, True, 0, 0, 0, base)
		if got is None or got.hex() != want:
			print(f"selftest: a borrow at {base:#x} encoded "
			      f"{got.hex() if got else None}, want {want}",
			      file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(SHADOW_CASES)} shadow reaches, "
		      f"{len(DEPTH_CASES)} rsp depths and "
		      f"{len(REFERENCE_CASES)} shadow references, both directions")
	return failures


def gpr_survey(binary, listing):
	"""How many volatile GPRs are dead at each starved site. Always 0.

	A measurement rather than a gate, and it exists to price static TLS
	before anyone builds it. Finding 139 put that at 67 sites by
	`function_scope`'s whole-function argument -- a function that never
	NAMES a register cannot read it -- and said in the same breath that the
	argument is blunt: it disqualifies a range for any jump leaving it, so
	500 of the 1,332 starved sites are refused for having a tail call
	somewhere rather than for wanting the register. A borrow bracket holds
	one instruction and contains no control transfer at all, so the
	question that fits it is whether the register is dead AT THE SITE.

	Reported by count, because the addressing needs TWO registers at once
	(Finding 139) and one is worth nothing to it.
	"""
	groups = target_set.collect(binary)
	blocked = set()
	for values in groups.values():
		blocked |= values
	instructions = list(parse_with_comments(listing))
	plain = [(a, e, m, o) for a, e, m, o, _c in instructions]
	for address, _e, mnemonic, operands, comment in instructions:
		if mnemonic.startswith(("j", "call", "loop")) and operands:
			field = operands.split()[0]
			if field.startswith("0x"):
				try:
					blocked.add(int(field, 16))
				except ValueError:
					pass
		elif mnemonic == "lea" and isinstance(comment, int) \
				and "(%rip)" in operands:
			blocked.add(comment)
	_p, _c, _s, _sk, declined, home = collect(binary, listing)
	starts, ranges, _usable, _state = home
	scope_starts, scope_free = gpr_function_scope(plain, ranges)

	wanted = sorted(address for address, reason in declined.items()
	                if reason == "no home space to borrow")
	if not wanted:
		print("gprs: no site was declined `no home space to borrow`, so "
		      "there is nothing to price", file=sys.stderr)
		return 2

	cache = {}

	def live_after(i, address):
		"""The volatile GPRs live after `address` in function `i`."""
		if i not in cache:
			start, end = ranges[i]
			first = bisect.bisect_left(plain, (start,))
			last = bisect.bisect_left(plain, (end,), first)
			inside = tuple(position for position in range(first, last)
			               if plain[position][0] in blocked)
			cache[i] = (first, last,
			            gpr_live_out(plain, first, last, inside))
		first, last, live = cache[i]
		at = bisect.bisect_left(plain, (address,), first, last)
		if at >= last or plain[at][0] != address:
			return None
		return live[at]

	counts, per_register, whole = Counter(), Counter(), Counter()
	unplaced, sample = 0, []
	for address in wanted:
		i = bisect.bisect_right(starts, address) - 1
		if i < 0 or address >= ranges[i][1]:
			unplaced += 1
			continue
		live = live_after(i, address)
		if live is None:
			unplaced += 1
			continue
		# The site's own operands are live: a 256-bit load reaching through
		# `(%rax,%rcx,4)` needs both while the stub runs.
		free = (frozenset(VOLATILE_GPRS) - live
		        - gprs_named(plain[bisect.bisect_left(
			        plain, (address,))][3] or ""))
		counts[len(free)] += 1
		for name in free:
			per_register[name] += 1
		# **A number this large has to be checkable by hand.** The
		# whole-function argument reached 57 sites and this reaches 753,
		# and a reader who cannot pick one out and read the disassembly
		# around it has only the tool's word for the difference.
		if len(free) >= 2 and len(sample) < 8:
			sample.append((address, ranges[i], sorted(free)))
		# What the whole-function argument says about the same site, for
		# the comparison this survey exists to make.
		j = bisect.bisect_right(scope_starts, address) - 1
		whole[len(scope_free[j]) if 0 <= j < len(scope_free)
		      and address < ranges[j][1] else 0] += 1

	total = sum(counts.values())
	print(f"sites declined `no home space to borrow` {len(wanted):>10,}")
	print(f"  not inside a known function            {unplaced:>10,}")
	print(f"  priced here                            {total:>10,}")
	print("\nvolatile GPRs dead across the bracket:")
	for many in sorted(counts):
		print(f"  {many}: {counts[many]:>7,}")
	at_least = lambda n: sum(c for k, c in counts.items() if k >= n)
	print(f"\n  at least ONE  {at_least(1):>7,}")
	print(f"  at least TWO  {at_least(2):>7,}   <- what the addressing needs")
	print("\nby register, dead across the bracket:")
	for name in VOLATILE_GPRS:
		print(f"  {name:<4} {per_register[name]:>7,}")
	print("\nwhat the whole-function argument says at the same sites:")
	for many in sorted(whole):
		print(f"  {many}: {whole[many]:>7,}")
	if sample:
		print("\nsites to check by hand, with the function they sit in:")
		for address, (start, end), free in sample:
			print(f"  0x{address:x}  in 0x{start:x}-0x{end:x}  "
			      f"{' '.join(free)}")
	return 0


def span_survey(binary, listing, patched):
	"""How much of the 256-bit residue a closed span could reach. Always 0.

	A measurement rather than a gate, and it exists because Finding 133's
	number was an upper bound on CAPACITY and this is the bound that binds:
	a span is worth nothing unless every value it tracks dies inside it,
	and most of them do not. Re-take it before building anything on the
	scoping figure -- 1,674 sites have room for their upper halves, and 212
	are reachable by a span that closes.
	"""
	groups = target_set.collect(binary)
	blocked = set()
	for values in groups.values():
		blocked |= values
	instructions = list(parse_with_comments(listing))
	plain = [(a, e, m, o) for a, e, m, o, _c in instructions]
	for address, _e, mnemonic, operands, comment in instructions:
		if mnemonic.startswith(("j", "call", "loop")) and operands:
			first = operands.split()[0]
			if first.startswith("0x"):
				try:
					blocked.add(int(first, 16))
				except ValueError:
					pass
		elif mnemonic == "lea" and isinstance(comment, int) \
				and "(%rip)" in operands:
			blocked.add(comment)
	positions = scratch_finder.address_index(plain)
	_p, _c, _s, _sk, _d, home = collect(binary, listing)
	starts, ranges, _usable, _state = home

	survivors = set()
	for address, encoding, _m, _o in inplace.parse_listing(patched):
		vex = inplace.decode_vex(encoding)
		if vex is not None and vex["L"]:
			survivors.add(address)

	def slots(address):
		"""How many 16-byte slots this site's function will lend."""
		i = bisect.bisect_right(starts, address) - 1
		if i < 0 or address >= ranges[i][1]:
			return 0
		total = 0
		if home_space_free(home, address):
			readers = home_readers(home, i)
			if readers is not None and address not in readers:
				total += SLOTS_PER_REGION
		found = shadow_depths(home, i)
		if found is not None:
			seen, shadow_readers = found
			if address not in shadow_readers \
					and seen.get(address) is not None:
				total += SLOTS_PER_REGION
		return total

	# **A per-thread block is as big as it is asked to be.** `slots` above
	# answers for the home space and the caller's shadow, which are 32 bytes
	# each and cannot grow; `SizeOfZeroFill` is a number in a directory, so
	# eleven slots there cost exactly what one costs. What a TLS-backed span
	# pays instead is two general-purpose registers dead across the whole of
	# it -- the same price `--spill=tls` pays per site, asked over a span.
	#
	# Reported as its own column rather than folded in, because the two are
	# different claims: the home space is free and limited, the block is
	# unlimited and costs registers. Finding 143.
	tls_here = tls_for(binary)
	# The whole-function free-register argument, which is what a region's
	# helper is chosen from -- the same blunt rule `span_helper` uses, and
	# the same one Finding 141 sharpened for general-purpose registers and
	# nobody has yet pointed at xmm.
	scope = scratch_finder.function_scope(plain, ranges)
	region_covered, region_refused = set(), Counter()
	region_cache, region_slots, region_cost = {}, Counter(), Counter()
	region_whole = region_emittable = 0
	region_buildable = set()
	region_shapes = Counter()

	covered, refused, fit = set(), Counter(), Counter()
	tls_covered, tls_reason = set(), Counter()
	forms = Counter()
	for index, (address, encoding, _m, _o, _c) in enumerate(instructions):
		if address not in survivors:
			continue
		vex = inplace.decode_vex(encoding)
		if vex is None or not vex["L"]:
			continue
		# **What a region-based rewrite would reach**, asked of every
		# surviving site whether a span takes it or not. A span must begin
		# at a 256-bit load and must close; a region begins where the ABI
		# says every upper half is already dead -- after a call, at a
		# branch target, at a function's first instruction -- and closes
		# for free at the next call, because a later read of an upper half
		# would be reading garbage in the ORIGINAL program too. Finding
		# 147.
		refusal = region_reachable(instructions, index, blocked)
		if refusal is None:
			region_covered.add(address)
			# **What the region would COST**, which is the bound Finding
			# 147 said to take before designing anything on the 3,355.
			# Memoised on the region's first instruction, because a region
			# holds many sites and the demand is the region's.
			begin = region_start(instructions, index, blocked)
			if begin not in region_cache:
				finish = region_end(instructions, begin, blocked)
				extent = instructions[finish - 1][0] \
					+ len(instructions[finish - 1][1]) \
					- instructions[begin][0]
				peak, used = region_demand(instructions, begin, finish)
				at = instructions[begin][0]
				# **Per position, not per function.** `scope_free` asks
				# whether the function names the register ANYWHERE, which
				# over a region of up to 192 instructions is nearly always
				# empty -- Finding 148 measured it at 2,782 of 3,355 sites
				# refused for exactly that. `xmm_live_out` asks whether it
				# is dead at every position the region covers, which is a
				# question about the region rather than about the function.
				# A region that ends at a CALL knows what is live after
				# it: nothing volatile, by the ABI. One that ends at a
				# branch target does not -- control carries on in the same
				# function and anything may be wanted.
				# The collector asks the same question through the same
				# function, which is the whole point of it being one.
				helpers, whole = region_helpers(plain, instructions, begin,
				                                finish, blocked, scope)
				# **Every 256-bit member must be emittable, or none is.**
				# A region is a representation and half of one is a
				# program that reads an upper half nobody wrote, which is
				# `span_operand_shape`'s rule applied to the larger unit.
				shapes = set()
				for position in range(begin, finish):
					name = span_shape_name(instructions[position][1],
					                       instructions[position][3])
					if name is not None:
						shapes.add(name)
				region_cache[begin] = (
					peak, len(helpers), len(whole),
					window_borrow(home, at, extent) is not None,
					len(window_gpr_free(home, at, extent)),
					frozenset(shapes))
			peak, helpers, whole_helpers, frame, gprs, shapes = \
				region_cache[begin]
			if whole_helpers:
				region_whole += 1
			for name in shapes - SPAN_EMITTABLE:
				region_shapes[name] += 1
			emittable = not (shapes - SPAN_EMITTABLE)
			if emittable:
				region_emittable += 1
			region_slots[min(peak, 9)] += 1
			if not helpers:
				region_cost["no xmm free across the region"] += 1
			elif not frame and gprs < 2:
				region_cost["no frame region and fewer than two GPRs"] += 1
			elif peak > TLS_SLOTS and not frame:
				region_cost[f"wants more than {TLS_SLOTS} slots"] += 1
			else:
				region_cost["slots and registers both available"] += 1
				# **The intersection, which is the buildable number.**
				# Emittable and affordable are different populations over
				# the same 3,355, and every earlier figure on this item
				# was one population read as though it were the answer.
				if emittable:
					region_buildable.add(address)
		else:
			region_refused[refusal] += 1
		why = []
		found = ymm_span(instructions, index, blocked, positions, why=why)
		if found is None:
			refused[why[0] if why else "?"] += 1
			if len(why) > 1 and why[1].startswith("form: "):
				forms[why[1][len("form: "):]] += 1
			continue
		members, _end, peak = found
		room = slots(address)
		fit[(peak, min(room, 2 * SLOTS_PER_REGION))] += 1
		if peak <= room:
			for _kind, member, _r in members:
				if instructions[member][0] in survivors:
					covered.add(instructions[member][0])
		# The same span, priced against a per-thread block instead. The
		# registers have to be dead across every instruction the span
		# covers, not merely at its first -- a slot addressed through a
		# register the span itself clobbers is worse than no slot.
		if tls_here is not None and peak > room:
			last_member = instructions[members[-1][1]]
			length = last_member[0] + len(last_member[1]) - address
			free = window_gpr_free(home, address, length)
			if len(free) >= 2:
				tls_reason["a block would fit it"] += 1
				for _kind, member, _r in members:
					if instructions[member][0] in survivors:
						tls_covered.add(instructions[member][0])
			else:
				tls_reason[f"{len(free)} register(s) dead across the span"] \
					+= 1

	if not survivors:
		# **A survey over nothing reports success as loudly as a real
		# one.** The first run of this was handed the rewritten executable
		# where a disassembly was wanted, found no instructions at all, and
		# printed a tidy pair of zeroes above `exit 0`. `patched` is
		# objdump's output, as `census` takes.
		print("spans: no 256-bit site in that listing, so nothing was "
		      "surveyed", file=sys.stderr)
		return 2
	print(f"surviving 256-bit sites          {len(survivors):>8,}")
	print(f"covered by a closed span that fits {len(covered):>6,}")
	print(f"\nwhy no span closed here, {sum(refused.values()):,} in "
	      f"{len(refused)} reason(s), the 8 commonest:")
	for reason, count in refused.most_common(8):
		print(f"  {count:>7,}  {reason}")
	if forms:
		# **The total is printed because the rows are truncated.** The
		# reason buckets above carry a register name, so "not lane-wise"
		# was never one line but one per register, and reading the top of
		# that list as the whole of it is how project.md came to quote 171
		# for a population half again as large. A histogram that shows its
		# head must say what the head is a head OF. Finding 140.
		shown = forms.most_common(20)
		print(f"\n256-bit forms that stopped a span, {sum(forms.values()):,} "
		      f"in {len(forms)} form(s), the {len(shown)} commonest:")
		for name, count in shown:
			print(f"  {count:>7,}  {name}")
	print("\nclosed spans, slots wanted against slots available:")
	for (peak, room), count in sorted(fit.items()):
		print(f"  wants {peak}, has {room}: {count:>6,}"
		      f"{'  fits' if peak <= room else ''}")
	print(f"\nwhat a call-free REGION would reach, span or no span:")
	print(f"  every ymm it reads defined in its own region  "
	      f"{len(region_covered):>6,}")
	for reason, count in region_refused.most_common(6):
		print(f"  {count:>7,}  {reason}")
	print("\n  upper halves live at once in the region, by site:")
	for many in sorted(region_slots):
		print(f"    {many}{'+' if many == 9 else ' '}: "
		      f"{region_slots[many]:>6,}")
	print("\n  and what the region can afford:")
	for reason, count in region_cost.most_common():
		print(f"    {count:>7,}  {reason}")
	print(f"\n  a helper by the WHOLE-FUNCTION rule       {region_whole:>6,}")
	print(f"  a helper by per-position liveness         "
	      f"{sum(c for r, c in region_cost.items() if 'no xmm' not in r):>6,}")
	print(f"\n  every 256-bit member a shape the lowering emits "
	      f"{region_emittable:>6,}")
	print("  what the rest would need built, by site:")
	for name, count in region_shapes.most_common(10):
		print(f"    {count:>7,}  {name}")
	print(f"\n  BUILDABLE: emittable AND affordable        "
	      f"{len(region_buildable):>6,}")
	if tls_here is not None:
		print("\nspans that do NOT fit the home space, priced against a "
		      "per-thread block:")
		for reason, count in tls_reason.most_common():
			print(f"  {count:>7,}  {reason}")
		print(f"\ncovered by a span the home space fits   {len(covered):>6,}")
		print(f"  and by one only a block fits          "
		      f"{len(tls_covered - covered):>6,}")
		print(f"  both                                  "
		      f"{len(covered | tls_covered):>6,}")
	return 0


def census(binary, listing, patched):
	"""Reconcile what survives against what the rewriter declined.

	project.md carried this as an open question, and the honest answer turned
	out not to be a missing counter. **The skip tallies and the survivor
	count measure different populations**, and subtracting one from the other
	was the mistake:

	  * a site the collector declines can still be lowered, because a
	    neighbour's widened window swallows it and the stub lowers it there;
	  * a site it accepts can still survive, because the stub could not be
	    built or the window overlapped one already committed;
	  * and the survivor count comes from a fresh linear sweep of rewritten
	    bytes, which is authoritative only where the code oracle vouches for
	    it -- elsewhere the sweep can manufacture or hide a VEX prefix that
	    was never an instruction.

	So this compares the actual address sets instead of the totals, and
	prints what falls in each part rather than a single number that hides
	three effects at once.

	It reconciles exactly, and getting there refuted two guesses. The first,
	that declined sites were being swallowed by a neighbour and lowered in a
	stub, is wrong: not one of them is inside a committed window. The
	second, that the leftovers were the disassembler inventing VEX prefixes
	in bytes it had desynchronised on, is also wrong: **every survivor was an
	instruction boundary and a VEX site in the original**, all 3,548 of them.

	What was actually wrong was this function. A window is a range and, for
	one widened backwards, it does not start at the site -- so testing a
	surviving address against a set of window *starts* missed every site
	whose window began on the instruction before it.
	"""
	# **An empty parse and a clean image are the same output.** The third
	# argument is a LISTING of the rewritten binary, and handing this the
	# binary itself makes `parse_listing` yield nothing -- whereupon every
	# count below is zero and the tool reports a finished translator. That
	# is the vacuous pass in the one place whose whole job is to say what
	# is left, so it refuses rather than reporting a total over an empty
	# set. Finding 261.
	lines = list(inplace.parse_listing(patched))
	if not lines:
		raise SystemExit(
			f"census: {patched} parsed to no instructions. It wants a "
			f"disassembly of the rewritten binary -- "
			f"`objdump -d -j .text <patched.exe>` -- rather than the "
			f"binary itself.")
	context = analysis_context(binary, listing)
	instructions, _plain, blocked, sources, _tables, _seen = context
	patches, candidates, _stats, _skipped, declined, home = collect(
		binary, listing, context)

	# **This placed the stubs itself and did not run the repair, so it was
	# reconciling against an image nobody builds.** `apply` withholds every
	# window whose lowering would leave a surviving 256-bit read of an upper
	# half no longer in its register -- 277 of them under the uniform
	# representation -- and those windows are not in the artifact. Counting
	# their sites as "inside a committed window" asserted a commitment the
	# computation never checked, and it is why 278 of the survivors carried
	# a label that could not be true of them.
	#
	# This is Finding 197 exactly, in a third tool. That finding fixed the
	# same drift between `apply` and `verify`, and its own note says a
	# promise in a comment is not a mechanism -- so `census` goes through
	# the one function too, rather than through a second copy of the
	# placement that is correct until somebody changes the first.
	# Finding 261.
	stub_base = stub_base_of(open(binary, "rb").read())
	spill_base = 0
	if SPILL == SPILL_POOL:
		spill_base = stub_base
		stub_base += SECTION_ALIGNMENT
	unrepaired, _b, _sw, _ov, _rf = place_stubs(
		candidates, stub_base, spill_base, Counter(), home=home,
		tls=tls_pair_of(tls_for(binary)))
	placed, _blob, overlapped, refused, dropped, swallowed = \
		repaired_placement(instructions, blocked, sources, candidates,
		                   {address for address, *_rest in patches},
		                   stub_base, spill_base, Counter(), home,
		                   tls_pair_of(tls_for(binary)))
	rewritten = {address for address, _window, *_rest in placed}
	covered = set()
	for address, window, *_rest in placed:
		covered.update(range(address, address + window))
	# What the repair cost, as a set rather than as a count: a window it
	# withheld is a window whose sites are still VEX, and they belong in a
	# bucket that says so instead of falling out as unaccounted.
	# **From the candidates, not from a placement.** This read `unrepaired`
	# -- the placement taken with the repair switched off -- and a window
	# the repair later dropped is not necessarily IN that placement: if
	# something overlapped it there, it contributes no range at all and its
	# sites fall out as unaccounted. 85 of them did, every one flagged as
	# both inside a candidate span and dropped.
	#
	# A dropped window's extent is a property of the candidate, which is
	# where it is now read from. Finding 282.
	withheld = set()
	for start, _e, _o, _m, window, *_r in candidates:
		if start in dropped:
			withheld.update(range(start, start + window))

	# **`apply` also REVERTS, and this did not model that either.** A
	# patch whose zeroing a surviving 256-bit instruction still reads is
	# put back as it was, so the site is VEX in the artifact while being
	# neither declined, refused, windowed nor overlapped -- it fell out as
	# unaccounted. Same root as the bucket above: a second copy of what
	# `apply` does, kept correct by nobody. Finding 261.
	stale, _unresolved, unsure = stale_upper_reads(
		instructions, blocked, sources, placed,
		{address for address, *_rest in patches}, conservative=True)
	undone = {address for address, *_rest in patches}
	reverted = {producer for _reader, _field, producer in stale + unsure
	            if producer in undone and producer not in covered}

	# **One definition of a surviving VEX, shared with `verify`.** This
	# selected on the first byte, so 180 sequences that decode to nothing
	# counted as survivors here and in the frontier both. They are reported
	# below rather than dropped. Finding 290.
	survivors = {a for a, e, m, _o in lines
	             if e[:1] in (b"\xc4", b"\xc5") and m != "(bad)"}
	undecoded_now = {a for a, e, m, _o in lines
	                 if e[:1] in (b"\xc4", b"\xc5") and m == "(bad)"}

	print(f"declined by the collector      {len(declined):>10,}")
	print(f"  of those, swallowed anyway   "
	       f"{len(set(declined) & covered):>10,}")
	print(f"accepted as candidates         {len(candidates):>10,}")
	print(f"  detoured                     {len(rewritten):>10,}")
	print(f"  skipped, window overlapped   {len(overlapped):>10,}")
	print(f"  refused, stub not buildable  {len(refused):>10,}")
	print(f"instructions swallowed         {len(swallowed):>10,}")
	print()
	print(f"VEX in the rewritten .text     {len(survivors):>10,}")
	# **A window is a range, not an address, and for a backward-widened one
	# the start is not the site.** Recording only the start and then asking
	# whether a surviving instruction is in that set misses every site whose
	# window began on the instruction before it -- which is what made 1,102
	# of these look unaccounted when they were plainly refused.
	# **Read what was placed, not what was collected.** `REPAIR_FINAL` is
	# the list the repair handed to `place_stubs`, so a window the repair
	# rebuilt is found under the start it was actually refused at. Reading
	# `candidates` here missed every substituted one. Finding 282.
	def spread(starts):
		out = set()
		for start, _e, _o, _m, window, _d, _s, _p, _strategy in (
				REPAIR_FINAL or candidates):
			if start in starts:
				out.update(range(start, start + window))
		return out

	# The collector never sees these -- and since Finding 223 that is a rule
	# rather than an accident. They are objdump's `(bad)` lines, bytes it
	# could not decode rather than instructions, and both the candidate loop
	# and the in-place path now refuse them on the mnemonic.
	#
	# **Selecting them by `decode_vex` found 81 of Starfield's 180.** That
	# test rejects on LENGTH alone -- under three bytes, or a `c4` under
	# four -- so the 99 longer sequences passed it, and the claim above was
	# false for exactly those until the guard existed. Select on the thing
	# that decides.
	undecodable = {a for a, e, m, _o in inplace.parse_listing(listing)
	               if m == "(bad)" and e[:1] in (b"\xc4", b"\xc5")}

	buckets = (("declined by the collector", set(declined)),
	           ("refused, stub not buildable", spread(refused)),
	           ("inside a committed window", covered),
	           ("in a window the repair dropped", withheld),
	           ("in-place patch reverted", reverted),
	           ("skipped for overlap", spread(overlapped)))
	accounted = set()
	for label, group in buckets:
		hit = (survivors & group) - accounted
		accounted |= hit
		print(f"  {label:<30}{len(hit):>10,}")
	rest = survivors - accounted
	print(f"  {'unaccounted':<30}{len(rest):>10,}")
	print(f"and {len(undecoded_now):,} VEX-prefixed sequence(s) that decode to "
	      f"nothing, which are not instructions and are not counted above "
	      f"({len(undecodable):,} of them in the original)")
	if rest:
		print("  -- unaccounted, and that should be zero. Every survivor was")
		print("     an instruction boundary and a VEX site in the original,")
		print("     so none of it is the disassembler inventing one.")
	return 0


def version():
	"""The project, its version and who holds the copyright.

	**The first line is the parseable one and keeps its shape**, with the
	attribution on a line of its own -- apt-emerge's shape, and its
	caution: a version string with a stable format is an interface, so
	appending to it changes that interface. Nothing consumes this one yet,
	which is the moment to get it right rather than after.

	**The attribution covers this rewriter and its tooling, and nothing
	else.** anti-avx exists to modify somebody else's binary, and naming
	the holder here says who wrote the tool; it says nothing whatever
	about the artifact the tool emits, in which this project holds no
	copyright and claims none.

	The number comes from `VERSION`, which until now nothing read.
	"""
	release = HERE.parent / "VERSION"
	number = release.read_text().strip() if release.is_file() else "unknown"
	return (f"anti-avx {number}\n"
	        f"Copyright (C) 2026 Nabeel Sowan <nabeel@vibes.se>")


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	if argv[0] in ("-V", "--version"):
		print(version())
		return 0
	# `--spill=` selects where a borrowed register is saved, and it is an
	# evaluation switch rather than a tuning knob: the default refuses the
	# site, as it always has, and the other two exist so that all three can
	# be built and compared. See Finding 46.
	global SPILL, RSP_RULE, SHADOW_RULE, REGION_RULE, ESCAPE_RULE
	global REGION_PLACE, FALLBACK_RULE, SHADOW_REGS_RULE, TEB_SCRATCH
	global INDEX_CONST
	argv = list(argv)
	for i, item in enumerate(argv):
		if item.startswith("--escape="):
			ESCAPE_RULE = item.split("=", 1)[1]
			if ESCAPE_RULE not in (ESCAPE_REFUSE, ESCAPE_ALLOW):
				print(f"detour.py: unknown escape rule {ESCAPE_RULE!r}",
				      file=sys.stderr)
				return 2
			del argv[i]
			break
	for i, item in enumerate(argv):
		if item.startswith("--region="):
			REGION_RULE = item.split("=", 1)[1]
			if REGION_RULE not in (REGION_WHOLE, REGION_LIVE):
				print(f"detour.py: unknown region rule {REGION_RULE!r}",
				      file=sys.stderr)
				return 2
			del argv[i]
			break
	for i, item in enumerate(argv):
		if item.startswith("--shadow-regs="):
			want = item.split("=", 1)[1]
			if want not in (SHADOW_REGS_OFF, SHADOW_REGS_ALL):
				print(f"detour.py: --shadow-regs wants off or all, "
				      f"not {want!r}", file=sys.stderr)
				return 2
			SHADOW_REGS_RULE = want
			del argv[i]
			break
	for i, item in enumerate(argv):
		if item.startswith("--index-const="):
			want = item.split("=", 1)[1]
			if want not in ("on", "off"):
				print(f"detour.py: --index-const wants on or off, "
				      f"not {want!r}", file=sys.stderr)
				return 2
			INDEX_CONST = want == "on"
			del argv[i]
			break
	for i, item in enumerate(argv):
		if item.startswith("--teb-scratch="):
			want = item.split("=", 1)[1]
			if want in ("auto", "off"):
				# **`off` is the A/B and exists because `auto` is now
				# the default.** Every default this tool has taken has
				# kept the previous behaviour reachable -- `--index-
				# const=off`, `--shadow-regs=off` -- because a default
				# whose alternative cannot be run is a measurement
				# nobody can repeat. Finding 309.
				TEB_SCRATCH = None if want == "off" else "auto"
				del argv[i]
				break
			try:
				offset = int(want, 0)
			except ValueError:
				print(f"detour.py: --teb-scratch wants a number, "
				      f"not {want!r}", file=sys.stderr)
				return 2
			# **No default and a named offset, because the bytes belong to
			# somebody.** The checks below refuse the two fields this tool
			# knows are in use and nothing else -- they cannot establish
			# that an offset is free, only that it is not obviously taken.
			# Whose the rest are is the open half of Finding 280.
			if offset <= 0 or offset % 8:
				print("detour.py: --teb-scratch wants a positive multiple "
				      "of 8", file=sys.stderr)
				return 2
			if offset + TEB_SCRATCH_BYTES > 0x1800:
				print("detour.py: --teb-scratch would run past the TEB",
				      file=sys.stderr)
				return 2
			for low, name in ((0x30, "the TEB self-pointer"),
			                  (TEB_TLS_POINTER, "ThreadLocalStoragePointer")):
				if offset < low + 8 and low < offset + TEB_SCRATCH_BYTES:
					print(f"detour.py: --teb-scratch 0x{offset:x} overlaps "
					      f"{name} at 0x{low:x}", file=sys.stderr)
					return 2
			TEB_SCRATCH = offset
			del argv[i]
			break
	for i, item in enumerate(argv):
		if item.startswith("--fallback="):
			FALLBACK_RULE = item.split("=", 1)[1]
			if FALLBACK_RULE not in (FALLBACK_OFF, FALLBACK_ON):
				print(f"detour.py: unknown fallback rule {FALLBACK_RULE!r}",
				      file=sys.stderr)
				return 2
			del argv[i]
			break
	for i, item in enumerate(argv):
		if item.startswith("--shadow="):
			SHADOW_RULE = item.split("=", 1)[1]
			if SHADOW_RULE not in (SHADOW_OFF, SHADOW_ON):
				print(f"detour.py: unknown shadow rule {SHADOW_RULE!r}",
				      file=sys.stderr)
				return 2
			del argv[i]
			break
	for i, item in enumerate(argv):
		if item.startswith("--rsp="):
			RSP_RULE = item.split("=", 1)[1]
			if RSP_RULE not in (RSP_BLANKET, RSP_FOLLOWED):
				print(f"detour.py: unknown rsp rule {RSP_RULE!r}",
				      file=sys.stderr)
				return 2
			del argv[i]
			break
	for i, item in enumerate(argv):
		if item.startswith("--region-place="):
			REGION_PLACE = item.split("=", 1)[1]
			if REGION_PLACE not in (REGION_EARLY, REGION_MID, REGION_LATE):
				print(f"detour.py: unknown region place {REGION_PLACE!r}",
				      file=sys.stderr)
				return 2
			del argv[i]
			break
	for i, item in enumerate(argv):
		if item.startswith("--spill="):
			SPILL = item.split("=", 1)[1]
			if SPILL not in (SPILL_NONE, SPILL_STACK, SPILL_POOL,
			                 SPILL_HOME, SPILL_TLS):
				print(f"detour.py: unknown spill {SPILL!r}", file=sys.stderr)
				return 2
			del argv[i]
			break
	mode = argv[0]

	if mode == "selftest":
		return selftest()

	if mode == "census":
		return census(argv[1], argv[2], argv[3])

	if mode == "gprs":
		return gpr_survey(argv[1], argv[2])

	if mode == "spans":
		return span_survey(argv[1], argv[2], argv[3])

	if mode == "plan":
		_patches, candidates, stats, skipped, declined, _home = \
			collect(argv[1], argv[2])
		print(f"detour candidates (A/B/C) {len(candidates):>10,}")
		# **A refusal inside an accepted window is not a residue.** A run is
		# anchored at its load and its window reaches through the store, so
		# the loop meets that store again and declines it on its own
		# account -- 9,100 sites sat in `ymm value has no known upper half`
		# that a run was about to lower, and the counter read as work
		# remaining. It is not dropped from the collector, because a site
		# inside a window whose stub later fails to build still deserves its
		# own chance and taking that away cost 409 sites when tried. It is
		# subtracted HERE, where the question is what is left rather than
		# what was decided.
		covered = set()
		for start, _e, _o, _m, window, *_rest in candidates:
			covered.update(range(start, start + window))
		outside_windows = Counter()
		for address, reason in declined.items():
			if address not in covered:
				outside_windows[reason] += 1
		for reason, count in skipped.most_common():
			left = outside_windows.get(reason, 0)
			note = "" if left == count else f"   ({left:,} outside any window)"
			print(f"  skipped, {reason:<24} {count:>10,}{note}")
		print(f"\nnot inside any accepted window "
		      f"{sum(outside_windows.values()):>10,}")
		print(f"stub bytes (estimate)     {len(candidates) * 15:>10,}")
		return 0

	if mode == "apply":
		return apply_all(argv[1], argv[2], argv[3])

	if mode == "verify":
		return verify(argv[1], argv[2], argv[3] if len(argv) > 3 else None)

	if mode == "sabotage":
		return sabotage(argv[1], argv[2], argv[3])

	if mode == "sources":
		return source_census(argv[1], argv[2])

	if mode == "frontier":
		return frontier_census(argv[1], argv[2], argv[3])

	if mode == "chains":
		return chain_census(argv[1], argv[2], argv[3])

	if mode == "spills":
		return spill_census(argv[1], argv[2])

	print(f"detour.py: unknown mode {mode!r}", file=sys.stderr)
	return 2


# How far apart two undecodable bytes may be and still be called one data
# island. 256 is `vex_scan`'s figure, kept so the two agree about what an
# island is rather than each having its own idea. Finding 224.
ISLAND_GAP = 256

# Sabotage kinds that break the COLLECTOR rather than an image, so an
# unchanged output is correct for them and an error for everything else.
CODE_KINDS = ("badrow", "staleupper", "conservative", "switchbase")

# **Controls for the checks no broken IMAGE can express.** `sabotage`
# corrupts an artifact, which is enough for a check that reads bytes: the
# stub section, the sections after `.text`, the data islands. Those are
# three of `verify`'s seventeen. The rest test the COLLECTOR's decisions,
# and no image can make a `(bad)` row reach the candidate loop or make a
# repair fail to happen -- so fourteen checks had never been watched
# failing, which by Finding 196's rule is a green light.
#
# Each value here disables exactly one guard, so the gate can run `apply`
# with it and watch `verify` reject the result. Read once, at import, so
# no hot path pays for it, and named in `SABOTAGE` beside the image kinds
# so the two are found together. Finding 231.
CODE_SABOTAGE = os.environ.get("ANTI_AVX_SABOTAGE", "")

# **Both of these have to force the TEB path, and the first attempt at
# `tebconst` did not.** It emptied the patch tables and left the forcing
# condition naming `teb` alone, so the control built a stub that saved to
# the callee home space -- an image with no TEB write in it at all -- and
# returned 77 exactly as the good one did. Read as a passing control it
# would have said `%gs:0x5b5b5b00` was harmless; what it actually said is
# that the sabotage had not applied. A control has to fail through the
# check it is testing. Finding 297.
FORCE_TEB = ("teb", "tebconst")

SABOTAGE = {
	# name: (which check must reject it, what is broken)
	"stubvex": "the stub section holds no VEX",
	"section": "every section after .text is byte-identical",
	"island": "no byte inside a data island was modified",
	# Code sabotages, set through ANTI_AVX_SABOTAGE rather than written
	# into an image -- see CODE_SABOTAGE for why these cannot be artifacts.
	"notable": "the exception directory points at a function table",
	"unsorted": "the function table is sorted",
	"nostub": "the stub section is present",
	"stubgap": "every stub byte lies inside a function table entry",
	"stubcall": "the stub section holds no call",
	"stubbad": "every byte of stub decodes to an instruction",
	"badrow": "no (bad) row reaches the candidate loop",
	"staleupper": "the repair withholds what would ship a stale upper half",
	"conservative": "a conservative candidate keeps its VEX form",
	"switchbase": "a recognised switch dispatch resolves its table",
	"teb": "a block borrows the callee home space, not the TEB",
	"tebconst": "the callback fills in every TEB scratch displacement",
	"indexconst": "the index callback fills every placeholder in",
	"backtarget": "a window widened backwards never buries a branch target",
}


def sabotage(patched, output, kind):
	"""Write a deliberately broken copy of a rewritten image. 0, or 2.

	**A verifier nobody has watched fail is a green light.** Finding 188's
	`verify` rebound its own parameter, raised `TypeError`, and aborted
	before its last two checks -- and no gate noticed, because nothing ran
	it. `make check-verify` runs it over all 35 PE fixtures now, and this
	is what stops that being 35 vacuous passes.

	The two kinds are chosen for WHERE they fail, not for what they break.
	`section` trips an early check and `stubvex` trips one of the last, so
	a `verify` that dies in the middle passes neither -- which is exactly
	the failure that shipped. Finding 196.
	"""
	if kind not in SABOTAGE:
		print(f"detour.py: unknown sabotage {kind!r}, want one of "
		      f"{', '.join(sorted(SABOTAGE))}", file=sys.stderr)
		return 2
	original_bytes = open(patched, "rb").read()
	data = bytearray(original_bytes)
	if kind == "stubvex":
		# `c5 fc 10 06` is `vmovups (%rsi),%ymm0` -- a VEX prefix in the one
		# section this whole rewrite exists to keep free of them.
		found = section_named(bytes(data), SECTION_NAME)
		if found is None:
			print("detour.py: no stub section to sabotage", file=sys.stderr)
			return 2
		_vaddr, _vsize, raddr, rsize = found
		if rsize < 4:
			print("detour.py: stub section is too small to sabotage",
			      file=sys.stderr)
			return 2
		data[raddr:raddr + 4] = bytes.fromhex("c5fc1006")
	elif kind == "section":
		# **`elif`, not `else`.** This was a catch-all, so every kind added
		# after it -- `island` first -- silently performed the section
		# sabotage as well as its own, and tripped the section check for a
		# reason that had nothing to do with what it was testing. Measured
		# by asking which checks each control actually fires: `island` flips
		# two bytes, 0x433 in `.text` and 0x600 in the section after it.
		# A control that fails for two reasons is not a control for either.
		# Finding 234.
		#
		# Any section after `.text`: the check is about all of them, and the
		# fixtures do not all carry the same ones. The stub section is
		# skipped because it is APPENDED rather than carried over, so it is
		# not one of the sections that must be byte-identical.
		stub = section_named(bytes(data), SECTION_NAME)
		after = [(r, rs) for _v, _vs, r, rs in sections_of(bytes(data))[1:]
		         if rs and not (stub and r == stub[2])]
		if not after:
			print("detour.py: no section after .text to sabotage",
			      file=sys.stderr)
			return 2
		raddr, _rsize = after[0]
		data[raddr] ^= 0xFF
	if kind == "island":
		# Flip a byte objdump could not decode. Those are Finding 8's data
		# islands, and the rewrite must never touch one. The address is
		# read out of the PATCHED image, which is sound because an
		# untouched island holds the same bytes at the same addresses in
		# both -- and if that were false the check would already be
		# failing for real.
		done = subprocess.run(["objdump", "-d", "-j", ".text", patched],
		                      capture_output=True, text=True,
		                      errors="replace")
		spot = None
		for line in done.stdout.splitlines():
			field = line.split("\t")
			if len(field) < 3 or not field[2].startswith("(bad)"):
				continue
			head = field[0].strip()
			if not head.endswith(":"):
				continue
			try:
				spot = int(head[:-1], 16)
			except ValueError:
				continue
			break
		if spot is None:
			print("detour.py: no undecodable byte to sabotage",
			      file=sys.stderr)
			return 2
		vaddr, raddr, _size = inplace.text_mapping(patched)
		data[raddr + (spot - vaddr)] ^= 0xFF
	if kind in ("notable", "unsorted", "nostub", "stubgap", "stubcall",
	            "stubbad"):
		# **The unwinder checks, which are an if/elif chain**, so each needs
		# its own kind: only the first failing condition is ever reported.
		# Finding 46 measured what their absence costs -- an exception
		# raised in a stub is never dispatched at all -- and until now
		# nothing had watched any of them fail. Finding 235.
		pe = struct.unpack_from("<I", bytes(data), 0x3C)[0]
		where = pe + 24 + 112 + EXCEPTION_DIRECTORY * 8
		rva, size = struct.unpack_from("<II", bytes(data), where)
		if kind == "notable":
			struct.pack_into("<II", data, where, 0, 0)
		elif kind == "nostub":
			found = section_named(bytes(data), SECTION_NAME)
			if found is None:
				print("detour.py: no stub section to hide", file=sys.stderr)
				return 2
			at = bytes(data).find(SECTION_NAME)
			data[at:at + len(SECTION_NAME)] = b".gone\0\0\0"
		else:
			at = rva_to_offset(bytes(data), rva) if rva and size else None
			if at is None or size < 24:
				print("detour.py: no function table to sabotage",
				      file=sys.stderr)
				return 2
			if kind == "unsorted":
				# Swap the last two entries: a binary search over an
				# unsorted table finds the wrong stub, or none.
				last = at + (size // 12 - 1) * 12
				before = at + (size // 12 - 2) * 12
				one = bytes(data[before:before + 12])
				data[before:before + 12] = data[last:last + 12]
				data[last:last + 12] = one
			elif kind == "stubgap":
				# Shrink the last entry, leaving stub bytes no entry covers.
				last = at + (size // 12 - 1) * 12
				begin, end, unwind = struct.unpack_from("<III", bytes(data),
				                                        last)
				struct.pack_into("<III", data, last, begin,
				                 max(begin, end - 4), unwind)
			elif kind == "stubbad":
				# `06` is `push es`, deleted in 64-bit mode, so objdump
				# renders it `(bad)`. Chosen over a malformed VEX on
				# purpose: a `c4` with an illegal map would also be counted
				# by the stub-VEX check, and a control that fails two checks
				# is a control for neither -- Finding 234.
				found = section_named(bytes(data), SECTION_NAME)
				if found is None or found[3] < len(PERMIL_POOL) + 4:
					print("detour.py: stub section too small to corrupt",
					      file=sys.stderr)
					return 2
				_v, _vs, raw, _rs = found
				at = raw + len(PERMIL_POOL)
				data[at:at + 4] = b"\x06\x06\x06\x06"
			else:			# stubcall
				found = section_named(bytes(data), SECTION_NAME)
				if found is None or found[3] < len(PERMIL_POOL) + 5:
					print("detour.py: stub section too small for a call",
					      file=sys.stderr)
					return 2
				_v, _vs, raw, _rs = found
				at = raw + len(PERMIL_POOL)
				data[at:at + 5] = b"\xe8\x00\x00\x00\x00"
	# **A sabotage that did not apply and a check that cannot fail are
	# indistinguishable from the output**, which is `evidence.md`'s rule and
	# was met here rather than quoted: `stubbad` was added to the dispatch
	# and not to the tuple guarding it, so it wrote an unmodified copy and
	# announced that its property "must now be false". The gate would have
	# caught it -- verify passes, the control fails -- but the sabotage had
	# no way to know, and the next one might be added the same way. An image
	# kind that changes nothing is now an error. Finding 236.
	if kind not in CODE_KINDS and bytes(data) == original_bytes:
		print(f"detour.py: the {kind} sabotage changed nothing",
		      file=sys.stderr)
		return 2
	with open(output, "wb") as image:
		image.write(bytes(data))
	print(f"sabotage: {kind} -- {SABOTAGE[kind]} must now be false")
	return 0


def repaired_placement(instructions, blocked, sources, candidates, patched,
                       stub_base, spill_base, stub_reasons, home, tls):
	"""Place the stubs, withholding the windows that would ship wrong bytes.

	Returns `(placed, blob, overlapped, refused, dropped, swallowed)`.

	**A window that swallows a VEX.128 write loses its upper-half zeroing,
	and reverting cannot reach it.** The passenger is re-emitted inside the
	stub as legacy SSE, so there is nothing on disk to put back and Finding
	187's repair has no purchase. The only fix is not to place that window:
	it costs the site and keeps the bytes right, which is 187's trade one
	layer out.

	It iterates because dropping a window un-swallows everything it
	covered, which can make a reader that was inside it survive and expose
	a producer of its own. Bounded by `REPAIR_ROUNDS`, and the candidate
	list only shrinks.

	**This is one function because the first version was not.** `apply`
	grew the repair and `verify` did not, so `verify` went on placing the
	eight windows `apply` withheld and reported 15 stale reads the image
	does not have -- against a comment on its own `place_stubs` call saying
	"the same call apply makes, so the two cannot drift apart". A promise
	in a comment is not a mechanism. Finding 197.
	"""
	global REPAIR_SUBSTITUTED
	dropped, swapped = set(), {}
	# The strategy and the site count are properties of the ORIGINAL
	# candidate, and `dropped` is keyed by its start, so both are read
	# once here rather than from whatever shape the loop ended on.
	# **`strategy[0]`, the way `build_stub` reads it.** The field is a
	# tuple whose head names the kind, or None where the plain rules
	# sufficed -- so the whole tuple is unhashable and cannot key a
	# Counter. Taking `item[8]` whole worked on the one fixture that
	# drops a window, whose strategy is None, and died on Starfield at
	# the first candidate carrying a real one. A field's shape read off
	# a single fixture is a sample of one. Finding 298.
	strategy_of = {item[0]: (item[8][0] if item[8] is not None
	                         else "(no strategy)") for item in candidates}
	# Sites, not windows, because a window is not a unit of loss: the
	# census counts what survives in .text and one dropped window can
	# hold one site or a dozen. `bisect` over a sorted address list
	# rather than a scan per window, which at this candidate count is
	# the difference between seconds and minutes.
	vex_at = sorted(row[0] for row in instructions
	                if row[1][:1] in (b"\xc4", b"\xc5"))
	def sites_in(start, window):
		left = bisect.bisect_left(vex_at, start)
		return bisect.bisect_left(vex_at, start + window) - left
	sites_of = {item[0]: sites_in(item[0], item[4]) for item in candidates}
	width_of = {item[0]: item[4] for item in candidates}
	REPAIR_BLAME_WHERE.clear()
	REPAIR_SPLITTABLE.clear()
	REPAIR_READERS.clear()
	REPAIR_EXCLUDED.clear()
	REPAIR_BLAMED_BY.clear()
	REPAIR_DROPPED_WHY.clear()
	REPAIR_DROPPED_SITES.clear()
	# Per window: the rungs already spent on it, the blame it has
	# accumulated, and the ladder's answers cached so it is walked once.
	spent, seen_blame = defaultdict(set), defaultdict(set)
	offers = {}
	REPAIR_SUBSTITUTED = 0
	settled = False
	REPAIR_DECAY.clear()
	for _round in range(REPAIR_ROUNDS):
		# **Everything is keyed by the ORIGINAL candidate's start.** A
		# substitute is a different window with a different start, so
		# keying on the current one lets a substitute's start collide
		# with some other candidate's -- and then `dropped` filters out
		# the wrong window, or a guilty one reads as already handled and
		# the loop settles with it still placed. The first version did
		# exactly that and shipped 186 stale reads. Finding 281.
		keep, origin = [], {}
		for item in candidates:
			if item[0] in dropped:
				continue
			use = swapped.get(item[0], item)
			origin[use[0]] = item[0]
			keep.append(use)
		placed, _blob, _swallowed, _over, _refused = place_stubs(
			keep, stub_base, spill_base, Counter(), home=home, tls=tls)
		stale, _unresolved, unsure = stale_upper_reads(
			instructions, blocked, sources, placed, patched,
			conservative=True)
		stale = stale + unsure
		covers = {}
		for site, window, _stub, _size, _prologue in placed:
			for address in range(site, site + window):
				covers[address] = site
		# **Inside a window outranks being an in-place patch.** This said
		# `and producer not in patched`, on the assumption that a patched
		# producer would be repaired by Finding 187's revert. It is not:
		# `apply` reverts into `data` and THEN writes the jump and its
		# padding over the window, so a revert inside a window is
		# overwritten seconds later and nothing says so. Three readers of
		# %ymm7 shipped that way, all from one `vmovss` that was both
		# patched and swallowed. A producer inside a window is guilty
		# whatever else is true of it. Finding 197.
		# **Who is doing the blaming.** A window is withheld because a
		# surviving 256-bit instruction still reads an upper half it
		# would zero -- and every surviving instruction is itself a
		# frontier site, with its own reason for being one. If those
		# readers are concentrated in a class already called a floor,
		# that floor is not costing only its own sites: it is holding
		# windows hostage too, and the classes are not independent the
		# way the census's buckets make them look. Finding 300.
		REPAIR_READERS.update(reader for reader, _f, producer in stale
		                      if producer in covers)
		# **And WHICH window each one blamed**, because the reader set
		# alone cannot say what releasing a class would buy. 553 of the
		# 903 readers are themselves sites in withheld windows and 197
		# are the FMA class, so the buckets are a dependency graph
		# rather than a partition -- and the question a leverage
		# argument needs is how many windows are blamed ONLY by a class,
		# which needs the edges. Finding 300.
		for reader, _f, producer in stale:
			if producer in covers:
				REPAIR_BLAMED_BY[origin[covers[producer]]].add(reader)
		guilty = {origin[covers[producer]]
		          for _reader, _field, producer in stale
		          if producer in covers}
		if CODE_SABOTAGE == "staleupper":
			guilty = set()		# the repair keeps nothing: see CODE_SABOTAGE
		# **`guilty`, not `guilty - dropped`.** A guilty window is by
		# construction one that is PLACED, so subtracting the dropped set
		# was always a no-op -- until substitution made a start able to
		# appear in both, at which point it silently declared the repair
		# settled with a guilty window in the image.
		if not guilty:
			settled = True
			break
		fresh = guilty
		REPAIR_DECAY.append(len(fresh))
		# **A window is dropped for ONE instruction it swallowed, and the
		# ladder can usually build a window that does not swallow it.**
		# Before this the whole candidate was lost, which on Starfield was
		# 1,318 windows and 1,364 surviving sites -- half the frontier and
		# larger than every refusal put together.
		#
		# Substitution is tried once per window and the alternative must
		# cover NONE of the producers this round blamed it for. Where none
		# fits, it is dropped exactly as before, so the correctness
		# argument is unchanged: what ships is still a window nothing
		# blames. What changes is how much is thrown away to get there.
		#
		# **Once, so the loop still terminates.** A substitute's start
		# differs from the original's and `UNIT_ALTERNATIVES` is keyed by
		# the original, so a substitute that is itself blamed finds
		# nothing and is dropped. Both sets only grow. Finding 281.
		for start in sorted(fresh):
			blamed = {producer for _reader, _field, producer in stale
			          if producer in covers
			          and origin[covers[producer]] == start}
			# **Every rung, not one.** The first version allowed a single
			# attempt per window: a substitute that was itself blamed
			# meant the window was dropped, with the rest of the ladder
			# untouched. The blame accumulates across rounds, so an
			# alternative must avoid everything this window has ever been
			# blamed for and not merely this round's -- conservative in
			# the safe direction, since blame is relative to a placement
			# and a producer that was guilty once may be guilty again in
			# a shape nobody has tried yet. Finding 283.
			seen_blame[start] |= blamed
			if start not in offers:
				make = UNIT_ALTERNATIVES.get(start)
				offers[start] = list(make()) if make is not None else []
			other = None
			for rung, item in enumerate(offers[start]):
				if rung in spent[start]:
					continue
				if any(item[0] <= producer < item[0] + item[4]
				       for producer in seen_blame[start]):
					continue
				spent[start].add(rung)
				other = item
				break
			if other is None:
				if start not in dropped:
					kind = strategy_of.get(start, "?")
					why = ("no alternative window exists"
					       if not offers[start] else
					       "every alternative covers a blamed producer")
					REPAIR_DROPPED_WHY[(kind, why)] += 1
					REPAIR_DROPPED_SITES[(kind, why)] += sites_of.get(
						start, 0)
					width = width_of.get(start, 0)
					for producer in seen_blame[start]:
						if producer == start:
							where = "the window's own first instruction"
						elif not (start < producer < start + width):
							where = "outside the window it was blamed on"
						elif producer >= start + width - 16:
							where = "the last 16 bytes of the window"
						else:
							where = "interior: a window wanting a split"
						REPAIR_BLAME_WHERE[(kind, where)] += 1
					inside = sorted(p for p in seen_blame[start]
					                if start <= p < start + width)
					gained, edge = 0, start
					for producer in inside + [start + width]:
						if producer > edge:
							gained = max(gained, sites_in(edge,
							                             producer - edge))
						edge = producer + 1
					REPAIR_SPLITTABLE[(kind, bool(gained))] += 1
				dropped.add(start)
				swapped.pop(start, None)
			else:
				swapped[start] = other
				# A set difference and not a suffix: the replacement is
				# another rung, so it may begin earlier as well as end
				# sooner.
				REPAIR_EXCLUDED.update(
					set(range(start, start + width))
					- set(range(other[0], other[0] + other[4])))
	# **Not settling means the windows below are known-guilty.** The
	# previous version placed them and left a wrong image for `verify` to
	# find. Refusing is the only honest end: there is no partial repair
	# here, because a window that is still guilty ships a surviving
	# 256-bit read of an upper half that is no longer in its register.
	if not settled:
		raise SystemExit(
			f"apply: the stale-read repair did not settle in "
			f"{REPAIR_ROUNDS} rounds, having dropped {len(dropped):,} "
			f"window(s). Placing what is left would ship a surviving "
			f"256-bit read of an upper half no longer in its register.")
	# **The same list the loop settled on, substitutions included.** This
	# rebuilt it from `candidates` alone, so every window the loop had
	# rebuilt was placed here in its ORIGINAL form -- the shape the loop
	# had just proved guilty. `apply` reported 459 windows rebuilt and
	# emitted none of them, and the image shipped 166 stale reads.
	#
	# It survived because the loop and the return computed the same thing
	# two ways, which was true until one of them learned about
	# substitution. Finding 281.
	final = []
	for item in candidates:
		if item[0] in dropped:
			continue
		final.append(swapped.get(item[0], item))
	# Distinct windows rebuilt, not attempts: a window offered three rungs
	# before one fitted is one rebuilt window.
	REPAIR_SUBSTITUTED = len(swapped)
	REPAIR_FINAL[:] = final
	STUB_DETAIL.clear()
	placed, blob, swallowed, overlapped, refused = place_stubs(
		final, stub_base, spill_base, stub_reasons, detail=STUB_DETAIL,
		home=home, tls=tls)
	return placed, blob, overlapped, refused, dropped, swallowed


CHAIN_LOADS = ("vmovup", "vmovdqu", "vmovap", "vmovdqa", "vbroadcast",
               "vmovss", "vmovsd")
CHAIN_ZEROS = ("vxorps", "vxorpd", "vpxor")


SPILL_WATCH = ("no home space to borrow", "no SSE form at any register",
               "src2 aliases dst, no scratch", "sequence with no usable scratch")


def spill_census(original, listing):
	"""What each backing store is worth, measured. Always 0.

	**A wholesale switch is not the only shape the question has, and the
	numbers say so.** `tls` declines 386 sites "no home space to borrow"
	because its addressing needs two free GPRs; `stack` and `pool` need
	none and decline zero -- and both end with 194 FEWER candidates than
	`tls`, having lost 580 elsewhere to buy 386. The default is the best of
	the five and the borrow mechanism as a whole is worth 4,357 candidates
	over `none`.

	So the 386 are reachable only by a per-site fallback, which is a
	different thing from a different default, and the comparison has to be
	run to see that at all. Finding 202.
	"""
	global SPILL
	context = analysis_context(original, listing)
	first = None
	for mode in (SPILL_NONE, SPILL_STACK, SPILL_POOL, SPILL_HOME, SPILL_TLS):
		SPILL = mode
		_patches, candidates, _stats, _skipped, declined, _home = collect(
			original, listing, context)
		counted = Counter(declined.values())
		if first is None:
			first = len(candidates)
		print(f"spills: --spill={mode:<5} candidates {len(candidates):>9,} "
		      f"({len(candidates) - first:+,})  declined {len(declined):>7,}")
		for name in SPILL_WATCH:
			print(f"    {name:<34} {counted.get(name, 0):>6,}")
	return 0


def chain_census(original, listing, reason):
	"""What a declined class is shaped like, as a dataflow. Always 0.

	**For a class that is a graph rather than a list.** 1,976 sites are
	declined "256-bit: arithmetic rather than a copy", and reading that as
	1,976 sites of available work is the mistake Finding 179 already paid
	for once. An SSE-only CPU cannot READ bits 255:128 of a ymm register at
	all -- that is what `vextractf128` is for, and it is itself AVX -- so
	such a site is reachable only if the value never sits in a ymm at all.
	That is a property of the whole chain and not of the instruction.

	So this reports what produced each ymm source and what consumes each
	result. A chain is closed only when every source is a load or a
	zeroing idiom and every consumer ends in memory, which makes the store
	count the ceiling on the class however many sites it holds.
	Finding 200.
	"""
	context = analysis_context(original, listing)
	_patches, _cand, _stats, _skipped, declined, _home = collect(
		original, listing, context)
	instructions, _plain, blocked, sources, _tables, _seen = context
	index_of = {row[0]: i for i, row in enumerate(instructions)}
	sites = sorted(a for a, why in declined.items() if why == reason)
	print(f"chains: {len(sites):,} site(s) declined as {reason!r}")
	if not sites:
		# A renamed message must not present itself as an empty class.
		print(f"chains: FAILED -- no site carries that reason; the reasons "
		      f"in use are:", file=sys.stderr)
		for name, count in Counter(declined.values()).most_common(12):
			print(f"    {name}  ({count:,})", file=sys.stderr)
		return 1
	mnemonics, sourcing, consuming = Counter(), Counter(), Counter()
	for address in sites:
		position = index_of[address]
		_a, _e, mnemonic, operands, _c = instructions[position]
		mnemonics[mnemonic] += 1
		fields = inplace.split_operands(operands or "")
		for field in [f for f in fields[:-1] if f.startswith("%ymm")]:
			where = reaching_definitions(instructions, position, field,
			                             blocked, sources=sources,
			                             depth=JOIN_DEPTH)
			if where is None:
				sourcing["producer unknown"] += 1
				continue
			kinds = set()
			for one in where:
				made = instructions[one][2]
				kinds.add("a load or a move" if made.startswith(CHAIN_LOADS)
				          else "a zeroing idiom" if made in CHAIN_ZEROS
				          else "more arithmetic")
			sourcing["+".join(sorted(kinds))] += 1
		destination = fields[-1] if fields else None
		found = "nothing found"
		if destination and destination.startswith("%ymm"):
			for step in range(1, CHAIN_REACH):
				at = position + step
				if at >= len(instructions):
					break
				later = instructions[at]
				if later[2].startswith(("call", "ret")):
					found = "a call or a return"
					break
				if destination in (later[3] or ""):
					names = inplace.split_operands(later[3])
					found = ("a 256-bit store"
					         if later[2].startswith("vmov") and names
					         and names[-1].startswith("(")
					         else "a move" if later[2].startswith("vmov")
					         else "more arithmetic")
					break
		consuming[found] += 1
	for title, counted in (("mnemonics", mnemonics),
	                       ("what produced each ymm source", sourcing),
	                       ("what consumes the result", consuming)):
		print(f"chains: {title}")
		width = max((len(str(name)) for name in counted), default=0)
		for name, count in counted.most_common(10):
			print(f"  {str(name):<{width}}  {count:>6,}")
	return 0


def frontier_census(original, patched, listing):
	"""Why each surviving VEX instruction is still there. Always 0.

	**Nobody has ever asked.** The frontier is quoted as one number and
	attacked by whichever strategy somebody was thinking about; the source
	census found 77 of 257 refusals to be a constant in this file, and the
	same question has never been put to the sites themselves.

	Classified against what the rewriter DID, in the order that a site
	stops being available: kept on purpose by a repair, kept because its
	window was withheld, declined by the collector with its reason, lost to
	an overlap, or never a candidate at all. Read from the IMAGE, so a site
	counted here is one that really survived. Finding 199.
	"""
	context = analysis_context(original, listing)
	patches, candidates, _stats, _skipped, declined, home = collect(
		original, listing, context)
	instructions, _plain, blocked, sources, _tables, _seen = context
	placed, _blob, overlapped, refused, dropped, _swallowed = \
		repaired_placement(
			instructions, blocked, sources, candidates,
			set(row[0] for row in patches),
			stub_base_of(open(original, "rb").read()), 0, Counter(), home,
			tls_pair_of(tls_for(original)))

	_bounds, surviving, _bad = inplace.disassemble(patched)
	surviving = set(surviving)
	vaddr, raddr, _size = inplace.text_mapping(original)
	image = open(patched, "rb").read()
	reverted = {row[0] for row in patches
	            if image[raddr + (row[0] - vaddr):
	                     raddr + (row[0] - vaddr) + len(row[1])] == row[1]}
	inside_dropped = set()
	for site, window, _s, _z, _p in place_stubs(
			[item for item in candidates if item[0] in dropped],
			stub_base_of(open(original, "rb").read()), 0, Counter(),
			home=home, tls=tls_pair_of(tls_for(original)))[0]:
		inside_dropped.update(range(site, site + window))
	# **Spread over the extent, not the start.** `inside_dropped` above
	# is spread and these were not, so a site that is inside a candidate
	# without BEING its start fell past every bucket into `never a
	# candidate` -- which reads as "the collector never saw it" and is
	# the opposite of the truth. A window widened backwards starts on
	# the instruction before its site, so its site is exactly such an
	# address, and 31 of them were filed that way: ordinary 256-bit
	# three-register arithmetic, `vdivps %ymm1,%ymm2,%ymm4` ten times
	# over, in a bucket that said nothing had been tried.
	#
	# Same defect as Finding 282, which put 79 survivors in
	# `unaccounted` by keying on a start that appears in no candidate.
	# There it was loud, because the census asserts `unaccounted` is
	# zero; here it was silent, because the fallback bucket has no such
	# assertion and a wrong label reads as data. Finding 310.
	wanted, got = set(), set()
	width = {start: window for start, _e, _o, _m, window, *_r
	         in (REPAIR_FINAL or candidates)}
	over_extent, refused_extent = set(), set()
	for start, where in ((overlapped, over_extent), (refused, refused_extent)):
		for one in start:
			where.update(range(one, one + width.get(one, 1)))
	for start, _e, _o, _m, window, *_rest in (REPAIR_FINAL or candidates):
		wanted.update(range(start, start + window))
	for site, window, _s, _z, _p in placed:
		got.update(range(site, site + window))

	counted, shapes = Counter(), Counter()
	# **And the shape of each bucket, not only of the whole.** The
	# totals say which reason is biggest; they cannot say what the
	# sites in it ARE, which is what decides whether a bucket is one
	# strategy's worth of work or a thousand unrelated shapes.
	by_reason = defaultdict(Counter)
	reason_of = {}
	by_address = {row[0]: row for row in instructions}
	for address in surviving:
		row = by_address.get(address)
		if row is not None:
			shapes[row[2]] += 1
		if address in reverted:
			reason = "kept: a repair left it in VEX form"
		elif address in inside_dropped:
			reason = "kept: its window was withheld"
		elif address in declined:
			reason = f"declined: {declined[address]}"
		elif address in wanted and address not in got:
			# **Which of the two, because they want opposite work.** A
			# candidate a neighbour overlapped is a PLACEMENT question
			# -- somebody else took the bytes -- while one whose stub
			# would not build is a LOWERING question with a reason
			# already recorded in the refusal roll. Merged, the bucket
			# says only that the candidate existed and did not place,
			# which is where it was before Finding 310 moved 27 sites
			# into it. Finding 311.
			reason = ("lost to an overlap" if address in over_extent
			          else "lost to a refused stub"
			          if address in refused_extent
			          else "lost to an overlap or a refused stub")
		elif address in wanted:
			reason = "a placed window covered it (should not happen)"
		elif address in REPAIR_EXCLUDED:
			reason = "excluded by a window the repair rebuilt"
		elif address in COLLECT_SEEN:
			reason = "the collector reached it and recorded nothing"
		elif not COLLECT_SEEN:
			# **The branch above cannot fire against an empty set, and it
			# did not.** `COLLECT_SEEN.clear()` was first wired into
			# `repaired_placement`, which runs AFTER `collect` fills it, so
			# every site reaching here read "never reached" -- including one
			# measured as passing all four of the loop's head guards, which
			# is what made the answer impossible rather than merely wrong.
			#
			# A distinction drawn against an empty set is not a weaker
			# distinction, it is a constant. Saying so here costs one branch
			# and makes the failure name itself. Finding 319.
			reason = "unclassifiable: COLLECT_SEEN was never filled"
		else:
			reason = "the collector never reached it"
		counted[reason] += 1
		reason_of[address] = reason
		if row is not None:
			by_reason[reason][row[2]] += 1
	print(f"frontier: {len(surviving):,} surviving VEX instruction(s)")
	width = max((len(name) for name in counted), default=0)
	for name, count in counted.most_common():
		print(f"  {name:<{width}}  {count:>6,}")
	print(f"  {'total':<{width}}  {sum(counted.values()):>6,}")
	# **And the sites themselves, because a count cannot be read.** The
	# bucket totals say which reason is biggest and the shapes say what is
	# in it; neither lets anybody go and LOOK at a site. Written the way
	# `apply` writes its refused regions, and for the same reason: an item
	# is picked from this census, and picking one on a number whose members
	# nobody has seen is how a bucket gets characterised wrongly.
	# Finding 228.
	from pathlib import Path		# imported here as elsewhere in this file
	roll = Path("build") / "frontier-sites.txt"
	if roll.parent.is_dir():
		with roll.open("w", encoding="utf-8") as out:
			# **Name the image, because the path is fixed.** Any `frontier`
			# run overwrites this file, so a two-line census of a fixture
			# replaces Starfield's 5,673 and nothing says so. Measured the
			# hard way: a coverage count was computed against a fixture's
			# leftovers and reported 304 lowered sites with no oracle case,
			# where the real answer is 1. A reader -- or a script -- can now
			# see which binary the rows describe. Finding 240.
			out.write(f"# {original}\t{len(surviving)} surviving\t"
			          f"{run_configuration()}\n")
			for address in sorted(surviving):
				row = by_address.get(address)
				out.write(f"{address:#x}\t{reason_of.get(address, '?')}\t"
				          f"{row[2] if row else '?'}\t"
				          f"{(row[3] if row else '') or ''}\n")
		print(f"frontier: every surviving site written to {roll}")
	print("frontier: the commonest mnemonics in each reason")
	for reason, _n in counted.most_common():
		shown = by_reason[reason]
		if not shown:
			continue
		top = "  ".join(f"{name} {n:,}"
		                for name, n in shown.most_common(4))
		print(f"  {reason}")
		print(f"      {top}")
	print("frontier: the ten commonest mnemonics among them")
	for name, count in shapes.most_common(10):
		print(f"  {name:<{width}}  {count:>6,}")
	return 0


def source_census(binary, listing):
	"""Break the unresolved upper-half sources down by why. Always 0.

	**A residue is not a floor until somebody asks what is in it.** The
	193 indirect entries and 23 call/ret this project quotes were measured
	when the total was 603; Findings 194 and 195 closed 346 of those, and
	nothing re-derives a scope number by itself. This is the method beside
	the fact. Finding 197.
	"""
	context = analysis_context(binary, listing)
	_patches, candidates, _stats, _skipped, _declined, home = collect(
		binary, listing, context)
	placed, _blob, _swallowed, _over, _refused = place_stubs(
		candidates, stub_base_of(open(binary, "rb").read()), home=home,
		tls=tls_pair_of(tls_for(binary)))
	instructions, _plain, blocked, sources, _tables, _seen = context
	reasons = []
	stale, unknown, _unsure = stale_upper_reads(
		instructions, blocked, sources, placed,
		set(row[0] for row in _patches), reasons)
	readers = len({reader for reader, _f, _p in stale})
	print(f"sources: {readers:,} stale reader(s), {unknown:,} unresolved")
	counted = Counter(reason for (reason, _at), _reader, _field in reasons)
	width = max((len(name) for name in counted), default=0)
	for name, count in counted.most_common():
		print(f"  {name:<{width}}  {count:>5,}")
	print(f"  {'total':<{width}}  {sum(counted.values()):>5,}")
	return 0


INDEX_CALLBACK_FLAGS = 0xE0000020	# read, write, execute, code
INDEX_NAME = b".avxidx\0"
INDEX_FLAGS = 0x60000020		# read, execute, code


def patch_loop():
	"""One `fill every RVA in this table with %eax` loop, and its rel32.

	`%r9` walks the table, `%r10d` holds each RVA, and the base is `%rcx`
	as the loader passed it -- so nothing here is an absolute address.
	"""
	out = bytearray()
	out += b"\x4c\x8d\x0d\0\0\0\0"		# lea <table>(%rip),%r9
	rel = len(out) - 4
	top = len(out)
	out += b"\x45\x8b\x11"				# mov (%r9),%r10d
	out += b"\x45\x85\xd2"				# test %r10d,%r10d
	done = len(out)
	out += b"\x74\x00"					# je done
	out += b"\x42\x89\x04\x11"			# mov %eax,(%rcx,%r10)
	out += b"\x49\x83\xc1\x04"			# add $4,%r9
	out += b"\xeb" + bytes([(top - (len(out) + 2)) & 0xFF])
	out[done + 1] = (len(out) - (done + 2)) & 0xFF
	return bytes(out), rel


def index_callback(index_rva, table_rel, orig_rva, teb=None):
	# **Every table offset is measured from this function's first byte,
	# and this function does the arithmetic.** It used to be handed a
	# displacement the caller had computed by counting instruction
	# lengths in a comment -- `code_off + 3 + 2 + 6 + 3 + 7` -- and that
	# `2` was the short `jne`. Widening it to a near branch made the
	# count wrong by four and nothing would have said so: the callback
	# would have read its table from four bytes early, which is inside
	# the padding and decodes as a plausible RVA. So the caller now says
	# WHERE the table is and the emitter works out how to reach it.
	# Finding 297.
	"""The TLS callback that writes the index into every stub. 48 bytes.

	    tls_cb(rcx = module base, rdx = reason, r8 = reserved)
	        cmp   $1,%edx                  DLL_PROCESS_ATTACH
	        jne   chain
	        mov   <index>(%rcx),%eax       the index the loader wrote
	        shl   $3,%eax                  a slot is eight bytes
	        lea   <table>(%rip),%r9        the table is in this payload
	    loop:
	        mov   (%r9),%r10d              an RVA, zero ends the table
	        test  %r10d,%r10d
	        je    chain
	        mov   %eax,(%rcx,%r10)         fill one displacement
	        add   $4,%r9
	        jmp   loop
	    chain:
	        lea   <orig>(%rcx),%rax
	        jmp   *%rax                    the original, arguments intact

	**Everything is base-plus-RVA and nothing is absolute**, because the
	image is `DYNAMIC_BASE` and nothing relocates bytes this tool writes.
	The base arrives in `rcx` as the loader's `DllHandle`. Finding 292.

	**Only volatile registers are touched** -- rax, r9, r10 -- so `rcx`,
	`rdx` and `r8` reach the original unchanged, and a jump rather than a
	call leaves the stack as the loader arranged it.
	"""
	out = bytearray()
	out += b"\x83\xfa\x01"				# cmp $1,%edx
	# **A NEAR jne, always.** The short form reaches 127 bytes and the
	# callback is 237 with the TEB half, so it assembled as a jump
	# BACKWARDS out of the routine -- taken on every reason except
	# DLL_PROCESS_ATTACH, which is every thread attach. The non-TEB
	# form is 39 bytes and hides it completely. Finding 297.
	jne_at = len(out)
	out += b"\x0f\x85\0\0\0\0"			# jne chain
	out += b"\x8b\x81" + struct.pack("<i", index_rva)
	out += b"\xc1\xe0\x03"				# shl $3,%eax
	# **rip-relative, not base-relative.** The table sits in the same
	# payload as this code, so reaching it needs no knowledge of where
	# the loader put the section -- which is what lets the payload be
	# built before it has an address. `table_rel` is measured from the
	# end of this instruction.
	body, rel = patch_loop()
	body = bytearray(body)
	struct.pack_into("<i", body, rel, table_rel - (len(out) + rel + 4))
	out += body
	chain = len(out)
	struct.pack_into("<i", out, jne_at + 2, chain - (jne_at + 6))
	if teb is not None:
		# **Two slots of our own, asked for at load time.** `TlsAlloc`
		# is the documented way to own one, and slot k is then
		# `%gs:0x1480+8k` -- no base, no index, no register, which is
		# what a site with no dead GPR needs. Finding 297.
		#
		# It clobbers every volatile register, including the three the
		# tail-jump owes the original, so they go on the stack across
		# both calls. 0x48 keeps `rsp` 16-aligned: entry is 8 mod 16.
		alloc_rva, getproc_rva, term_rva, rel_a, rel_b = teb
		out += b"\x48\x83\xec\x48"			# sub $0x48,%rsp
		out += b"\x48\x89\x4c\x24\x20"		# mov %rcx,0x20(%rsp)
		out += b"\x48\x89\x54\x24\x28"		# mov %rdx,0x28(%rsp)
		out += b"\x4c\x89\x44\x24\x30"		# mov %r8,0x30(%rsp)
		out += b"\xff\x91" + struct.pack("<i", alloc_rva)
		out += b"\x89\x44\x24\x38"			# mov %eax,0x38(%rsp)
		out += b"\x48\x8b\x4c\x24\x20"		# mov 0x20(%rsp),%rcx
		out += b"\xff\x91" + struct.pack("<i", alloc_rva)
		out += b"\x41\x89\xc3"			# mov %eax,%r11d
		out += b"\x8b\x44\x24\x38"			# mov 0x38(%rsp),%eax
		out += b"\x48\x8b\x4c\x24\x20"		# mov 0x20(%rsp),%rcx
		out += b"\x48\x8b\x54\x24\x28"		# mov 0x28(%rsp),%rdx
		out += b"\x4c\x8b\x44\x24\x30"		# mov 0x30(%rsp),%r8
		out += b"\x48\x83\xc4\x48"			# add $0x48,%rsp
		# **Only the first 64 slots are addressable with no register.**
		# Past them a value sits behind `TlsExpansionSlots`, which is
		# the dereference this exists to avoid, so an index of 64 or
		# more is refused rather than patched. Measured at 5 here
		# (Finding 296), and a floor is not a guarantee.
		out += b"\x83\xf8\x40"			# cmp $64,%eax
		bad1 = len(out); out += b"\x0f\x83\0\0\0\0"
		out += b"\x41\x83\xfb\x40"			# cmp $64,%r11d
		bad2 = len(out); out += b"\x0f\x83\0\0\0\0"
		out += b"\xc1\xe0\x03"			# shl $3,%eax
		out += b"\x05" + struct.pack("<I", 0x1480)	# add $0x1480,%eax
		body, r = patch_loop()
		body = bytearray(body)
		struct.pack_into("<i", body, r, rel_a - (len(out) + r + 4))
		out += body
		out += b"\x44\x89\xd8"			# mov %r11d,%eax
		out += b"\xc1\xe0\x03"			# shl $3,%eax
		out += b"\x05" + struct.pack("<I", 0x1480)
		body, r = patch_loop()
		body = bytearray(body)
		struct.pack_into("<i", body, r, rel_b - (len(out) + r + 4))
		out += body
		over = len(out); out += b"\xe9\0\0\0\0"	# jmp past refuse
		refuse = len(out)
		# `%r11` carries the base, because the handle lands in `%rcx`.
		out += b"\x49\x89\xcb"			# mov %rcx,%r11
		out += b"\x48\x83\xec\x28"			# sub $0x28,%rsp
		out += b"\x41\xff\x93" + struct.pack("<i", getproc_rva)
		out += b"\x48\x89\xc1"			# mov %rax,%rcx
		out += b"\xba\xc0\x00\x00\x00"		# mov $192,%edx
		out += b"\x41\xff\x93" + struct.pack("<i", term_rva)
		out += b"\xf4"					# hlt: never returns
		here = len(out)
		struct.pack_into("<i", out, bad1 + 2, refuse - (bad1 + 6))
		struct.pack_into("<i", out, bad2 + 2, refuse - (bad2 + 6))
		struct.pack_into("<i", out, over + 1, here - (over + 5))
		chain = len(out)
		struct.pack_into("<i", out, jne_at + 2, chain - (jne_at + 6))
	if orig_rva is None:
		# An empty callback array -- a fixture's -- has nothing to chain
		# to, so the callback simply returns.
		out += b"\xc3"					# ret
		return bytes(out)
	out += b"\x48\x8d\x81" + struct.pack("<i", orig_rva)
	out += b"\xff\xe0"					# jmp *%rax
	return bytes(out)


def index_payload(data, blob, stub_base):
	"""`(bytes, offset of the callback)` for the index section, or None.

	**A section of its own, because `.avxsse` is verified as pure code.**
	The first attempt appended the table to the stub blob and `verify`
	produced four failures for it: 98,261 bytes of stub outside every
	function table entry, 3,891 sequences that decode to nothing, 52
	phantom calls, all of them the table being disassembled -- and the
	array write besides. The checks were right and the placement was
	wrong. Finding 294.

	The payload is self-contained: the callback reaches its table
	rip-relative, so this can be built before the loader or `add_section`
	has given it an address.
	"""
	found = tls_directory(data)
	if found is None:
		raise SystemExit("apply: --index-const needs a TLS directory")
	_at, fields = found
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	image_base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
	slot = rva_to_offset(data, fields[3] - image_base)
	if slot is None:
		raise SystemExit("apply: the TLS callback array is in no section")
	original = struct.unpack_from("<Q", data, slot)[0]

	stub_rva = stub_base - image_base

	def table_for(offsets):
		return b"".join(struct.pack("<I", stub_rva + off)
		                for off in offsets) + b"\x00\x00\x00\x00"

	spots = index_placeholders(blob)
	if CODE_SABOTAGE == "indexconst":
		spots = []		# the callback runs and patches nothing
	tables = [table_for(spots)]

	teb = None
	if TEB_SCRATCH == "auto":
		# **Two more tables, filled by two more `TlsAlloc` calls.** A
		# scratch site borrows two registers and so needs two slots;
		# they are separate tables rather than one because each carries
		# a different slot number. Finding 297.
		# **Counted in the blob, not at the emitter.** An emission
		# counter was written here first and reported 16 against the 4
		# that ship, because the collector emits for candidates it never
		# places and for every rung of the ladder. That is the same
		# error `INDEX_CONST_SITES` was measured making at 60 to 1, met
		# a second time in the same file. A call count is not a
		# denominator for an artifact.
		#
		# What replaces it is a structural witness rather than a
		# tally: a TEB block saves exactly two registers, one at the
		# slot and one eight bytes above it, so the two tables must be
		# the same length whatever the collector did. Findings 293
		# and 297.
		low, high = teb_placeholders(blob)
		if CODE_SABOTAGE == "tebconst":
			# The callback runs, allocates its slots, and patches
			# nothing -- so every stub writes eight bytes at
			# `%gs:TEB_PLACEHOLDER`. The fixture must die. Without
			# this the 77 it returns is a green light with no shown
			# ability to be anything else. Finding 297.
			low, high = [], []
		if len(low) != len(high):
			raise SystemExit(
				f"apply: {len(low):,} low and {len(high):,} high TEB "
				f"scratch displacements; they are saved in pairs.")
		if not low:
			# **No placeholder, no requirement.** With `auto` the
			# default, every image reaches this -- and a fixture with
			# no site that needs TEB scratch would otherwise be made
			# to import `TlsAlloc` to be rewritten at all. That is
			# Finding 295's lesson from the constant index, where
			# making it the default broke every fixture twice: a
			# default must be a no-op where the thing it enables is
			# not used. Finding 309.
			return_early = True
		else:
			return_early = False
		if return_early:
			tables = tables[:1]
			teb = None
		else:
			tables += [table_for(low), table_for(high)]
			teb = tuple(iat_rva(data, name) for name in
			            ("TlsAlloc", "GetCurrentProcess",
			             "TerminateProcess"))
			missing = [n for n, r in zip(("TlsAlloc",
			                              "GetCurrentProcess",
			                              "TerminateProcess"), teb)
			           if r is None]
			if missing:
				raise SystemExit("apply: --teb-scratch=auto needs the "
				                 "image to import " + ", ".join(missing))

	# The callback reaches each table with a rip-relative `lea` measured
	# from its own first byte, so the tables are laid out first and the
	# code after them at a known offset.
	spans, at = [], 0
	for one in tables:
		spans.append(at)
		at += len(one)
	code_off = (at + 15) // 16 * 16
	rels = [off - code_off for off in spans]
	orig = (original - image_base) if original else None
	probe = index_callback(fields[2] - image_base, 0, orig,
	                       teb=(teb + (0, 0)) if teb else None)
	code = index_callback(fields[2] - image_base, rels[0], orig,
	                      teb=(teb + tuple(rels[1:])) if teb else None)
	assert len(code) == len(probe), "the callback changed length"
	payload = bytearray(b"".join(tables))
	payload += b"\xcc" * (code_off - len(payload))
	payload += code
	print(f"apply: {len(spots):,} stub(s) take the TLS index from a "
	      f"constant, filled in by a callback chained ahead of "
	      f"{'the original' if original else 'nothing'}")
	if teb:
		print(f"apply: {len(low) * 2:,} scratch displacement(s) in "
		      f"{len(low) // 2:,} stub(s) come from two TLS slots the "
		      f"same callback allocates")
	return bytes(payload), code_off, slot, original


def iat_rva(data, name):
	"""RVA of the import address table entry for `name`, or None.

	**A call through the IAT, not a `GetProcAddress`.** A TLS callback
	runs after the loader has resolved imports, so an entry the image
	already has is a pointer that is already correct -- which removes
	both a name lookup and the module handle it would need. Every
	function the callback wants is imported by this image; a name that
	is not is refused rather than worked around. Finding 297.
	"""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	rva, _size = struct.unpack_from("<II", data, pe + 24 + 112 + 8)
	start = rva_to_offset(data, rva)
	if start is None:
		return None
	n = 0
	while True:
		ilt, _ts, _fc, _nm, iat = struct.unpack_from("<IIIII", data,
		                                             start + n * 20)
		if not (ilt or _nm or iat):
			return None
		n += 1
		thunk = rva_to_offset(data, ilt or iat)
		if thunk is None:
			continue
		i = 0
		while True:
			entry = struct.unpack_from("<Q", data, thunk + i * 8)[0]
			if not entry:
				break
			if not (entry >> 63):
				at = rva_to_offset(data, (entry & 0x7FFFFFFF) + 2)
				if at is not None:
					end = data.index(b"\0", at)
					if data[at:end] == name.encode():
						return iat + i * 8
			i += 1


def teb_placeholders(blob):
	"""`(low, high)` offsets of every unfilled TEB scratch displacement.

	Anchored on the whole instruction -- the `%gs` prefix, REX, the
	opcode, a mod-00 rm-100 modrm and the no-base no-index SIB -- rather
	than on the value, for the reason `index_placeholders` gives: the
	placeholder alone would also match the constant pool. Five anchoring
	bytes here against two there. Finding 297.
	"""
	out = ([], [])
	for rex in (0x48, 0x4C):
		for opcode in (0x89, 0x8B):
			for reg in range(8):
				head = bytes([0x65, rex, opcode, (reg << 3) | 4, 0x25])
				for which, value in enumerate((TEB_PLACEHOLDER,
				                               TEB_PLACEHOLDER + 8)):
					want = head + struct.pack("<I", value)
					start = 0
					while True:
						start = blob.find(want, start)
						if start < 0:
							break
						out[which].append(start + 5)
						start += 1
	return sorted(out[0]), sorted(out[1])


def index_placeholders(blob):
	"""Offsets of every unfilled TLS-index displacement in `blob`.

	Anchored on the instruction rather than the value: `8b`, a modrm with
	mod 10 and reg equal to rm, then the placeholder. `0x5a5a5a5a` on its
	own occurs in the constant pool. Finding 293.
	"""
	out = []
	for number in sorted(GPR_NUMBERS.values()):
		head = bytes([0x8B, 0x80 | ((number & 7) << 3) | (number & 7)]) \
			+ struct.pack("<I", INDEX_PLACEHOLDER)
		start = 0
		while True:
			start = blob.find(head, start)
			if start < 0:
				break
			out.append(start + 2)		# the displacement, not the opcode
			start += 1
	return sorted(out)


def tls_pair_of(found):
	"""The `(index VA, slot offset)` a stub needs, from `tls_for`'s answer."""
	return None if found is None else (found[0], found[1])


def tls_for(binary):
	"""`(index VA, slot offset, zero fill)` for `--spill=tls`, or None.

	One place, because `census`, `apply` and `verify` all place stubs and a
	disagreement between them is the defect `place_stubs` was written to
	prevent: apply refusing a stub that verify expects leaves a window
	uncommitted and a later site detoured inside it.
	"""
	if SPILL != SPILL_TLS:
		return None
	with open(binary, "rb") as image:
		# `TLS_SLOTS` slots, not one. The borrow spill wants a single slot
		# and a span wants its peak, and both address the same area --
		# `SizeOfZeroFill` is one number for the image, so it is sized for
		# the largest thing that will ever reach into it.
		return tls_slot(image.read(), tls_block_slots() * SLOT)


def report_cost(candidates, placed, home):
	"""What each strategy costs per site it lowers.

	**The project prices the whole binary and no strategy within it.** The
	estimated-cost table puts a translated Starfield at +1.34%, built from
	operand shapes; nothing says what a `pair` costs against a `region` for
	the same instruction, and Finding 161 ended at exactly that gap -- 1,145
	windows changed hands for seven sites and nobody could say whether the
	trade was good.

	The unit is **bytes of stub per VEX site removed**, and every term of it
	already exists: `placed` carries each window's length and the length of
	the body written for it, and the listing says how many VEX instructions
	that window contained. A strategy that covers four sites in one window
	is charged for four; one that covers a single site is charged for one.

	Bytes are a proxy for time and an imperfect one -- a `movups` to a slot
	and a `movaps` between registers are the same length and not the same
	cost. What the table can say is which strategies are cheap and which are
	dear per site, which is the question every ordering on the build-next
	list turns on and none of them could ask.
	"""
	if home is None:
		return
	plain = home[3]["plain"]
	starts = [row[0] for row in plain]
	kind_of = {}
	for entry in candidates:
		strategy = entry[8]
		kind_of[entry[0]] = strategy[0] if strategy is not None else "plain"
	cost = {}
	for address, window, _stub, body, _prologue in placed:
		kind = kind_of.get(address, "plain")
		row = cost.setdefault(kind, [0, 0, 0, 0])
		row[0] += 1				# windows
		row[1] += body				# bytes written
		row[2] += window			# bytes replaced
		low = bisect.bisect_left(starts, address)
		high = bisect.bisect_left(starts, address + window)
		for position in range(low, high):
			vex = inplace.decode_vex(plain[position][1])
			if vex is not None:
				row[3] += 1			# VEX sites this window removes
	print("apply: what each strategy costs, per VEX site it removes:")
	print(f"apply:   {'kind':<12} {'windows':>8} {'sites':>8} "
	      f"{'stub B':>10} {'B/site':>8}")
	for kind in sorted(cost, key=lambda k: -cost[k][3]):
		windows, body, _replaced, sites = cost[kind]
		per = body / sites if sites else 0
		print(f"apply:   {kind:<12} {windows:>8,} {sites:>8,} "
		      f"{body:>10,} {per:>8.1f}")


def report_regions(candidates, original=None):
	"""Why regions the collector accepted were not emitted.

	Every line below `members refused the region` is a disagreement between
	two functions about what is representable: `region_members` said yes and
	something after it said no. That is the drift `SPAN_EMITTABLE` prevents
	between the survey and the lowering, and it went unprevented between the
	collector and the lowering for as long as the reason went unrecorded.
	Finding 171.
	"""
	if not REGION_REFUSED:
		return
	made = sum(1 for c in candidates if c[8] and c[8][0] == "region")
	walk = {w: n for w, n in REGION_REFUSED.items() if w.startswith("members: ")}
	after = {w: n for w, n in REGION_REFUSED.items()
	         if not w.startswith("members: ")}
	# **Two groups, because they are two different failures.** A `members:`
	# line is the walk deciding the region is not representable; everything
	# else is a refusal AFTER it said yes, which is the disagreement
	# Finding 171 went after. Printing one total for both is how 5,610
	# walk refusals sat under a heading saying "after the walk said yes".
	print(f"apply: regions the collector built: {made:,} emitted, "
	      f"{sum(walk.values()):,} not representable, "
	      f"{sum(after.values()):,} refused after the walk said yes")
	for why, count in sorted(walk.items(), key=lambda kv: -kv[1]):
		print(f"apply:   {why:<52} {count:>7,}")
		for begin, site in REGION_EXAMPLES.get(why, [])[:3]:
			print(f"apply:       region at {begin:#x}, site {site:#x}")
	from pathlib import Path		# imported here as elsewhere in this file
	roll = Path("build") / "region-refused.txt"
	if roll.parent.is_dir():
		with roll.open("w", encoding="utf-8") as out:
			out.write(f"# {original}\t{sum(walk.values()):,} not "
			          f"representable\n")
			for why, rows in sorted(REGION_EXAMPLES.items()):
				for begin, site in rows:
					out.write(f"{why}\t{begin:#x}\t{site:#x}\n")
		print(f"apply: every refused region written to {roll}")
	for why, count in sorted(after.items(), key=lambda kv: -kv[1]):
		print(f"apply:   {why:<52} {count:>7,}")


def report_placement(candidates, placed, overlapped, refused):
	"""What the placer did to each kind of candidate, and what it cost.

	**The placer has never been instrumented and it is the dominant term.**
	Finding 159 measured 920 regions clearing every filter this project can
	name and about 100 reaching the binary, which makes `place_stubs` a
	bigger loss than every analysis rule left -- and until now the only
	numbers it reported were three totals with no way to tell which kind of
	candidate they fell on.

	Nothing in the placer changes to produce this. It already returns the
	sets of overlapped and refused addresses, and `apply_all` already holds
	the candidate list, so the tally is arithmetic on what exists. That is
	deliberate: instrumenting a placer by changing it risks changing what it
	places, and the first question is what it does now.

	The second table is what a window COSTS. A region's window is three to
	twelve instructions where an ordinary site's is five bytes, so a placed
	region forecloses every candidate that starts inside it -- and those
	candidates are counted here rather than guessed at.
	"""
	kind_of = {}
	starts = []
	for entry in candidates:
		start, strategy = entry[0], entry[8]
		kind_of[start] = strategy[0] if strategy is not None else "plain"
		starts.append(start)
	starts.sort()
	taken = {address for address, *_rest in placed}
	tally = {}
	for start, kind in kind_of.items():
		row = tally.setdefault(kind, [0, 0, 0])
		if start in taken:
			row[0] += 1
		elif start in overlapped:
			row[1] += 1
		elif start in refused:
			row[2] += 1
	print("apply: what the placer did, by strategy:")
	print(f"apply:   {'kind':<12} {'placed':>9} {'overlapped':>11} "
	      f"{'refused':>9}")
	for kind in sorted(tally, key=lambda k: -sum(tally[k])):
		row = tally[kind]
		print(f"apply:   {kind:<12} {row[0]:>9,} {row[1]:>11,} {row[2]:>9,}")

	# What each placed window forecloses: the candidates starting strictly
	# inside it, which the placer will meet later and skip for overlap.
	cost = Counter()
	for address, window, *_rest in placed:
		kind = kind_of.get(address, "plain")
		low = bisect.bisect_right(starts, address)
		high = bisect.bisect_left(starts, address + window)
		if high > low:
			cost[kind] += high - low
	if cost:
		print("apply: candidates foreclosed by a placed window, by kind:")
		for kind, count in cost.most_common():
			print(f"apply:   {kind:<12} {count:>9,}")


def stub_base_of(data):
	"""Where the stub section will start: past every section, page aligned."""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	opt = pe + 24
	alignment = struct.unpack_from("<I", data, opt + 32)[0]
	sections = struct.unpack_from("<H", data, pe + 6)[0]
	opt_size = struct.unpack_from("<H", data, pe + 20)[0]
	table = opt + opt_size
	highest = 0
	for i in range(sections):
		off = table + i * 40
		vsize, va, _rsize, _raddr = struct.unpack_from("<IIII", data, off + 8)
		highest = max(highest, va + vsize)
	image_base = struct.unpack_from("<Q", data, opt + 24)[0]
	return image_base + (highest + alignment - 1) // alignment * alignment


# How many passengers one rescue may chain. Each seat lengthens the window
# by its instruction, and the next seat is looked for at the new end, so an
# unbounded walk would grow a window until it swallowed a function. Four is
# well past the two the binary actually offers (Finding 183) and short
# enough that the extended window stays the shape the safety argument was
# made about.
RESCUE_CHAIN = 4


def rescue_seat(entries, i, start, reach, taken):
	"""The next candidate that would ride at `start + reach`, or None.

	`(index, entry, length)`. The entry is `emit_swallowed`'s shape, whose
	seventh field is the borrow flag -- a `spill` passenger carries the
	register its own candidate was given, from `borrow_that_lowers` at this
	same address, so it is as valid here as there.
	"""
	seated = {index for index, _entry, _grew in taken}
	for j in range(i + 1, len(entries)):
		if j in seated:
			continue
		other = entries[j]
		if other[0] >= start + reach:
			break
		following = other[7]
		borrowed = None
		if other[8] is not None:
			# A site with a strategy of its own mostly cannot ride along: a
			# passenger is lowered by `moved_instruction`, which knows only
			# the plain rules and would refuse a 256-bit one. `spill` is the
			# exception and was the whole bucket -- an ordinary lowering
			# that needs a register it gives back, which `emit_swallowed`
			# has bracketed since Finding 93.
			if other[8][0] != "spill":
				continue
			borrowed = other[8][1]
		if not following or other[1][:1] not in (b"\xc4", b"\xc5"):
			continue
		site = other[0] + sum(len(e[1]) for e in following)
		if site != start + reach:
			continue
		return (j, (site, other[1], None, other[2], other[3],
		            other[6] if borrowed is None else borrowed,
		            borrowed is not None), len(other[1]))
	return None


def place_stubs(candidates, stub_base, spill_base=0, reasons=None,
                detail=None, home=None, tls=None):
	"""Choose and build the stubs. (placed, blob, swallowed, overlap, refused)

	**One selection rule, executed once and used by both apply and verify.**
	It used to be written twice, and the two copies disagreed: a candidate
	whose stub could not be built is refused and writes nothing, so apply
	left its window uncommitted and went on to detour a later site inside
	it, while verify's copy committed the window regardless and therefore
	never expected that later site -- or the instruction its widened window
	swallowed. That surfaced as 356 lost boundaries reported as unexplained,
	every one of them correct in the binary and wrong only in the model.

	The count of refusals is what made it visible, having gone from 762 to
	2,402 when the src2-aliasing check started refusing sites with no
	scratch. The divergence was there the whole time.

	Windows must not overlap for the original reason too: two Class C sites
	can sit next to each other, and the first one's widened window swallows
	the second, which would otherwise be patched again on top of the jump
	already written there.
	"""
	# The constant pool goes first, so its address is the section's and the
	# 16-byte alignment SSE memory operands need comes free.
	blob = bytearray(PERMIL_POOL)
	pool = stub_base
	placed, swallowed = [], set()
	# Sets rather than counters: a tally cannot say WHICH sites these were,
	# and that is the question census has to answer.
	refused, overlapped = set(), set()
	committed_to = 0
	entries = sorted(candidates, key=lambda c: c[0])
	rescued = set()
	for i, entry in enumerate(entries):
		start, encoding, operands, mnemonic, window, displaced, \
			scratch, preceding, strategy = entry
		if i in rescued:
			continue		# already taken along by an earlier stub
		if start < committed_to:
			overlapped.add(start)
			continue

		# **Take the next one with us rather than lose it.** A candidate
		# widened backwards starts on the instruction BEFORE its site, so
		# when that earlier byte falls inside the window about to be
		# committed the whole candidate is refused -- even though its site
		# sits outside, untouched, and cannot be reached any other way,
		# having gone backwards precisely because forward widening was
		# refused.
		#
		# Measured before it was written: 1,053 sites, and in every one of
		# them the covering window ends EXACTLY at the site. So extending
		# this window by that one instruction rescues all of them.
		#
		# It is safe for the same reasons the candidate itself was: the
		# site is not a branch target, or backward widening would not have
		# been allowed to swallow it; and the extended window stays inside
		# one function, because the two windows overlap and each was
		# already checked to lie within one.
		# **A chain, because the extension makes its own next seat.** Taking
		# one passenger moves the window's end four bytes on, and a second
		# candidate's site can land exactly there -- measured at two sites,
		# `0x140e072c8` and `0x14126a10f`, where the first passenger is
		# non-borrowing and a `spill` candidate begins at its site. The loop
		# used to `break` after one and never look again. Bounded, because
		# each seat lengthens the window and an unbounded walk would swallow
		# a function. Finding 183.
		chain = []
		reach = window
		while len(chain) < RESCUE_CHAIN:
			seat = rescue_seat(entries, i, start, reach, chain)
			if seat is None:
				break
			chain.append(seat)
			reach += seat[2]

		stub_address = stub_base + len(blob)
		body, prologue = None, 0
		# **Longest chain first, then shorter, then none.** A chain that
		# will not build must not cost the passenger that would have ridden
		# alone, so the last seat is dropped and the rest retried. The floor
		# is the plain stub, which is what this did before there were
		# chains: taking a passenger along must never cost the stub that was
		# going anyway.
		while chain:
			grew = sum(length for _j, _entry, length in chain)
			extra = [entry for _j, entry, _length in chain]
			body, prologue = build_stub(
				start, encoding, operands, mnemonic, window + grew,
				list(displaced) + extra, stub_address, scratch, pool,
				preceding, strategy, spill_base, home=home, tls=tls)
			if body is not None:
				window += grew
				displaced = list(displaced) + extra
				rescued.update(j for j, _entry, _length in chain)
				break
			chain.pop()
		if body is None:
			# **Only this call decides a refusal.** The extension above
			# failing is ordinary -- it falls back to the plain stub -- so
			# passing `reasons` to it would name causes for sites that were
			# placed perfectly well.
			# A fresh counter per site when `detail` is wanted, so the
			# reason can be attributed to the address as well as tallied.
			per = Counter() if detail is not None else None
			body, prologue = build_stub(
				start, encoding, operands, mnemonic, window, displaced,
				stub_address, scratch, pool, preceding, strategy, spill_base,
				per if per is not None else reasons, home, tls)
			if per is not None:
				if reasons is not None:
					reasons.update(per)
				if body is None and per:
					# **The strategy, because the reason alone does not say
					# which lowering was asked.** `moved: 256-bit, no Y
					# strategy took it` comes from `lower_vex`, the
					# per-instruction fallback -- so it says the window held
					# a 256-bit instruction and was built as something that
					# lowers one instruction at a time. Which strategy that
					# was is the whole question, and nothing recorded it:
					# 33 of the 36 such windows have a span shape for every
					# member, so the classifier is not the cause and the
					# roll could not name what is. Finding 314.
					detail[start] = (next(iter(per)), window,
					                 list(preceding), list(displaced),
					                 strategy[0] if strategy else "plain")
		if body is None:
			refused.add(start)
			continue
		placed.append((start, window, stub_address, len(body), prologue))
		committed_to = start + window
		blob += body
		# Every boundary strictly inside the window disappears. The window's
		# first byte keeps its boundary, because the jump is written there.
		offset = 0
		for entry in preceding:
			if offset:
				swallowed.add(entry[0])
			offset += len(entry[1])
		if preceding:
			swallowed.add(start + offset)	# the site, now inside the window
		for entry in displaced:
			swallowed.add(entry[0])
		if strategy is not None and strategy[0] in ("pair", "splat"):
			# A ymm pair carries no `displaced` list -- both instructions
			# are lowered together -- but the store's boundary disappears
			# just the same, and the verifier is right to want it named.
			# A zero store is one instruction and loses no extra boundary.
			#
			# **A splat has exactly this shape and was added without it**,
			# and `verify` refused the build for 41 unexplained boundaries
			# -- one per splat pair, the store of each. The gate was doing
			# precisely its job. Finding 108.
			swallowed.add(start + len(encoding))
		if strategy is not None and strategy[0] == "run":
			# Same again over a longer stretch: every boundary from the one
			# after the first load to the last store's own disappears.
			#
			# **`run_entries`, not `entries`.** This read `entries`, which
			# is the loop's own `sorted(candidates, ...)` twenty lines up,
			# and rebound it to a strategy's two-to-ten member list. The
			# `enumerate` iterator holds the original object so the loop
			# kept running and nothing looked wrong -- but the Finding 36
			# rescue above reads `range(i + 1, len(entries))`, and from the
			# first `run` candidate onward it was ranging over a list of
			# three. **The rescue never fired once in the whole binary.**
			# Renaming it recovers 396 sites and makes the stub section
			# 42,381 bytes SMALLER, because a window that is extended
			# swallows a neighbour instead of leaving it to detour on its
			# own. Finding 175.
			run_entries = strategy[1][1]
			for one in run_entries[1:]:
				swallowed.add(one[4])
		if strategy is not None and strategy[0] in ("span", "region", "unit"):
			# The window's first byte keeps its boundary because the jump is
			# written there; every member after the first loses its own.
			# Each entry's second field is its address.
			for entry in strategy[1][0][1:]:
				swallowed.add(entry[1])
		if strategy is not None and strategy[0] == "splatop":
			# The insert keeps the window's first byte; the operation and
			# the store both lose theirs. Each half of the strategy is
			# (vex, tail, address, length).
			for entry in strategy[1]:
				swallowed.add(entry[2])
		if strategy is not None and strategy[0] == "splatrun":
			# The insert keeps the window's first byte and every store after
			# it loses its boundary. Each entry's third field is its address.
			for entry in strategy[1]:
				swallowed.add(entry[2])
		if strategy is not None and strategy[0] == "construn":
			# Every store after the first loses its boundary to the group's
			# single window. Each entry is (load, store) and the store's
			# address is its third field.
			for _load, store in strategy[1][1:]:
				swallowed.add(store[2])
		if strategy is not None and strategy[0] == "zerorun":
			# Every store after the first loses its boundary to the group's
			# single window. Its address is the third field of the entry.
			for entry in strategy[1][1:]:
				swallowed.add(entry[2])
	return placed, blob, swallowed, overlapped, refused


def apply_all(binary, listing, output):
	context = analysis_context(binary, listing)
	patches, candidates, _stats, _skipped, _declined, home = collect(
		binary, listing, context)
	data = bytearray(open(binary, "rb").read())
	# Read from the ORIGINAL bytes, before anything is appended: the
	# directory's own contents do not move, and reading it later would make
	# the answer depend on how far the rewrite had got.
	tls_here = tls_for(binary)
	vaddr, raddr, _size = inplace.text_mapping(binary)

	# The in-place work first: it does not move anything, so the addresses
	# the detours are computed against are unaffected either way.
	undo = {}
	for address, original, replacement, _kind, _mnemonic in patches:
		offset = raddr + (address - vaddr)
		if bytes(data[offset:offset + len(original)]) != original:
			raise SystemExit(f"0x{address:x}: bytes on disk do not match")
		undo[address] = (offset, original)
		data[offset:offset + len(original)] = replacement

	# Lay the stubs out. The section's address is not known until its size
	# is, and the size depends on the stubs, which depend on the address --
	# so measure with a placeholder address first, then build for real.
	stub_base = stub_base_of(bytes(data))
	# **A pool spill writes, and code sections are not writable.** The first
	# build of it stored into the stub section and every run died at
	# 0xC0000005. Making the stub section writable would work and would make
	# it W+X, so the slot goes in a section of its own -- one page of
	# writable data, laid down FIRST so that both addresses are known before
	# a single displacement is computed.
	spill_base = 0
	if SPILL == SPILL_POOL:
		spill_base = stub_base
		stub_base += SECTION_ALIGNMENT
	# **The largest remaining bucket was the one with no reason.** `build_stub`
	# returned None and nothing said why, so 3,959 refusals reconciled to
	# "refused" and stopped there -- and Finding 45 had to walk its three
	# steps by hand to find out that a swallowed instruction wanted a scratch.
	# Every failure path names itself now. Finding 88.
	stub_reasons = Counter()
	instructions, _plain, blocked, sources, _tables, _seen = context

	# **A window that swallows a VEX.128 write loses its upper-half
	# zeroing, and reverting cannot reach it.** The passenger is re-emitted
	# inside the stub as legacy SSE, so there is nothing on disk to put
	# back -- the only repair is to not place that window, which costs the
	# site and keeps the bytes right. Same trade as Finding 187's revert,
	# one layer out.
	#
	# It iterates because dropping a window un-swallows everything it
	# covered, which can make a reader that was inside it survive and
	# expose a producer of its own. Bounded: each round drops at least one
	# candidate or stops, and the list only shrinks. Finding 197.
	placed, blob, overlapped, refused, dropped, swallowed = \
		repaired_placement(instructions, blocked, sources, candidates,
		                   set(undo), stub_base, spill_base, stub_reasons,
		                   home, tls_pair_of(tls_here))
	del swallowed
	if dropped:
		print(f"apply: {len(dropped):,} window(s) not placed, each having "
		      f"swallowed a VEX.128 write whose zeroing a surviving "
		      f"256-bit instruction still reads")
		from pathlib import Path	# imported here as elsewhere in this file
		roll = Path("build") / "repair-readers.txt"
		if roll.parent.is_dir():
			with roll.open("w", encoding="utf-8") as out:
				# **Name the image, because the path is fixed.** Finding
				# 240 wrote this rule for `frontier-sites.txt` and these
				# two files were added without it: a `check-pe` run
				# overwrote Starfield's 903 readers and 2,889 edges with
				# a fixture's one and one, and nothing said so. It was
				# caught only because 40 bytes is obviously not an
				# edge list -- a fixture with more rows would have read
				# as data. Finding 302.
				out.write(f"# {binary}\t{len(REPAIR_READERS)} "
				          f"distinct reader(s)\t"
				          f"{run_configuration()}\n")
				for at in sorted(REPAIR_READERS):
					out.write(f"{at:#x}\n")
			print(f"apply:   {len(REPAIR_READERS):,} distinct surviving "
			      f"reader(s) did the blaming, written to {roll}")
		# **Do the sites inside a dropped window have candidates of
		# their own?** 81% of the withheld windows are avalanche
		# rather than root blame -- dropping one un-swallows its
		# members, which become surviving 256-bit readers and blame
		# further windows. If those members are candidates in their
		# own right they should place once the window covering them
		# is gone; if they are passengers with no candidate, they have
		# no second chance and the avalanche has no brake.
		# Finding 305.
		starts = {item[0] for item in candidates}
		widths = {item[0]: item[4] for item in candidates}
		sites = sorted(row[0] for row in instructions
		               if row[1][:1] in (b"\xc4", b"\xc5"))
		inside, standalone = 0, 0
		for window in dropped:
			width = widths.get(window, 0)
			for at in sites[bisect.bisect_left(sites, window):
			                bisect.bisect_left(sites, window + width)]:
				inside += 1
				standalone += at in starts
		print(f"apply:   {inside:,} VEX site(s) lie in dropped windows; "
		      f"{standalone:,} are candidates in their own right and "
		      f"{inside - standalone:,} are passengers with none")
		edges = Path("build") / "repair-blame.txt"
		if edges.parent.is_dir():
			# **The extent, because a reader is a SITE and a window is a
			# RANGE.** The roll carried the window's first byte and the
			# reader's address and nothing else, so a reader that is a
			# mid-window passenger could not be attributed to the window
			# holding it: a walk up the blame graph stopped at any reader
			# that was not itself a window start. 437 of 443 starts are
			# frontier sites and 65 of that class's sites are passengers,
			# so the closure was wrong by exactly those and reported no
			# cycles where it could not have found one.
			#
			# That is Finding 310's defect -- keying on a start where an
			# extent is meant -- for the third time in this file, and here
			# it was in the diagnostic rather than in the census. A roll
			# that cannot answer the question it was written for reads
			# exactly like a roll that answers it and finds nothing.
			#
			# `end` is a byte address rather than the instruction count,
			# so a consumer can map a reader to its window without
			# parsing the listing. Finding 314.
			order = [row[0] for row in instructions]
			place = {address: i for i, address in enumerate(order)}
			with edges.open("w", encoding="utf-8") as out:
				out.write(f"# {binary}\t{run_configuration()}\t"
				          f"window\treader\twidth\tend\n")
				for window in sorted(REPAIR_BLAMED_BY):
					if window not in dropped:
						continue
					width = widths.get(window, 0)
					i = place.get(window)
					end = (order[i + width]
					       if i is not None and i + width < len(order)
					       else window)
					for reader in sorted(REPAIR_BLAMED_BY[window]):
						out.write(f"{window:#x}\t{reader:#x}\t"
						          f"{width}\t{end:#x}\n")
			print(f"apply:   the blame edges for dropped windows "
			      f"written to {edges}")
		print(f"apply:   the repair settled after {len(REPAIR_DECAY):,} "
		      f"of {REPAIR_ROUNDS:,} round(s); guilty per round "
		      f"{', '.join(str(n) for n in REPAIR_DECAY)}")
		# **Say so while there is still room, because the other side of
		# this bound is not a worse image but no image at all.** The
		# cap was found at 56 of 64 having been documented as 15, and
		# nothing reported the margin closing over two default flips.
		# Finding 298.
		if len(REPAIR_DECAY) * 2 > REPAIR_ROUNDS:
			print(f"apply:   WARNING: that is more than half of "
			      f"ANTI_AVX_REPAIR_ROUNDS={REPAIR_ROUNDS:,}. Exceeding "
			      f"it is a refusal to build, not a worse image -- "
			      f"re-measure the bound before it is reached.")
		# **Split by why, because the total cannot say where to push.**
		# A window with no ladder behind it and one that walked every
		# rung and found each of them blamed are the same number and
		# want opposite work -- the first wants a ladder for that
		# strategy, the second wants a different kind of alternative.
		# Sites as well as windows, since a window is not a unit of
		# loss and the census counts sites. Finding 298.
		# `strategy` is None on a candidate the collector built
		# without one, so it is named rather than formatted as a
		# number would be -- the first version passed None straight to
		# an f-string width and the apply died with a TypeError after
		# printing the line above it. It was invisible because the run
		# was read through a grep for the lines expected, which is the
		# reduction `evidence.md` warns about doing before knowing a
		# run passed.
		for (kind, why), count in sorted(
				REPAIR_DROPPED_WHY.items(), key=lambda row: -row[1]):
			print(f"apply:   {str(kind):<10} {why:<44} "
			      f"{count:>6,} window(s), "
			      f"{REPAIR_DROPPED_SITES[(kind, why)]:>6,} site(s)")
		for (kind, where), count in sorted(
				REPAIR_BLAME_WHERE.items(), key=lambda row: -row[1]):
			print(f"apply:     blamed on {str(kind):<8} "
			      f"{where:<42} {count:>6,}")
		for (kind, gained), count in sorted(
				REPAIR_SPLITTABLE.items(), key=lambda row: -row[1]):
			says = ("a gap still holds a site: splitting would place it"
			        if gained else
			        "no gap holds a site: nothing to place either side")
			print(f"apply:     {str(kind):<10} {says:<52} {count:>6,}")

	# **A VEX.128 write that stops zeroing, where somebody still looks.**
	# Patching one in place turns it into legacy SSE, which leaves bits
	# 255:128 alone -- and 29 surviving 256-bit readers observed exactly
	# that. There is no SSE instruction that writes an upper half, so the
	# only repair is to leave the VEX form standing: it costs the site and
	# keeps the bytes right. Reverting cannot cascade, because a 128-bit
	# write reads no upper half of its own. Finding 187.
	stale, unresolved, unsure = stale_upper_reads(
		instructions, blocked, sources, placed, set(undo), conservative=True)
	# **The conservative rows are repaired exactly like the certain ones.**
	# A candidate the walk could not rule out is kept in its VEX form, at
	# the price of the site: `apply` cannot tell the two apart and must not
	# try. Finding 198.
	kept = len({producer for _r, _f, producer in unsure})
	# The conservative half is dropped only under sabotage, which leaves
	# those candidates narrowed in the image for `verify` to catch: no
	# corrupted artifact can express "a repair that did not happen", so this
	# check needs a code control like `badrow`'s. Finding 237.
	stale = stale + ([] if CODE_SABOTAGE == "conservative" else unsure)
	covered = set()
	for site, window, _stub, _size, _prologue in placed:
		covered.update(range(site, site + window))
	reverted, stuck = set(), []
	for reader, field, producer in stale:
		if producer in undo and producer not in covered:
			if producer not in reverted:
				offset, original = undo[producer]
				data[offset:offset + len(original)] = original
				reverted.add(producer)
			continue
		# **A stale read a revert cannot repair.** Either the producer is
		# not an in-place patch at all, or it is one inside a window --
		# and a revert inside a window is overwritten by the jump written
		# over that window a moment later, which is worse, because it
		# looks repaired. `repaired_placement` withholds those windows, so
		# anything still here is a producer neither mechanism reaches.
		# Silence shipped 5 wrong readers once already: `apply` counted
		# them among the 52 it reported and repaired only the 45 it could,
		# and the difference was visible nowhere until `verify` read the
		# image. Findings 194 and 197.
		stuck.append((reader, field, producer))
	# **Two different failures were being reported as one sentence.** A
	# producer inside a window is a repair that did not finish; a producer
	# that is not an in-place patch at all is a site no mechanism here
	# reaches. The first is a bug and the second is a floor, and calling
	# both "not an in-place patch" sent every reader of this line at the
	# wrong one -- which is how a cap set too low read as an ISA limit for
	# as long as it did. `repaired_placement` settles or refuses now, so
	# the first count must be zero; it is printed rather than asserted
	# because a wrong image is worth a sentence even when it cannot
	# happen. Finding 259.
	inside = [row for row in stuck if row[2] in covered]
	outside = [row for row in stuck if row[2] not in covered]
	if inside:
		print(f"apply: {len(inside):,} stale read(s) whose producer sits "
		      f"inside a placed window -- the repair did not finish and "
		      f"these bytes are wrong", file=sys.stderr)
		for reader, field, producer in sorted(inside)[:8]:
			print(f"    0x{reader:x} reads {field}, decided at "
			      f"0x{producer:x}", file=sys.stderr)
	if outside:
		print(f"apply: {len(outside):,} stale read(s) whose producer is not "
		      f"an in-place patch and cannot be reverted", file=sys.stderr)
		for reader, field, producer in sorted(outside)[:8]:
			print(f"    0x{reader:x} reads {field}, decided at "
			      f"0x{producer:x}", file=sys.stderr)
	if reverted:
		# Distinct READERS, because `stale` now carries one row per
		# rewritten producer and a reader at a join has several.
		readers = len({reader for reader, _field, _producer in stale})
		print(f"apply: {len(reverted):,} in-place patch(es) reverted, their "
		      f"zeroing still read by {readers:,} surviving 256-bit "
		      f"instruction(s)")
	if kept:
		print(f"apply: {kept:,} of those are conservative -- a reader the "
		      f"walk could not resolve, and a patched VEX.128 write to its "
		      f"register before the nearest call")
	if unresolved:
		print(f"apply: {unresolved:,} upper-half source(s) the walk could "
		      f"not resolve, which this cannot speak for")

	for site, window, stub_address, _length, _prologue in placed:
		offset = raddr + (site - vaddr)
		jump = encode_jump(site + 5, stub_address)
		pad = window - 5
		data[offset:offset + window] = jump + inplace.nop_padding(pad)

	# **Before the section is made, because both change the blob.** The
	# table names every placeholder by RVA and the callback is appended
	# after it, so neither can be written until the stub bytes are final
	# and the section's base is known. Finding 293.
	staged = bytes(data)
	pe = struct.unpack_from("<I", staged, 0x3C)[0]
	image_base = struct.unpack_from("<Q", staged, pe + 24 + 24)[0]
	if SPILL == SPILL_POOL:
		staged, data_va = add_section(staged, DATA_NAME, bytes(16), DATA_FLAGS)
		assert data_va == spill_base - image_base, "spill section moved"
	# The callback writes into this section at load time, so it has to be
	# writable when `--index-const` is on and not otherwise.
	image, section_va = add_section(staged, SECTION_NAME, bytes(blob),
	                                INDEX_CALLBACK_FLAGS
	                                if (INDEX_CONST and
	                                    index_placeholders(blob))
	                                else SECTION_FLAGS)
	assert section_va == stub_base - image_base, "stub section moved"

	# **Unwind data for the stubs.** Without it an exception raised inside
	# one is never dispatched: the section has no entry, the unwinder assumes
	# a leaf, and reads a return address out of an `[rsp]` that never held
	# one. Measured in Finding 46, fixed here.
	#
	# The `.xdata` goes down before the `.pdata` because a RUNTIME_FUNCTION
	# names its unwind block by address, so that address has to exist first.
	# Both sizes are known before either is placed -- the blocks hold only
	# the primary's own entry, which is a `.text` address.
	extents, prologues = [], []
	ordered = sorted(placed, key=lambda item: item[2])
	for site, _window, stub_address, length, prologue in ordered:
		extents.append((stub_address - image_base,
		                stub_address + length - image_base,
		                site - image_base))
		prologues.append(prologue)
	xdata_rva = next_section_rva(image)
	xdata, pdata = stub_unwind(extents, prologues, image_base,
	                           existing_pdata(image), xdata_rva)
	image, got = add_section(image, XDATA_NAME, xdata, UNWIND_FLAGS)
	assert got == xdata_rva, "unwind section moved"
	pdata_rva = next_section_rva(image)
	image, got = add_section(image, PDATA_NAME, pdata, UNWIND_FLAGS)
	# **The index section, last, and in a section of its own.** It holds
	# the patch table and the callback; `.avxsse` is verified as pure code
	# and this is data plus one 48-byte routine, so putting it there
	# produced four failures. Finding 294.
	# **Nothing to patch means nothing to emit.** An image with no TLS
	# directory has no per-thread block, so no stub stands a pointer up and
	# no placeholder exists -- most fixtures are like that. Making the
	# default `on` turned that into "needs a TLS directory" and every one
	# of them failed to build. Finding 295.
	if INDEX_CONST and index_placeholders(blob):
		global INDEX_CONST_CALLBACK
		payload, code_off, slot, was = index_payload(image, blob, stub_base)
		image, index_va = add_section(image, INDEX_NAME, payload,
		                              INDEX_FLAGS)
		image = bytearray(image)
		base = struct.unpack_from("<Q", bytes(image),
		                          struct.unpack_from("<I", bytes(image),
		                                             0x3C)[0] + 24 + 24)[0]
		struct.pack_into("<Q", image, slot, base + index_va + code_off)
		image = bytes(image)
		INDEX_CONST_CALLBACK = True
		print(f"apply: index section {INDEX_NAME.decode().rstrip(chr(0))} "
		      f"at 0x{base + index_va:x}, {len(payload):,} bytes; the TLS "
		      f"callback array's first slot was 0x{was:x}")
	assert got == pdata_rva, "function table moved"
	image = bytearray(image)
	pe = struct.unpack_from("<I", bytes(image), 0x3C)[0]
	struct.pack_into("<II", image, pe + 24 + 112 + EXCEPTION_DIRECTORY * 8,
	                 pdata_rva, len(pdata))

	# **The slot has to be asked for or it is not there.** Raising
	# `SizeOfZeroFill` is what makes the loader hand every thread the bytes
	# past the module's template, and `make check-tls` is what proves it
	# does -- Finding 138 swept the field and got a different answer for
	# every value, so the pass depends on this write rather than on the
	# template happening to be copied. Written last, after every section is
	# added, because the directory is addressed by RVA and nothing here
	# moves it.
	if tls_here is not None:
		image = bytearray(set_tls_zero_fill(bytes(image), tls_here[2]))

	open(output, "wb").write(bytes(image))
	# **What the image actually holds, which is neither the plan nor the
	# plan minus the reverts.** `len(patches)` is what `collect` intended;
	# subtracting the reverts of Finding 187 was closer but still counted
	# 28,513 sites that were patched and then OVERWRITTEN by a placed
	# detour window -- they are detours in the shipped binary, not in-place
	# patches, and the label says in-place patches. Finding 189.
	covered_bytes = set()
	for site, length, _stub, _size, _prologue in placed:
		covered_bytes.update(range(site, site + length))
	in_place = sum(1 for row in patches
	               if row[0] not in reverted and row[0] not in covered_bytes)
	print(f"apply: {in_place:,} in-place patches, "
	      f"{len(placed):,} detours, "
	      f"{len(overlapped):,} skipped for overlap, {len(refused):,} refused")
	for why, count in stub_reasons.most_common():
		print(f"apply:   refused, {why:<38} {count:>8,}")
	if STUB_DETAIL:
		from pathlib import Path	# imported here as elsewhere in this file
		roll = Path("build") / "stub-refused.txt"
		if roll.parent.is_dir():
			with roll.open("w", encoding="utf-8") as out:
				out.write(f"# {binary}\t{len(STUB_DETAIL):,} refused\t"
				          f"{run_configuration()}\n")
				out.write("# reason\tsite\twindow\tstrategy\n")
				for start in sorted(STUB_DETAIL):
					why, window, _p, _d, how = STUB_DETAIL[start]
					out.write(f"{why}\t{start:#x}\t{window}\t{how}\n")
			print(f"apply: every refused stub written to {roll}")
	if UNIT_RUNG:
		# **What the ladder cost, which the refusal roll cannot show.** The
		# first rung is the window the strategy wants; everything below it
		# is a window shortened to find a helper, and a shorter window is
		# one more likely to be overlapped. Finding 317.
		taken = sum(UNIT_RUNG.values())
		best = UNIT_RUNG.get((UNIT_LIMITS[0], "forward"), 0)
		print(f"apply: unit windows by the rung they were taken at, of "
		      f"{taken:,}: {best:,} at the full {UNIT_LIMITS[0]} forward "
		      f"({100 * best / taken:.1f}%), the rest shortened or reversed "
		      f"to find a helper")
		for (cap, way), count in sorted(
				UNIT_RUNG.items(), key=lambda kv: (-kv[1], kv[0])):
			print(f"apply:   {cap:>3} member(s) {way:<8} {count:>8,}")
	report_regions(candidates, binary)
	report_units(candidates, placed, home, WIDE_SITES["256-bit"],
	             binary)
	report_placement(candidates, placed, overlapped, refused)
	report_cost(candidates, placed, home)
	if REPAIR_SUBSTITUTED:
		print(f"apply: the stale-read repair rebuilt {REPAIR_SUBSTITUTED:,} "
		      f"window(s) to exclude what it blamed them for, rather than "
		      f"dropping them")
	# **An unpatched placeholder is a wrong image that verifies clean.**
	# `verify` re-derives the placement and checks structure; it has no
	# opinion about the value of a displacement, so an image emitted with
	# `INDEX_CONST` and no callback to fill the placeholders in would pass
	# every check and address whatever `0x5a5a5a5a` happens to reach.
	# Until the callback is emitted, this refuses rather than writes.
	# Finding 293.
	if INDEX_CONST:
		# **Count the artifact, not the calls.** `INDEX_CONST_SITES`
		# counts every call to `encode_tls_base`, and the collector calls
		# it for candidates it never places and for every rung of the
		# ladder -- 1,163,501 of them against 19,174 stubs that actually
		# stand a block pointer up. A patch table built from that number
		# would be meaningless. What matters is how many placeholders are
		# in the blob that ships, which is what gets patched, so the blob
		# is what is counted.
		#
		# The search is anchored on the instruction and not on the value:
		# `8b`, a modrm with mod 10 and reg equal to rm, then the
		# placeholder. `0x5a5a5a5a` alone occurs in the constant pool.
		# Finding 293.
		wanted = set()
		for number in sorted(GPR_NUMBERS.values()):
			wanted.add(bytes([0x8B, 0x80 | ((number & 7) << 3) | (number & 7)])
			           + struct.pack("<I", INDEX_PLACEHOLDER))
		found = 0
		for pattern in wanted:
			start = 0
			while True:
				start = blob.find(pattern, start)
				if start < 0:
					break
				found += 1
				start += 1
		if found and not INDEX_CONST_CALLBACK:
			raise SystemExit(
				f"apply: {found:,} stub(s) in the blob carry an unfilled "
				f"TLS index placeholder and no callback was emitted to "
				f"fill them. Refusing to write an image whose block "
				f"pointers would address 0x{INDEX_PLACEHOLDER:x}.")
	# **The same refusal for the scratch displacement**, and it is not
	# the same condition: the index placeholder and the TEB one are
	# filled by the same callback but emitted by different routes, so a
	# build can carry one and not the other. An unfilled scratch disp32
	# is worse than an unfilled index -- the index makes a stub read the
	# wrong block, while this makes it WRITE eight bytes at
	# `%gs:0x5b5b5b00`, far outside the TEB. Finding 297.
	stray = sum(len(one) for one in teb_placeholders(blob))
	if stray and not INDEX_CONST_CALLBACK:
		raise SystemExit(
			f"apply: {stray:,} stub(s) in the blob carry an unfilled TEB "
			f"scratch displacement and no callback was emitted to fill "
			f"them. Refusing to write an image whose stubs would write "
			f"to %gs:0x{TEB_PLACEHOLDER:x}.")
	print(f"apply: stub section .avxsse at 0x{stub_base:x}, "
	      f"{len(blob):,} bytes")
	print(f"apply: {len(pdata) // 12:,} function table entries "
	      f"({len(xdata):,} bytes of unwind info) at 0x{pdata_rva + image_base:x}")
	return 0


def is_call(data, at):
	"""True if a near call begins at this file offset.

	Read from the bytes rather than from a disassembly, so that counting
	the swallowed calls costs nothing beside a pass this function already
	makes. `e8` is call rel32; `ff` with a modrm reg field of 2 is the
	indirect form, and either may carry a REX prefix.
	"""
	while at < len(data) and 0x40 <= data[at] <= 0x4F:
		at += 1				# REX, which carries no opcode
	if at >= len(data):
		return False
	if data[at] == 0xE8:
		return True
	return data[at] == 0xFF and at + 1 < len(data) \
		and ((data[at + 1] >> 3) & 7) == 2


# The 64-bit name, the 32-bit name and the byte name are one register, and
# a stub that writes `%eax` has written `%rax` -- a 32-bit write zeroes the
# top half rather than leaving it. Built from GPR_NUMBERS so a register
# cannot be in one table and not the other.
GPR_ALIASES = {}
for _name, _number in GPR_NUMBERS.items():
	GPR_ALIASES[_name] = _number
	if _name.startswith("r") and _name[1:].isdigit():
		for _suffix in ("d", "w", "b"):
			GPR_ALIASES[_name + _suffix] = _number
	else:
		GPR_ALIASES["e" + _name[1:]] = _number
		GPR_ALIASES[_name[1:]] = _number
		GPR_ALIASES[_name[1] + "l"] = _number


def stub_gpr_problems(text, placed, home, base, size,
                      instructions):
	"""Registers a stub clobbers that the site was still using.

	**The one class every other check in this file is blind to.** `verify`
	reads decoding, VEX survival, stale upper halves and structure; none of
	them looks at a general-purpose register. Finding 264 was exactly that
	-- mode True loaded the TLS index into `%rax` and never put it back,
	while the original set `%rax` to zero four instructions above the site
	and read it five below -- and it passed every gate here, on every run,
	for as long as it existed. It was found by sizing an unrelated
	optimisation, which is luck rather than method.

	The invariant is the one the emitter already believes: **a stub may
	clobber a general-purpose register only where that register is dead
	across the window, or where the stub saves and restores it itself.**

	**A stub also RE-EMITS the instructions its window swallowed**, and
	those write general-purpose registers exactly as the original program
	did. The first version of this counted them and reported 20,631 of
	33,215 stubs -- 62%, which is a detector fault rather than a defect
	rate, and it is what a gate looks like just before somebody switches it
	off with an ignore list. A register the original window wrote is
	therefore allowed too.

	This reads the emitted disassembly rather than the plan, so it cannot
	agree with the generator by construction the way a regenerate-and-diff
	gate does. What it knows about the site comes from `window_gpr_free`,
	which is the same question the collector asks -- but asked of the
	FINISHED bytes, so a mode chosen for one reason and emitted under
	another is caught between the two. Finding 266.
	"""
	rows = []
	for line in text.splitlines():
		head, _tab, rest = line.partition("\t")
		if not rest or ":" not in head:
			continue
		try:
			at = int(head.strip().rstrip(":"), 16)
		except ValueError:
			continue
		body = rest.partition("\t")[2].strip()
		if not body:
			continue
		rows.append((at, body))
	rows.sort()
	starts = [at for at, _b in rows]

	def targets_of(operands, mnemonic):
		"""The general-purpose register an AT&T operand list writes."""
		operands = (operands or "").split("#")[0].strip()
		fields = inplace.split_operands(operands) if operands else []
		if len(fields) < 2 or mnemonic.startswith("j"):
			return None, None
		return fields[0], fields[-1]

	sites = sorted(a for a, _e, _m, _o, *_r in instructions)
	rows_by_site = {a: (m, o) for a, _e, m, o, *_r in instructions}

	problems = []
	for site, window, stub_at, stub_size, _prologue in placed:
		if not (base <= stub_at < base + size):
			continue
		lo = bisect.bisect_left(starts, stub_at)
		hi = bisect.bisect_left(starts, stub_at + stub_size)
		written = set()
		saved, restored = defaultdict(set), defaultdict(set)
		for _at, body in rows[lo:hi]:
			mnemonic, _sp, operands = body.partition(" ")
			operands = operands.split("#")[0].strip()
			if not operands or mnemonic.startswith("j"):
				continue
			fields = inplace.split_operands(operands)
			if len(fields) < 2:
				continue
			source, target = fields[0], fields[-1]
			# A destination that is a register is written; one that is
			# memory is not, and is a SAVE when its source is a register.
			if target.startswith("%"):
				number = GPR_ALIASES.get(target[1:])
				if number is None:
					# **An xmm destination taking a GPR is a STASH**, and
					# it is how mode True frees the index register:
					# `movq %rcx,%xmm4` ... `movq %xmm4,%rcx`. Memory is
					# not the only place a register can be kept, and
					# reading only memory reported 257 correct stubs as
					# clobbering the very register they had just put
					# back -- the mechanism at the heart of Finding 264,
					# working, called a fault by the gate written for it.
					held = (GPR_ALIASES.get(source[1:])
					        if source.startswith("%") else None)
					if held is not None and mnemonic.startswith("mov"):
						saved[held].add(target)
					continue
				written.add(number)
				# A restore reads from somewhere that is not another GPR:
				# memory, or the xmm a stash put it in.
				if mnemonic.startswith("mov") and (
						not source.startswith("%")
						or GPR_ALIASES.get(source[1:]) is None):
					restored[number].add(source)
			elif source.startswith("%"):
				number = GPR_ALIASES.get(source[1:])
				if number is not None and mnemonic.startswith("mov"):
					saved[number].add(target)
		# **Saved AND restored to the SAME place, or it is not
		# preserved.** A save with no matching restore is a register left
		# clobbered with extra steps.
		#
		# Locations are sets rather than one apiece, because the mover
		# does its own work through `mov %reg,mem` as well: keyed by
		# register alone, its last data store overwrote the record of
		# where it had been saved, and %rdx was reported clobbered in
		# almost every stub. That took the first control to 20,502 of
		# 33,215, and the reading of one stub to explain.
		preserved = {n for n in saved if saved[n] & restored[n]}
		# What the ORIGINAL window wrote, which the stub re-emits.
		lo_o = bisect.bisect_left(sites, site)
		hi_o = bisect.bisect_left(sites, site + window)
		theirs = set()
		for address in sites[lo_o:hi_o]:
			mnemonic, operands = rows_by_site[address]
			source, target = targets_of(operands, mnemonic or "")
			if target and target.startswith("%"):
				number = GPR_ALIASES.get(target[1:])
				if number is not None:
					theirs.add(number)
		dead = set(window_gpr_free(home, site, window))
		loose = written - preserved - dead - theirs
		if loose:
			problems.append((site, stub_at, sorted(loose)))
	return problems


def verify(original, patched, listing=None):
	a = open(original, "rb").read()
	b = open(patched, "rb").read()
	problems = 0
	print(f"verify: {len(a):,} -> {len(b):,} bytes "
	      f"(+{len(b) - len(a):,} for the appended sections)")

	faults = header_problems(b)
	if faults:
		for fault in faults:
			print(f"verify: FAILED -- {fault}", file=sys.stderr)
		problems += len(faults)
	else:
		print("verify: the image headers are self-consistent")

	# **Every stub has to be findable by the unwinder.** The exception
	# directory must point at the rebuilt function table, that table must
	# still be sorted -- `RtlLookupFunctionEntry` binary-searches it -- and
	# every stub address must fall inside an entry. Finding 46 measured what
	# the absence of this costs: an exception raised in a stub is never
	# dispatched at all.
	pe = struct.unpack_from("<I", b, 0x3C)[0]
	rva, size = struct.unpack_from("<II", b,
	                               pe + 24 + 112 + EXCEPTION_DIRECTORY * 8)
	at = rva_to_offset(b, rva) if rva and size else None
	table = []
	if at is not None:
		for i in range(size // 12):
			table.append(struct.unpack_from("<III", b, at + i * 12))
	stubs = section_named(b, SECTION_NAME)
	if not table:
		print("verify: FAILED -- no function table", file=sys.stderr)
		problems += 1
	elif sorted(table) != table:
		print("verify: FAILED -- the function table is not sorted",
		      file=sys.stderr)
		problems += 1
	elif stubs is None:
		print("verify: FAILED -- no stub section", file=sys.stderr)
		problems += 1
	else:
		svaddr, svsize, _sraddr, _srsize = stubs
		described = 0
		for begin, end, _unwind in table:
			if svaddr <= begin < svaddr + svsize:
				described += end - begin
		# The section is the constant pool followed by nothing but stubs,
		# so every byte past the pool must be inside an entry -- exactly,
		# not approximately. A stub the unwinder cannot find is a stub an
		# exception cannot be dispatched from.
		gap = svsize - len(PERMIL_POOL) - described
		if gap:
			print(f"verify: FAILED -- {gap:,} bytes of stub outside every "
			      f"function table entry", file=sys.stderr)
			problems += 1
		else:
			print(f"verify: function table has {len(table):,} entries, "
			      f"sorted, and covers every byte of stub past the "
			      f"{len(PERMIL_POOL)}-byte pool")

	vaddr, raddr, size = inplace.text_mapping(original)
	tail_a, tail_b = a[raddr + size:], b[raddr + size:len(a)]
	if tail_a == tail_b:
		print("verify: every section after .text is byte-identical")
	else:
		# **One field may differ, and exactly one.** `--spill=tls` raises
		# `SizeOfZeroFill` so the loader hands every thread the sixteen
		# bytes the stubs address. Everything else outside `.text` is the
		# program's and is not ours to touch.
		#
		# Written as an identity rather than as a skip: put the rewritten
		# field back into the original's bytes and the two must be equal
		# again. A check that merely tolerated a difference somewhere in
		# the TLS directory would tolerate a difference anywhere in it,
		# and the directory holds four pointers this must never move.
		raised = None
		found = tls_directory(bytes(a))
		if found is not None and len(tail_a) == len(tail_b):
			restored = bytearray(tail_a)
			at = found[0] + 32 - (raddr + size)
			ok = 0 <= at and at + 4 <= len(tail_a)
			if ok:
				restored[at:at + 4] = tail_b[at:at + 4]
			# **And the one callback slot, when `--index-const` is on.**
			# A load-time callback has to be reachable from the image's
			# TLS callback array, and that array is after `.text` in any
			# real binary -- so is the directory that points at it. There
			# is no version of this that touches nothing out here.
			#
			# Written the same way as the field above: put the rewritten
			# eight bytes back and the rest must be equal again. A skip
			# would tolerate a difference anywhere in the array, and the
			# array is a list of function pointers the loader calls.
			# Finding 294.
			if ok and INDEX_CONST:
				pe_a = struct.unpack_from("<I", bytes(a), 0x3C)[0]
				base_a = struct.unpack_from("<Q", bytes(a),
				                            pe_a + 24 + 24)[0]
				slot = rva_to_offset(bytes(a), found[1][3] - base_a)
				spot = None if slot is None else slot - (raddr + size)
				if spot is None or not (0 <= spot and
				                        spot + 8 <= len(tail_a)):
					ok = False
				else:
					restored[spot:spot + 8] = tail_b[spot:spot + 8]
			if ok and bytes(restored) == bytes(tail_b):
				raised = struct.unpack_from("<I", bytes(tail_b), at)[0]
		if raised is None:
			print("verify: FAILED -- sections after .text changed",
			      file=sys.stderr)
			problems += 1
		else:
			# **Name every exemption, not the first one.** This said
			# "except SizeOfZeroFill" while two fields were being
			# restored, so the line understated what it had allowed --
			# in the one check whose whole job is to say that nothing
			# outside `.text` moved. Finding 294.
			allowed = [f"SizeOfZeroFill, raised to {raised} so the loader "
			           f"allocates the per-thread slot"]
			if INDEX_CONST:
				allowed.append("the TLS callback array's first slot, which "
				               "now names the index callback and tail-jumps "
				               "to what it replaced")
			print(f"verify: every section after .text is byte-identical "
			      f"except {' and '.join(allowed)}")

	# **The feature tests, which decide what the CPU is asked to run.** 179
	# EVEX instructions in this image are unreachable only because a runtime
	# CPUID/XGETBV test says so, and nothing checked that the rewrite left
	# that test alone -- the failure it would cause looks like a crash
	# somewhere else entirely. Finding 5 named the risk and Finding 121
	# closes it. `isa_guard` runs its own control before it is allowed to
	# pass, and says so when the image is not the one its manifest names.
	if listing is None:
		print("verify: NOT RUN -- the dispatcher check needs the listing",
		      file=sys.stderr)
		problems += 1
	else:
		problems += isa_guard.check(original, patched, listing)

	before_bounds, before_vex, before_bad = inplace.disassemble(original)
	after_bounds, after_vex, after_bad = inplace.disassemble(patched)
	print(f"verify: VEX in .text {len(before_vex):,} -> {len(after_vex):,}"
	      f"  ({len(before_vex) - len(after_vex):,} removed, "
	      f"{100.0 * (len(before_vex) - len(after_vex)) / len(before_vex):.1f}%)")
	# **Counted apart from the frontier, and still counted.** These begin
	# with a VEX prefix byte and decode to nothing, so they are not
	# surviving instructions and were inflating the number this project
	# quotes by 5.9%. They are reported rather than dropped because
	# objdump is wrong about this image at least twice already, and a
	# silent discard could hide a real survivor. Finding 290.
	if before_bad or after_bad:
		print(f"verify: and {len(after_bad):,} VEX-prefixed byte sequence(s) "
		      f"that decode to nothing, which are not instructions "
		      f"(was {len(before_bad):,})")
	# Boundaries. A widened window deliberately swallows the instruction
	# after the site, so that address stops being a boundary -- which is
	# intended, and is exactly the thing that has to be justified rather
	# than tolerated. Every lost boundary must be one that was swallowed on
	# purpose, and none of them may be somewhere anything can branch to.
	lost = before_bounds - after_bounds
	if listing is None:
		if lost:
			print(f"verify: {len(lost):,} boundaries lost; pass the listing "
			       "to check they were swallowed deliberately")
		return 1 if problems else 0

	context = analysis_context(original, listing)
	patch_rows, candidates, _stats, _skipped, declined_rows, home = collect(
		original, listing, context)
	instructions, _plain, blocked, sources, _tables, _seen = context
	# **A data island must not reach the candidate loop.** `decode_vex`
	# rejects on LENGTH alone -- under three bytes, or a `c4` under four --
	# and never checks the map field, so a constant pool's `c5 32 00`
	# decodes as a VEX prefix and is offered to every strategy. What turned
	# those sites away was the mnemonic: objdump writes `(bad)` and no
	# strategy's table has an entry for one. That is the far wall of the
	# room rather than the door, and the 256-bit strategies already branch
	# on `vex["L"]` read straight out of the unvalidated prefix. Starfield
	# carries 180 such sequences in the islands of Finding 8 and 99 of them
	# reached the loop. Finding 222.
	# The in-place path is included because it is the one that rewrites
	# bytes where they lie: `build_patches` had the same incidental guard,
	# a mnemonic lookup in `classify`, at the site where a wrong answer
	# edits the image rather than building a stub. Finding 223.
	offered = ({item[0] for item in candidates} | set(declined_rows)
	           | {row[0] for row in patch_rows})
	intruders = sorted(row[0] for row in instructions
	                   if row[2] == "(bad)" and row[0] in offered)
	if intruders:
		print(f"verify: {len(intruders):,} (bad) row(s) reached the candidate "
		      f"loop, first at 0x{intruders[0]:x}", file=sys.stderr)
		problems += 1

	# **And the rewrite must never modify a byte inside a data island.**
	# The two guards above refuse data that FAILS to decode. Neither can
	# see data that decodes CLEANLY, which is the case that would actually
	# corrupt: such a run carries a real mnemonic, satisfies `classify`,
	# and is patched like any site. So this asks the outcome rather than
	# the decision -- cluster the bytes objdump refused, and require that
	# none of them changed.
	#
	# It over-covers on purpose, sweeping in real code that lies between
	# two data runs, so a hit is a question to be read and a zero is the
	# strong answer. Its limit is worth knowing rather than discovering: it
	# can only see data holding at least one undecodable byte, so a jump
	# table that decodes end to end is in no population here. Measured on
	# Starfield BY THIS CHECK: 747 islands spanning 48,399 bytes, none
	# touched.
	#
	# **An ad-hoc probe of the same question said 742 and 47,500**, having
	# parsed the listing with its own tab-splitting rather than through
	# `parse_with_comments`. The safety answer was the same either way, and
	# the count was not; the figure quoted here is the one this check
	# produces, because that is the one anybody will read. Three parsers
	# have now given three tallies of `(bad)` lines -- 11,783, 11,892 and
	# 12,021 -- and none of them has been reconciled. Finding 224.
	tv, tr, ts = inplace.text_mapping(original)
	before_text = open(original, "rb").read()[tr:tr + ts]
	after_text = open(patched, "rb").read()[tr:tr + ts]
	islands = [(low - tv, high - tv) for low, high in data_islands(instructions)
	           if 0 <= low - tv and high - tv <= ts]
	touched = [(low, high) for low, high in islands
	           if before_text[low:high] != after_text[low:high]]
	span = sum(high - low for low, high in islands)
	if touched:
		low, high = touched[0]
		print(f"verify: {len(touched):,} data island(s) modified by the "
		      f"rewrite, first at 0x{low + tv:x}-0x{high + tv:x}",
		      file=sys.stderr)
		problems += 1
	else:
		print(f"verify: none of {len(islands):,} data island(s) "
		      f"({span:,} bytes) was modified")
	# **The same call apply makes -- through the same function, now.** This
	# said so in a comment while `apply` grew a repair pass this did not,
	# and the drift cost 15 reported stale reads the image did not have.
	# The repair takes the FULL patch set, as apply does when it decides,
	# because the question is which windows apply withheld; the stale check
	# below then reads the image. Finding 197.
	placed, _blob, _over, _refused, _dropped, swallowed = repaired_placement(
		instructions, blocked, sources, candidates,
		set(row[0] for row in patch_rows),
		stub_base_of(open(original, "rb").read()), 0, Counter(), home,
		tls_pair_of(tls_for(original)))
	groups = target_set.collect(original)
	reachable = set()
	for values in groups.values():
		reachable |= values

	unexplained = lost - swallowed
	# **A boundary inside the TLS directory is not a boundary.** The
	# directory is data, it sits in `.text` in some images, and this rewrite
	# raises its `SizeOfZeroFill` on purpose -- so the sweep decodes those
	# bytes differently afterwards and reports lost instructions that never
	# existed. Excluding the structure the PE header names is exact; an
	# ignore list of the three addresses would not be. Finding 196.
	span = tls_directory_span(open(original, "rb").read())
	if span and unexplained:
		low, high = span
		inside_tls = {a for a in unexplained if low <= a < high}
		if inside_tls:
			print(f"verify: {len(inside_tls):,} lost boundary/ies are inside "
			      f"the TLS directory at 0x{low:x}, which is data this "
			      f"rewrite edits on purpose")
			unexplained = unexplained - inside_tls
	# **And the callback array slot, for the same reason.** It is a list
	# of function pointers, it sits in `.text` in a fixture (a real image
	# keeps it in `.rdata`), and `--index-const` rewrites one entry of it
	# on purpose -- so the sweep decodes those eight bytes differently and
	# reports boundaries that were never instructions. Named from the
	# directory the PE header carries, exactly as the span above is.
	# Finding 295.
	if INDEX_CONST and unexplained:
		raw = open(original, "rb").read()
		found = tls_directory(raw)
		if found is not None:
			pe_raw = struct.unpack_from("<I", raw, 0x3C)[0]
			base_raw = struct.unpack_from("<Q", raw, pe_raw + 24 + 24)[0]
			low = found[1][3]
			inside_cb = {a for a in unexplained if low <= a < low + 8}
			if inside_cb:
				print(f"verify: {len(inside_cb):,} lost boundary/ies are "
				      f"inside the TLS callback array at 0x{low:x}, whose "
				      f"first entry this rewrite names on purpose")
				unexplained = unexplained - inside_cb
	if unexplained:
		print(f"verify: FAILED -- {len(unexplained):,} boundaries lost that "
		      f"were not swallowed on purpose", file=sys.stderr)
		for address in sorted(unexplained)[:8]:
			print(f"    0x{address:x}", file=sys.stderr)
		problems += 1
	else:
		print(f"verify: {len(lost):,} boundaries lost, every one an "
		      f"instruction a widened window swallowed deliberately")

	# **This one could never fail, and saying so is the point.** `reachable`
	# is `targets.collect` and the collector refuses to swallow anything in a
	# SUPERSET of it -- that set plus the listing's own direct branches plus
	# the lea targets -- so the intersection is empty by construction. It is
	# the same fault as Finding 52 in a different place: a decision checked
	# against the data that made it. Kept because it costs nothing and would
	# catch `targets.collect` returning different answers on two calls, and
	# reported as what it is.
	dangerous = swallowed & reachable
	if dangerous:
		print(f"verify: FAILED -- {len(dangerous):,} swallowed instructions "
		      f"are branch targets", file=sys.stderr)
		problems += 1
	else:
		print(f"verify: none of the {len(swallowed):,} swallowed instructions "
		      f"is in the target set (weak: the collector used it too)")

	# The independent form of the same question, which reads the two
	# disassemblies and nothing else. **Every address a direct branch names
	# in the original must still begin an instruction in the rewritten
	# binary** -- if a window swallowed one, that branch now lands in the
	# middle of the jump that replaced it. `targets.py` has no say here, and
	# neither does the collector: this is the output being asked whether it
	# is well formed, rather than the model being asked whether it agrees
	# with itself.
	#
	# It cannot speak for indirect targets -- switch tables, relocations,
	# addresses taken by lea -- for which `targets.py` remains the only
	# source and the check above remains the only check. That gap is real
	# and named rather than papered over.
	named = set()
	for address, encoding, mnemonic, operands in inplace.parse_listing(listing):
		del address, encoding
		if not mnemonic.startswith(("j", "call", "loop")) or not operands:
			continue
		first = operands.split()[0]
		if not first.startswith("0x"):
			continue
		try:
			named.add(int(first, 16))
		except ValueError:
			pass
	# **A branch inside data names an address that was never an instruction.**
	# Finding 8 counted 11,892 bytes of `.text` that do not disassemble, and
	# a linear sweep through them manufactures branches: a repeating
	# `7d e9 2c 00` after an `int3` decodes as a row of `jge`s whose targets
	# land in the middle of the function above. The first run of this check
	# reported exactly one failure and it was one of those.
	#
	# The filter needs no oracle and keeps the check independent: a target
	# that was not an instruction boundary in the ORIGINAL cannot have been a
	# real one, and a real target always was.
	inside = {a for a in named
	          if vaddr <= a < vaddr + size and a in before_bounds}
	broken = inside - after_bounds
	if broken:
		print(f"verify: FAILED -- {len(broken):,} direct branch targets no "
		      f"longer begin an instruction", file=sys.stderr)
		for address in sorted(broken)[:8]:
			print(f"    0x{address:x}", file=sys.stderr)
		problems += 1
	else:
		print(f"verify: all {len(inside):,} direct branch targets still begin "
		      f"an instruction")

	# **A branch target that still begins an instruction can still be
	# wrong, and the check above cannot tell.** A window that buries its
	# own member pads the bytes after its jump, so the target lands on a
	# `nop`, the sweep finds a boundary there and is content. What it has
	# landed in is a window whose work the jump already skipped: arriving
	# by the branch runs the padding, falls out of the far end, and misses
	# everything the stub would have done. Nothing crashes and the answer
	# is wrong.
	#
	# Every widening strategy refuses to cross a branch target, and until
	# this existed nothing watched any of those refusals. Disabling the
	# backward one left every check in this file green -- including the
	# swallowed-instruction check above, which looks like it covers this
	# and does not: the buried instruction is the window's MEMBER, not a
	# passenger it swallowed, so it is not in `swallowed` at all.
	#
	# The window start is excluded deliberately. A branch arriving there
	# hits the jump, which is the one place in a window it is correct to
	# arrive. Finding 279.
	# **Bisect rather than scan.** The obvious loop asks every target about
	# every window, which on this binary is 201,624 windows against 1.19
	# million targets: the first version of this check turned a seventeen
	# minute `verify` into one still running at thirty-nine. A gate that
	# slow is a gate somebody stops running.
	ordered = sorted(inside)
	buried = set()
	for window_at, window_len, *_rest in placed:
		low = bisect.bisect_right(ordered, window_at)
		high = bisect.bisect_left(ordered, window_at + window_len)
		buried.update(ordered[low:high])
	if buried:
		print(f"verify: FAILED -- {len(buried):,} direct branch target(s) land "
		      f"inside a placed window, past its jump", file=sys.stderr)
		for address in sorted(buried)[:8]:
			print(f"    0x{address:x}", file=sys.stderr)
		problems += 1
	else:
		print(f"verify: no direct branch target lands inside a placed window, "
		      f"across {len(placed):,} window(s)")

	# **Does anything still read an upper half this rewrite left stale?**
	# Six lowerings leave one, and each is supposed to have proved nothing
	# reads it -- yet three of them shipped without the proof (Findings 173,
	# 180, 184) and two guards rest on facts the rewrite itself destroys
	# (185). None of that is reachable by execution here: on an SSE-only CPU
	# the surviving reader faults before the wrong value is observable. So
	# it is asked statically, of the output, from the READER's end.
	#
	# For every 256-bit instruction still in `.text`, the upper half it
	# reads was decided somewhere. If that somewhere was rewritten -- a
	# window that lowered it, or a VEX.128 write patched to legacy SSE,
	# which stops zeroing [255:128] -- then the reader takes bytes the
	# original would not have given it. Finding 186.
	# **From the IMAGE, not from the plan.** `patch_rows` is what `collect`
	# intended; `apply` then reverts any patch whose zeroing a surviving
	# reader still observes (Finding 187), so the planned list names sites
	# whose bytes never moved. Asking it reports defects the binary does
	# not have -- and would keep reporting them however many were repaired.
	# A site is narrowed only if its bytes actually changed. The rule this
	# broke is the file's own: check the artifact, not a fresh measurement
	# of where it came from.
	#
	# **And it is `narrowed_sites`, not `patched`.** `patched` is this
	# function's parameter holding the output binary's path. Rebinding it
	# to a set made the `objdump` call below raise `TypeError`, which
	# aborted `verify` before its last two checks -- one of them the stub
	# section's zero-VEX property. The same rebound-name defect as Finding
	# 175, written by the hand that recorded it. Finding 188.
	narrowed_sites = set()
	for row in patch_rows:
		where = raddr + (row[0] - vaddr)
		if bytes(b[where:where + len(row[1])]) != row[1]:
			narrowed_sites.add(row[0])
	stale, unresolved, unsure = stale_upper_reads(
		instructions, blocked, sources, placed, narrowed_sites,
		conservative=True)
	if unsure:
		# **A candidate still narrowed in the IMAGE is a repair that did not
		# happen.** `apply` keeps every one of these in its VEX form; asking
		# the output whether it did is the same artifact-not-plan rule as
		# the check below. Finding 198.
		print(f"verify: FAILED -- {len({p for _r, _f, p in unsure}):,} "
		      f"conservative candidate(s) were narrowed anyway",
		      file=sys.stderr)
		for reader, field, producer in sorted(unsure)[:8]:
			print(f"    0x{reader:x} reads {field}, could be 0x{producer:x}",
			      file=sys.stderr)
		problems += 1
	if stale:
		readers = len({reader for reader, _field, _producer in stale})
		print(f"verify: FAILED -- {readers:,} surviving 256-bit read(s) take "
		      f"an upper half this rewrite left stale", file=sys.stderr)
		for address, field, producer in sorted(stale)[:8]:
			print(f"    0x{address:x} reads {field}, decided at "
			      f"0x{producer:x}", file=sys.stderr)
		# **This did not count, and it is the check the repair exists
		# for.** Every other branch in this function adds to `problems`;
		# this one printed its finding to stderr and returned success, so
		# an image shipping the exact defect Findings 187 and 197 were
		# written about passed `verify` with the evidence on screen.
		#
		# Found by breaking the repair: a substitution bug placed 186
		# guilty windows, `verify` printed all 186 and exited 0, and the
		# only reason anybody looked was that the number matched the fall
		# in dropped windows. A gate that prints a failure and returns
		# success is worse than one that says nothing, because it is
		# quoted afterwards as having passed. Finding 281.
		problems += 1
	else:
		print("verify: no surviving 256-bit read takes an upper half this "
		      "rewrite left stale")
	if unresolved:
		print(f"verify: and {unresolved:,} upper-half source(s) the walk "
		      f"could not resolve, which this cannot speak for",
		      file=sys.stderr)

	# **And the indirect ones, which used to be the named gap.** The comment
	# above said `targets.py` was the only source for switch targets and the
	# model-agreement check the only check. `targets.from_switch_tables` was
	# reading the wrong base and finding noise (Finding 174), so that was
	# worse than it sounded. `switch_targets` reads the dispatch, so the
	# same independent question can now be asked of them: an address a
	# switch table names in the ORIGINAL must still begin an instruction in
	# the rewritten binary. Finding 177.
	resolved, resolved_tables, dispatches = switch_targets(
		inplace.parse_listing(listing), original, before_bounds)
	inside_switch = {a for a in resolved
	                 if vaddr <= a < vaddr + size and a in before_bounds}
	broken_switch = inside_switch - after_bounds
	if broken_switch:
		print(f"verify: FAILED -- {len(broken_switch):,} switch targets no "
		      f"longer begin an instruction", file=sys.stderr)
		for address in sorted(broken_switch)[:8]:
			print(f"    0x{address:x}", file=sys.stderr)
		problems += 1
	elif not resolved_tables and dispatches:
		# **A floor, because this check passes loudest when it inspects
		# nothing.** With no tables resolved, `inside_switch` is empty,
		# `broken_switch` is empty, and the line below would read "all 0
		# switch targets from 0 tables still begin an instruction" -- a
		# clean pass over nothing, which is the defect an audit had just
		# reported in `check-isa` and which this session then reproduced:
		# an image base added twice made `switch_targets` return zero for
		# a whole build, and the totals looked neutral.
		#
		# **The floor asks about DISPATCHES, not about the binary.** It
		# said "a binary with no switch statement at all is not one this
		# verifier is pointed at", which was true only while the verifier
		# was pointed at one binary. Pointing it at the 35 PE fixtures --
		# which is the whole of the gate that now runs it -- makes every
		# one of them fail a check about a construct they do not contain.
		# A broken resolver still recognises the dispatch and reads noise
		# from the table, so dispatches without tables is the resolver and
		# no dispatches is an honest nothing. Finding 196.
		print(f"verify: FAILED -- {dispatches:,} switch dispatch(es) "
		      f"recognised and no table resolved", file=sys.stderr)
		problems += 1
	elif not dispatches:
		print("verify: no switch dispatch in this image, so there is no "
		      "indirect target to check")
	else:
		print(f"verify: all {len(inside_switch):,} switch targets from "
		      f"{resolved_tables:,} tables still begin an instruction")

	done = subprocess.run(["objdump", "-d", "-j", ".avxsse", patched],
	                      capture_output=True, text=True, errors="replace")
	stub_vex = sum(1 for line in done.stdout.splitlines()
	               if len(line.split("\t")) >= 3
	               and line.split("\t")[1].split()[:1] in (["c4"], ["c5"]))
	jumps = done.stdout.count("\tjmp ")
	# **Every byte the rewriter emits must decode to an instruction, and
	# until now nothing said so.** The check above asks whether the stub
	# holds VEX; an invalid encoding is not VEX either, so a stub full of
	# bytes that decode to nothing passed both it and every structural
	# check in this file -- the image is well formed, the function table
	# sorts, the boundaries reconcile, and the program dies at a stub
	# entry.
	#
	# It is not hypothetical. `narrow_piece` lowers a span or region member
	# by clearing `VEX.L` and re-encoding as legacy, which is right for
	# `vaddps` and meaningless for an opcode the ISA only ever encoded
	# under VEX: `vbroadcastss` came out as `66 0f 38 18`. The first
	# fixture ever written for the region strategy produced it on its first
	# run, and nothing had shipped wrong only because Starfield's 93 region
	# sites happen to contain no such member.
	#
	# **This catches the whole class rather than one path.** Fixture
	# coverage catches an emission fault only where somebody wrote the
	# fixture that reaches it, and 11 of this file's 73 refusal reasons are
	# produced by any fixture at all. Every stub of every strategy goes
	# through this on every build. Finding 206.
	undecodable = [line for line in done.stdout.splitlines()
	               if "(bad)" in line]
	if undecodable:
		print(f"verify: FAILED -- {len(undecodable):,} byte sequence(s) in "
		      f"the stub section decode to nothing", file=sys.stderr)
		for line in undecodable[:8]:
			print(f"    {line.strip()}", file=sys.stderr)
		problems += 1
	else:
		print("verify: every instruction in the stub section decodes")

	# **A TEB bracket is not reentrant, and the property that keeps it safe
	# was asserted rather than checked.** Mode "teb" saves the block's two
	# borrows at a FIXED address shared by every stub in the image, where
	# mode "home" uses the caller's own frame. So a stub that swallowed a
	# `call` whose callee contains another teb stub would have its saved
	# registers overwritten and restore rubbish -- silently, since nothing
	# faults.
	#
	# `window_escape`'s docstring says no borrow window can contain a call
	# and says in as many words that this rests "on a property asserted in
	# two docstrings rather than enforced by a check". For the home space
	# that is second-order; for a fixed global it is the whole safety
	# argument, so it is enforced here instead. Measured zero on the first
	# build that produced any. Finding 280.
	if TEB_SCRATCH is not None:
		opened, reentrant, brackets = None, [], 0
		save = f",%gs:0x{teb_scratch_offset():x}"
		load = f"%gs:0x{teb_scratch_offset():x},%"
		for line in done.stdout.splitlines():
			if save in line:
				opened, brackets = line.split(":")[0].strip(), brackets + 1
			elif load in line:
				opened = None
			elif opened is not None and "\tcall" in line.expandtabs(1):
				reentrant.append((opened, line.strip()))
				opened = None
		if reentrant:
			print(f"verify: FAILED -- {len(reentrant):,} stub(s) hold a call "
			      f"inside a TEB save bracket, which is not reentrant",
			      file=sys.stderr)
			for at, line in reentrant[:8]:
				print(f"    bracket at {at}: {line}", file=sys.stderr)
			problems += 1
		else:
			print(f"verify: no call inside any of {brackets:,} TEB save "
			      f"bracket(s), which is what makes a fixed save location "
			      f"safe")
	# **The register class, which nothing else here reads.** See
	# `stub_gpr_problems`: every other check in this file is blind to a
	# general-purpose register, and Finding 264 shipped through all of them.
	if stubs is not None and placed:
		where = struct.unpack_from("<Q", b, pe + 24 + 24)[0] + stubs[0]
		loose = stub_gpr_problems(done.stdout, placed, home, where,
		                          stubs[1], instructions)
		if loose:
			print(f"verify: FAILED -- {len(loose):,} stub(s) clobber a "
			      f"general-purpose register the site was still using",
			      file=sys.stderr)
			for site, stub_at, registers in loose[:8]:
				names = ", ".join("%" + name for name in sorted(
					n for n, number in GPR_NUMBERS.items()
					if number in registers))
				print(f"    site 0x{site:x}, stub 0x{stub_at:x}: {names}",
				      file=sys.stderr)
			problems += 1
		else:
			print(f"verify: no stub clobbers a general-purpose register "
			      f"its site was still using, across {len(placed):,} "
			      f"placed window(s)")
	# **Every call in the stub section is a swallowed one, and this counts
	# them rather than forbidding them.** The first version of this check
	# asserted that no stub contains a call at all, which is a stronger
	# claim than anything rests on and is false: a window widened over a
	# `call` re-emits it at its new address, which is Finding 86 working,
	# and 384 of them are in the section. The check failed on its first run
	# against the real binary, on a claim its author had made up rather than
	# measured. It is kept, narrowed to what is true, because a count that
	# reconciles is worth more than a prohibition that does not hold.
	#
	# What actually matters is narrower still and is enforced where the
	# bytes are emitted rather than here: no call may lie between a borrow's
	# save and its restore. See `emit_swallowed` and `build_stub`'s run
	# branch. Finding 127.
	stub_calls = sum(1 for line in done.stdout.splitlines()
	                 if len(line.split("\t")) >= 3
	                 and line.split("\t")[2].split()[:1] in (["call"],
	                                                          ["callq"]))
	# Against the WINDOWS, not against `swallowed`. A window's first
	# instruction is re-emitted like every other one it covers, and it keeps
	# its boundary -- the jump is written there -- so it is deliberately not
	# in `swallowed`. Reconciling against that set said 384 against 294 and
	# the ninety were backward-widened windows whose first instruction is a
	# call. The set that matters is every instruction a placed window
	# covers.
	covered = set()
	for start, window, _at, _size, _prologue in placed:
		covered.update(range(start, start + window))
	window_calls = sum(1 for address in before_bounds & covered
	                   if is_call(a, raddr + (address - vaddr)))
	if stub_calls != window_calls:
		print(f"verify: FAILED -- {stub_calls:,} call instruction(s) in the "
		      f"stub section against {window_calls:,} inside a placed "
		      f"window; every one should be a re-emitted swallowed transfer",
		      file=sys.stderr)
		problems += 1
	else:
		print(f"verify: {stub_calls:,} call(s) in the stub section, every "
		      f"one an instruction a window covered and re-emitted")
	# **This number is reported, not asserted, and it stopped meaning "one
	# jump back per detour" the moment a window could swallow a branch.** It
	# equalled the detour count for as long as every stub held exactly one
	# jump -- the one home -- and it was quoted in project.md as a verified
	# invariant on the strength of the two figures matching. They no longer
	# do: Finding 86 re-emits a swallowed unconditional transfer inside the
	# stub, so 198,660 detours carry 199,798 jumps and both numbers are right.
	#
	# Saying "jumps back" of a count that includes jumps that do not come back
	# is the kind of claim `evidence.md` is about, so it says what it counts.
	# The real invariant -- one jump home per stub, at its end -- needs the
	# per-stub bounds this pass does not have, and asserting it is its own
	# piece of work rather than a wording fix.
	print(f"verify: stub section has {stub_vex:,} VEX instructions "
	      f"(must be 0) and {jumps:,} jmp instructions, one home per detour "
	      f"plus one per swallowed transfer")
	if stub_vex:
		problems += 1
	return 1 if problems else 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
