#!/usr/bin/env python3
"""Detours: a stub section, and a jump at every site that will not fit.

tools/patch.py rewrites the sites whose SSE form is no longer than the VEX
one. Everything else that HAS a lowering comes here -- Class C by
construction, and the class A and B sites whose SSE encoding happens to be
one byte longer. Class C is the obvious case -- `vaddss %xmm2,%xmm1,%xmm0` is four bytes
and becomes `movaps` plus `addss`, which is seven -- so the expansion has to
live somewhere else and the site has to jump to it.

**A near jump is five bytes**, so overwriting a five-byte instruction with
one leaves both its start and its end address exactly where they were, and
no address changes meaning. The four-byte register-to-register forms have to
swallow a neighbour to make room, which is safe only where nothing can
branch to the address that ends up inside the window. tools/targets.py
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
import re
import struct
import subprocess
import sys
from collections import Counter

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
import lower
import outside
import patch as inplace
import scratch as scratch_finder
import targets as target_set

# A memory operand based on rsp; group 1 is its displacement if it has one.
RSP_MEMORY = re.compile(r"(-?0x[0-9a-f]+)?\(%rsp\)")
# `rsp` copied into another register, after which any access through
# that register could reach the home space unseen.
RSP_COPY = re.compile(r"%rsp,\s*%r[a-z0-9]+$")

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
	if rip_relative(tail):
		old = struct.unpack_from("<i", out, len(out) - 4)[0]
		target = address + len(encoding) + old
		displacement = target - (at + len(out))
		if not -(1 << 31) <= displacement < (1 << 31):
			return None
		out[len(out) - 4:] = struct.pack("<i", displacement)
	return bytes(out)


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
# **The default is `none`, which refuses the site**, and that is the state to
# leave this in until the copyright holder decides otherwise: the two
# alternatives each buy the same sites and each pay for them in a different
# currency. Finding 46 measures all three.
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
SPILL = SPILL_NONE
HOME_SPACE = 32


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


def spill_register(registers):
	"""A register the site does not name, to borrow and give back.

	Always available: a site has at most four operands and there are sixteen
	registers. This is not `find_scratch` -- nothing is claimed about the
	register being dead, which is exactly why it has to be saved first.
	"""
	used = set()
	for operand in registers:
		used.update(scratch_finder.xmm_numbers(operand))
	for number in range(16):
		if number not in used:
			return number
	return None


def encode_spill(borrowed, save, at, spill_base):
	"""Save or restore a borrowed register. `save` picks the direction.

	**`movups`, not `movaps`.** Win64 guarantees `rsp` is 16-byte aligned at
	a call boundary and says nothing about an arbitrary instruction in the
	middle of a function, so an aligned move here would fault on exactly the
	sites that are hardest to reproduce.
	"""
	opcode = b"\x0f\x11" if save else b"\x0f\x10"
	if SPILL == SPILL_POOL:
		return encode_rip(None, opcode, borrowed, spill_base, at)
	# The home space and the stack spill address the same place -- `(%rsp)`
	# -- and differ only in whether `rsp` was moved to make room first. The
	# home space needs no room made.
	out = bytearray()
	if borrowed >= 8:
		out.append(0x44)			# REX.R
	out += opcode
	out.append(((borrowed & 7) << 3) | 4)	# mod 00, rm 100 -- SIB follows
	out.append(0x24)			# base rsp, no index
	return bytes(out)


# sub $16,%rsp and add $16,%rsp, which the pool spill does not need.
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


def lower_permilps(vex, tail, operands, scratch, at, pool):
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

	if scratch is None or scratch in (destination, data, control):
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
              pool=0):
	"""Lower one VEX instruction for execution at `at`. Bytes, or None.

	Used for the Class C site itself and for a swallowed instruction that
	turns out to be VEX too -- which most of them are, since VEX code comes
	in runs. Copying such an instruction into a stub unchanged would leave
	AVX in the output, which is the one thing the whole exercise is for.
	Inside a stub there is room, so it is lowered rather than refused.
	"""
	vex = inplace.decode_vex(encoding)
	if vex is None:
		return None
	# **Only mnemonics with a direct SSE form.** Stripping a VEX prefix is
	# a lowering only for those; for anything else it produces bytes that
	# are not an instruction. vbroadcastss is the one that got through
	# here: 0F 38 18 exists only under VEX, so `66 0f 38 18` decodes to
	# nothing at all and the disassembler desynchronises from there.
	# Class D, F and H need real sequences and belong in their own tools.
	if mnemonic in inplace.DESTINATION_IN_VVVV:
		return lower_vvvv_shift(vex, encoding, operands)
	if not inplace.has_direct_sse_form(mnemonic):
		if mnemonic in SEQUENCE_MNEMONICS or FMA_PATTERN.match(mnemonic):
			tail = encoding[vex["length"]:]
			if len(tail) < 2:
				return None
			if mnemonic.startswith("vblendv"):
				return lower_blendv(vex, tail, mnemonic, scratch)
			if mnemonic in BROADCASTS:
				return lower_broadcast(vex, tail, mnemonic, encoding,
				                       address, at)
			if mnemonic == "vpermilps":
				return lower_permilps(vex, tail, operands, scratch, at, pool)
			return lower_fma(vex, tail, mnemonic, scratch, address,
			                 encoding, at)
		return None
	tail = encoding[vex["length"]:]
	if len(tail) < 2:
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
	elif len(registers) != 2:
		return None			# four-operand forms are not Class A/B/C

	operation = inplace.sse_encoding(vex, tail)
	if operation is None:
		return None

	if rip_relative(tail):
		# Relative to the end of the instruction, and the instruction has
		# moved. The field sits four bytes from the end, or five when an
		# immediate follows it.
		offset = len(operation) - 4 - (1 if has_immediate else 0)
		if offset < 0:
			return None
		old = struct.unpack_from("<i", operation, offset)[0]
		target = address + len(encoding) + old
		new_end = at + len(body) + len(operation)
		displacement = target - new_end
		if not -(1 << 31) <= displacement < (1 << 31):
			return None
		operation = (operation[:offset]
		             + struct.pack("<i", displacement)
		             + operation[offset + 4:])
	body += operation
	return bytes(body)


def home_space_map(binary, plain, ranges):
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
	if at is not None:
		for i in range(size // 12):
			begin, end, unwind = struct.unpack_from("<III", data, at + i * 12)
			if end <= begin:
				continue
			off = rva_to_offset(data, unwind)
			if off is None or off + 4 > len(data):
				continue
			if not data[off + 3] & 0xF:		# no frame register
				fixed_frame.add(base + begin)

	starts = [start for start, _end in ranges]
	calls = [False] * len(ranges)
	touches = [False] * len(ranges)
	for address, _encoding, mnemonic, operands in plain:
		i = bisect.bisect_right(starts, address) - 1
		if i < 0 or address >= ranges[i][1]:
			continue
		if mnemonic in ("call", "callq"):
			calls[i] = True
		for match in RSP_MEMORY.finditer(operands):
			text = match.group(1)
			if 0 <= (int(text, 16) if text else 0) < HOME_SPACE:
				touches[i] = True
		# **A direct operand is not the only way to reach it.** A function
		# that computes the address of its own frame bottom can write there
		# through the result, and the scan above would see nothing. Both
		# shapes are refused: taking the address of anything in the region,
		# and copying `rsp` into another register at all.
		if mnemonic == "lea" and RSP_MEMORY.search(operands):
			text = RSP_MEMORY.search(operands).group(1)
			if 0 <= (int(text, 16) if text else 0) < HOME_SPACE:
				touches[i] = True
		if RSP_COPY.search(operands):
			touches[i] = True
	return (starts, ranges,
	        [calls[i] and not touches[i] and ranges[i][0] in fixed_frame
	         for i in range(len(ranges))])


def home_space_free(home, address):
	"""True if the function containing `address` can lend its home space."""
	if home is None:
		return False
	starts, ranges, usable = home
	i = bisect.bisect_right(starts, address) - 1
	if i < 0 or address >= ranges[i][1]:
		return False
	return usable[i]


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


def moved_instruction(entry, at, pool=0):
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
	if moved and moved[0] in (0xC4, 0xC5):
		# The swallowed instruction is VEX as well. Lower it here rather
		# than carry it across.
		return lower_vex(address, moved, moved_operands, moved_mnemonic, at,
		                 scratch, pool)
	# objdump comments a resolved target for several shapes, so the comment
	# only means a RIP displacement when the operand says (%rip). Anything
	# else copies across untouched.
	rip = comment if "(%rip)" in moved_operands else None
	return relocate(moved, address, at, rip)


YMM_MOVES = frozenset("vmovups vmovaps vmovdqu vmovdqa vmovupd vmovapd".split())


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
	if not rip_operand(tail) or len(tail) != 6:
		return None		# an immediate would follow the displacement
	return address + length + struct.unpack_from("<i", tail, 2)[0]


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
	return inplace.sse_encoding(narrow, tail[:2] + struct.pack("<i", value))


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


def ymm_run(instructions, index, blocked, limit=48):
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
	if first is None or first[0] != "load":
		return None
	tracked = {first[1]}
	members, at, last_store = [], address + len(encoding), None
	for step in range(1, limit + 1):
		position = index + step
		if position >= len(instructions):
			break
		next_address, bits, name, text, _c = instructions[position]
		if next_address != at or next_address in blocked:
			break
		if name.startswith(CONTROL_PREFIXES):
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
			tracked.add(what[1])
			members.append(("load", position, what[1]))
			at = next_address + len(bits)
			continue
		if vex is not None and vex["L"]:
			break			# a 256-bit instruction that is not a copy half
		if any(r in text or "%xmm" + r[len("%ymm"):] in text
		       for r in tracked):
			break			# the value is touched other than by a store
		members.append(("plain", position, None))
		at = next_address + len(bits)

	if last_store is None:
		return None
	# Trim whatever followed the last store: it is not part of the copy and
	# carrying it would only widen the window.
	members = members[:last_store]
	loaded = {first[1]} | {r for kind, _p, r in members if kind == "load"}
	stored = {r for kind, _p, r in members if kind == "store"}
	if loaded - stored:
		return None		# a register loaded and never stored has no use
	return members, members[-1][1]


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


def assign_helpers(plain, positions, index, members):
	"""One helper register per pair in the run, all distinct, or None.

	Greedy over the pairs in load order, which is enough here: a run holds
	ten pairs at the very most and the candidate sets are large. Distinctness
	has to be enforced rather than assumed -- two pairs' helpers are both
	invisible to the original code, so nothing else keeps them apart.
	"""
	loads = {register: position for kind, position, register in members
	         if kind == "load"}
	stores = {register: position for kind, position, register in members
	          if kind == "store"}
	loads[wide_move(*plain[index][1:4])[1]] = index
	taken, out = set(), {}
	for register, load_at in sorted(loads.items(), key=lambda kv: kv[1]):
		store_at = stores.get(register)
		if store_at is None:
			return None
		own = scratch_finder.xmm_numbers(plain[load_at][3])
		free = free_across(plain, positions, load_at, store_at, own) - taken
		if not free:
			return None
		chosen = min(free)
		taken.add(chosen)
		out[register] = chosen
	return out


def lower_ymm_run(strategy, at, pool):
	"""The run, with every 256-bit copy split and everything else moved."""
	helpers, entries = strategy
	body = bytearray()
	for kind, register, vex, tail, address, length, moved in entries:
		if kind == "plain":
			fixed = moved_instruction(moved, at + len(body), pool)
			if fixed is None:
				return None
			body += fixed
			continue
		high_vex, high_tail = retarget(vex, tail, helpers[register])
		for one_vex, one_tail, delta in ((vex, tail, 0),
		                                 (high_vex, high_tail, 16)):
			piece = narrow_piece(one_vex, one_tail, delta, address, length,
			                     at + len(body))
			if piece is None:
				return None
			body += piece
	return bytes(body)


def zeroed_ymm(instructions, index, register, blocked, limit=80):
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

	Sound because it walks back to the NEAREST write, so nothing between that
	write and the store can have changed the register. Everything unresolved
	is refused:

	  * a **branch target** in between means another path reaches the store
	    without passing the zeroing;
	  * a **call** in between is opaque, the upper half of every ymm being
	    volatile across one -- that is what `vzeroupper` exists for -- so the
	    zeroing does not survive it;
	An instruction that merely **reads** the register is scanned past, the
	value being unchanged by it. That was refused when this was written, on
	the grounds that "the nearest mention decides" is the rule easiest to be
	sure of; measured afterwards, the simplification was costing 3,299
	stores, which is more than a simplification is worth. Finding 44.

	**A conditional branch is transparent in this direction, and that is the
	asymmetry worth understanding.** Going forwards a branch splits the paths
	and the answer has to hold on both, which is why Finding 42 had to follow
	the edges. Going backwards there is nothing to split: reaching this store
	by falling through a `jcc` means the branch was not taken on this
	execution, so everything before it ran in order. An unconditional jump is
	not transparent -- the instruction after one is reachable only by a
	branch, and a branch target has already been refused above, so meeting a
	`jmp` walking backwards means bytes nothing reaches.

	`vzeroall` would be the one instruction that writes an xmm without naming
	it. There are none in `.text`, checked rather than assumed.
	"""
	narrow = "%xmm" + register[len("%ymm"):]
	for step in range(1, limit + 1):
		position = index - step
		if position < 0:
			return False
		address, encoding, mnemonic, operands, _comment = instructions[position]
		if address in blocked:
			return False
		if mnemonic.startswith(CONTROL_PREFIXES) \
				and not conditional_branch(mnemonic):
			return False
		if narrow not in operands and register not in operands:
			continue
		fields = inplace.split_operands(operands)
		if fields and fields[-1] not in (narrow, register):
			# **A pure source, so the value is unchanged and the walk goes
			# on.** In AT&T the destination is the last operand, and the one
			# family that writes a non-last one is `vgather*`, which zeroes
			# its mask. There are none in `.text`, checked rather than
			# assumed, so a register named anywhere but last is read-only.
			continue
		if mnemonic not in scratch_finder.ZEROING:
			return False
		if len(fields) != 3 or set(fields) != {narrow}:
			return False
		vex = inplace.decode_vex(encoding)
		return vex is not None and not vex["L"]
	return False


PATH_BUDGET = 400


def upper_half_read_later(instructions, index, register, limit=40,
                          positions=None, budget=None, visiting=frozenset()):
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
	"""
	if budget is None:
		budget = [PATH_BUDGET]
	for step in range(1, limit + 1):
		position = index + step
		if position >= len(instructions) or position in visiting:
			return True		# off the end, or a back edge
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
			# **Follow the edges, exactly as tools/scratch.py does, and for
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
				                         inside):
					return True
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
		fields = inplace.split_operands(operands)
		if mnemonic in YMM_MOVES and fields[-1] == register \
				and register not in fields[:-1]:
			vex = inplace.decode_vex(encoding)
			if vex is not None and vex["L"]:
				return False
		return True
	return False


def build_stub(start, encoding, operands, mnemonic, window, displaced,
               stub_address, scratch=None, pool=0, preceding=(),
               strategy=None, spill_base=0):
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
	if kind == "run":
		# A run of 256-bit copies and whatever lies between them, all in one
		# stub. It carries its own instruction list rather than using
		# `displaced`, because they have to land BETWEEN the halves of the
		# copies rather than after a site.
		body = lower_ymm_run(strategy[1], stub_address, pool)
		if body is None:
			return None, 0
		return bytes(body) + encode_jump(stub_address + len(body) + 5,
		                                 start + window), 0
	if kind == "pair":
		# A 256-bit copy: both instructions become four 128-bit moves, so
		# neither is lowered on its own.
		body = lower_ymm_pair(strategy[1], stub_address)
		if body is None:
			return None, 0
		return bytes(body) + encode_jump(stub_address + len(body) + 5,
		                                 start + window), 0

	body = bytearray()
	prologue = 0
	for entry in preceding:
		fixed = moved_instruction(entry, stub_address + len(body), pool)
		if fixed is None:
			return None, 0
		body += fixed

	site = start + sum(len(entry[1]) for entry in preceding)
	if kind == "spill":
		# Borrow a register the site does not name, and give it back. The
		# save has to come before the lowering and the restore after it, so
		# neither can live inside lower_vex.
		borrowed = strategy[1]
		if SPILL == SPILL_STACK:
			body += STACK_OPEN
			# Where the allocation is complete, which is what the unwind
			# code's offset means and why it is measured rather than assumed
			# to be zero: a backward-widened window emits its swallowed
			# instructions first.
			prologue = len(body)
		saved = encode_spill(borrowed, True, stub_address + len(body),
		                     spill_base)
		if saved is None:
			return None, 0
		body += saved
		lowered = lower_vex(site, encoding, operands, mnemonic,
		                    stub_address + len(body), borrowed, pool)
		if lowered is None:
			return None, 0
		body += lowered
		restored = encode_spill(borrowed, False, stub_address + len(body),
		                        spill_base)
		if restored is None:
			return None, 0
		body += restored
		if SPILL == SPILL_STACK:
			body += STACK_CLOSE
		lowered = b""
	elif kind == "zero":
		vex = inplace.decode_vex(encoding)
		lowered = lower_ymm_zero_store(vex, encoding[vex["length"]:], site,
		                               len(encoding), stub_address + len(body))
	else:
		lowered = lower_vex(site, encoding, operands, mnemonic,
		                    stub_address + len(body), scratch, pool)
	if lowered is None:
		return None, 0
	body += lowered

	for entry in displaced:
		fixed = moved_instruction(entry, stub_address + len(body), pool)
		if fixed is None:
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
		pending = [address, bytearray(encoding), fields[0],
		           (fields[1] if len(fields) > 1 else ""), comment]
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


def collect(binary, listing):
	"""(in-place patches, class C detour candidates, statistics)."""
	# Everything anything can branch to. A window may not contain one of
	# these anywhere but at its first byte.
	groups = target_set.collect(binary)
	blocked = set()
	for values in groups.values():
		blocked |= values
	instructions = list(parse_with_comments(listing))
	# The liveness scan wants the plain four-field shape.
	plain = [(a, e, m, o) for a, e, m, o, _c in instructions]
	for i, (address, _e, mnemonic, operands, comment) in enumerate(instructions):
		if mnemonic.startswith(("j", "call", "loop")) and operands:
			first = operands.split()[0]
			if first.startswith("0x"):
				try:
					blocked.add(int(first, 16))
				except ValueError:
					pass
		elif mnemonic == "lea" and isinstance(comment, int) \
				and "(%rip)" in operands:
			# A function address taken PC-relatively, so no relocation
			# records it and no call names it. It can still be called
			# through the pointer, which makes it a branch target like any
			# other -- see outside.lea_targets.
			blocked.add(comment)

	# The code oracle, in two parts. .pdata is the binary's own statement
	# about where its functions are and needs no disassembly to read, but the
	# x64 ABI lets a leaf function omit its unwind data -- and refusing those
	# was the largest single reason sites survived. tools/outside.py recovers
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
	# Which functions can lend their callee home space, if asked to.
	home = home_space_map(binary, plain, ranges) if SPILL == SPILL_HOME \
		else None
	patches, stats, _blocked = inplace.build_patches(listing, ranges)

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
	for index, (address, encoding, mnemonic, operands,
	            _comment) in enumerate(instructions):
		if not encoding or encoding[0] not in (0xC4, 0xC5):
			continue
		if address in already:
			continue
		vex = inplace.decode_vex(encoding)
		if vex is None:
			continue

		strategy = None
		# A 256-bit copy through one ymm, taken as a unit. Both halves of
		# it are refused individually -- there is no SSE form of either --
		# so this has to be seen before either is considered alone.
		# **The pair is tried first because it needs no helper register**,
		# and a failure here is not a refusal: the run below solves the same
		# problem differently and can take what the pair cannot. Its reason
		# is held back and only recorded if the run declines too -- one
		# source copied to two destinations was being refused for reading an
		# upper half that a run would have kept in a register.
		pair_reason = None
		if vex["L"] and index + 1 < len(instructions):
			following = instructions[index + 1]
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
			found = ymm_run(instructions, index, blocked)
			if found is not None:
				members, last = found
				tail_entry = instructions[last]
				window = tail_entry[0] + len(tail_entry[1]) - address
				helpers = assign_helpers(plain, positions, index, members)
				if helpers is None:
					skipped["no register free across the ymm run"] += 1
					declined[address] = "no register free across the ymm run"
					continue
				# **A run leaves every one of its ymms with a stale upper
				# half**, exactly as a pair does: the low half is in the
				# register's own xmm and the high half is in a helper the
				# original code knows nothing about. The pair strategy has
				# guarded that since Finding 38 and the run did not, which
				# was a live defect for as long as runs have existed --
				# a later 256-bit read of any register in the run would take
				# whatever was left in its upper half. Finding 64.
				if any(upper_half_read_later(instructions, last, register,
				                             positions=positions)
				       for register in helpers):
					skipped["ymm run upper half read later"] += 1
					declined[address] = "ymm run upper half read later"
					continue
				if not inplace.covered_by(ranges, address, window):
					skipped["outside .pdata"] += 1
					declined[address] = "outside .pdata"
					continue
				entries = [("load", operands.rpartition(",")[2], vex,
				            encoding[vex["length"]:], address, len(encoding),
				            None)]
				for kind, position, register in members:
					entry = instructions[position]
					if kind == "plain":
						entries.append((
							"plain", None, None, None, entry[0], len(entry[1]),
							(entry[0], entry[1], entry[4], entry[3], entry[2],
							 swallowed_scratch(plain, position, entry[0],
							                   entry[1], entry[3], entry[2],
							                   scope))))
						continue
					one = inplace.decode_vex(entry[1])
					entries.append((kind, register, one,
					                entry[1][one["length"]:], entry[0],
					                len(entry[1]), None))
				run = (helpers, entries)
				if lower_ymm_run(run, address, address) is None:
					skipped["ymm run operand cannot be moved"] += 1
					declined[address] = "ymm run operand cannot be moved"
					continue
				candidates.append((address, encoding, operands, mnemonic,
				                   window, [], None, [], ("run", run)))
				continue
		if pair_reason is not None:
			skipped[pair_reason] += 1
			declined[address] = pair_reason
			continue

		# A 256-bit store of a register a VEX.128 zeroing idiom emptied.
		# Both halves are zero, so it is two 128-bit stores of the same
		# register -- and unlike the copy it is one instruction, so it takes
		# the ordinary path below and may widen its window like any other.
		if vex["L"] and mnemonic in YMM_MOVES:
			fields = inplace.split_operands(operands)
			if (len(fields) == 2 and fields[0].startswith("%ymm")
					and "(" in fields[1]):
				if zeroed_ymm(instructions, index, fields[0], blocked):
					if lower_ymm_zero_store(vex, encoding[vex["length"]:],
					                        address, len(encoding),
					                        address) is None:
						skipped["ymm store operand cannot be offset"] += 1
						declined[address] = "ymm store operand cannot be offset"
						continue
					strategy = ("zero", None)
				else:
					skipped["ymm value has no known upper half"] += 1
					declined[address] = "ymm value has no known upper half"
					continue
		# There was a `mnemonic not in nds` test here, left over from when
		# this only handled Class C. It quietly excluded every mnemonic
		# that is DIRECT-only -- vcomiss and the rest -- as well as the
		# sequences, long after the code below had learned to handle them.
		needs_sequence = (mnemonic in SEQUENCE_MNEMONICS
		                  or FMA_PATTERN.match(mnemonic) is not None)
		if not inplace.has_direct_sse_form(mnemonic) and not needs_sequence:
			skipped["no direct SSE form"] += 1
			declined[address] = "no direct SSE form"
			continue
		fields = inplace.split_operands(operands)
		registers = [o for o in fields if not o.startswith("$")]
		if not needs_sequence and len(registers) not in (2, 3):
			skipped["operand shape not A/B/C"] += 1
			declined[address] = "operand shape not A/B/C"
			continue

		# A sequence may need somewhere to put an intermediate. Ask the
		# liveness scan; a site with no dead register is left alone rather
		# than spilled, because a stub that moves rsp breaks stack walking
		# (see tools/scratch.py).
		# A Class C site whose src2 IS the destination needs one too, for the
		# reason spelled out in lower_vex: the movaps that sets up the
		# destination would destroy src2 first.
		aliased = (not needs_sequence
		           and mnemonic not in inplace.DESTINATION_IN_VVVV
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
				if SPILL == SPILL_HOME \
						and not home_space_free(home, address):
					skipped["no home space to borrow"] += 1
					declined[address] = "no home space to borrow"
					continue
				borrowed = spill_register(registers)
				if borrowed is not None and lower_vex(
						address, encoding, operands, mnemonic, address,
						borrowed, address) is not None:
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
			if index + 1 >= len(instructions):
				reason = "nothing follows"
			else:
				nxt_address, nxt_encoding, nxt_mnemonic, nxt_operands, \
					nxt_comment = instructions[index + 1]
				if nxt_address != address + window:
					reason = "next instruction not adjacent"
				elif nxt_address in blocked:
					reason = "next instruction is a branch target"
				elif nxt_mnemonic.startswith(CONTROL_PREFIXES):
					reason = "next instruction transfers control"
				elif window + len(nxt_encoding) < 5:
					reason = "still too short"
				else:
					displaced.append((nxt_address, nxt_encoding, nxt_comment,
					                  nxt_operands, nxt_mnemonic,
					                  swallowed_scratch(
						                  plain, index + 1, nxt_address,
						                  nxt_encoding, nxt_operands,
						                  nxt_mnemonic, scope)))
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
				previous = instructions[index - 1] if index else None
				if previous is None:
					pass
				elif previous[0] + len(previous[1]) != address:
					pass		# not adjacent; something lies between
				elif address in blocked:
					pass		# the site is branched to; it cannot vanish
				elif previous[2].startswith(CONTROL_PREFIXES):
					pass		# does not fall through into the site
				elif len(previous[1]) + len(encoding) < 5:
					pass
				else:
					preceding.append((previous[0], previous[1], previous[4],
					                  previous[3], previous[2],
					                  swallowed_scratch(
						                  plain, index - 1, previous[0],
						                  previous[1], previous[3],
						                  previous[2], scope)))
					start = previous[0]
					window = len(previous[1]) + len(encoding)
					reason = None

			if reason is not None:
				skipped[reason] += 1
				declined[address] = reason
				continue

		if not inplace.covered_by(ranges, start, window):
			skipped["outside .pdata"] += 1
			declined[address] = "outside .pdata"
			continue
		candidates.append((start, encoding, operands, mnemonic, window,
		                   displaced, scratch, preceding, strategy))
	return patches, candidates, stats, skipped, declined


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

	if failures:
		print(f"selftest: {failures} of {len(SELFTEST)} lowerings are wrong",
		      file=sys.stderr)
		return 1
	print(f"selftest: {len(SELFTEST)} lowerings, none reads a register it "
	      f"has overwritten")
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
	_patches, candidates, _stats, _skipped, declined = collect(binary, listing)
	placed, _blob, swallowed, overlapped, refused = place_stubs(
		candidates, stub_base_of(open(binary, "rb").read()))
	rewritten = {address for address, _window, *_rest in placed}
	covered = set()
	for address, window, *_rest in placed:
		covered.update(range(address, address + window))

	survivors = {a for a, e, _m, _o in inplace.parse_listing(patched)
	             if e[:1] in (b"\xc4", b"\xc5")}

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
	def spread(starts):
		out = set()
		for start, _e, _o, _m, window, _d, _s, _p, _strategy in candidates:
			if start in starts:
				out.update(range(start, start + window))
		return out

	# The collector never sees these: decode_vex refuses the encoding, so
	# there is nothing to classify. They are objdump's `(bad)` lines, which
	# are bytes it could not decode rather than instructions.
	undecodable = {a for a, e, _m, _o in inplace.parse_listing(listing)
	               if e[:1] in (b"\xc4", b"\xc5")
	               and inplace.decode_vex(e) is None}

	buckets = (("declined by the collector", set(declined)),
	           ("refused, stub not buildable", spread(refused)),
	           ("inside a committed window", covered),
	           ("skipped for overlap", spread(overlapped)),
	           ("undecodable, never classified", undecodable))
	accounted = set()
	for label, group in buckets:
		hit = (survivors & group) - accounted
		accounted |= hit
		print(f"  {label:<30}{len(hit):>10,}")
	rest = survivors - accounted
	print(f"  {'unaccounted':<30}{len(rest):>10,}")
	if rest:
		print("  -- unaccounted, and that should be zero. Every survivor was")
		print("     an instruction boundary and a VEX site in the original,")
		print("     so none of it is the disassembler inventing one.")
	return 0


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	# `--spill=` selects where a borrowed register is saved, and it is an
	# evaluation switch rather than a tuning knob: the default refuses the
	# site, as it always has, and the other two exist so that all three can
	# be built and compared. See Finding 46.
	global SPILL
	argv = list(argv)
	for i, item in enumerate(argv):
		if item.startswith("--spill="):
			SPILL = item.split("=", 1)[1]
			if SPILL not in (SPILL_NONE, SPILL_STACK, SPILL_POOL,
			                 SPILL_HOME):
				print(f"detour.py: unknown spill {SPILL!r}", file=sys.stderr)
				return 2
			del argv[i]
			break
	mode = argv[0]

	if mode == "selftest":
		return selftest()

	if mode == "census":
		return census(argv[1], argv[2], argv[3])

	if mode == "plan":
		_patches, candidates, stats, skipped, declined = \
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

	print(f"detour.py: unknown mode {mode!r}", file=sys.stderr)
	return 2


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


def place_stubs(candidates, stub_base, spill_base=0):
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
		extension = None
		for j in range(i + 1, len(entries)):
			other = entries[j]
			if other[0] >= start + window:
				break
			following = other[7]
			if other[8] is not None:
				# A site with a strategy of its own cannot ride along:
				# a passenger is lowered by `moved_instruction`, which
				# knows only the plain rules and would refuse a 256-bit
				# one -- costing the stub that was going anyway.
				continue
			if not following or other[1][:1] not in (b"\xc4", b"\xc5"):
				continue
			site = other[0] + sum(len(e[1]) for e in following)
			if site != start + window:
				continue
			# The passenger carries the scratch its own candidate was given:
			# it is being lowered here rather than in a stub of its own, and
			# the register it may destroy does not change with the address.
			extension = (j, [(site, other[1], None, other[2], other[3],
			                  other[6])], len(other[1]))
			break

		stub_address = stub_base + len(blob)
		body, prologue = None, 0
		if extension:
			j, extra, grew = extension
			body, prologue = build_stub(
				start, encoding, operands, mnemonic, window + grew,
				list(displaced) + extra, stub_address, scratch, pool,
				preceding, strategy, spill_base)
			if body is None:
				# The extended stub would not build. Fall back to the plain
				# one rather than lose both -- taking a passenger along must
				# never cost the stub that was going anyway.
				extension = None
			else:
				window += grew
				displaced = list(displaced) + extra
				rescued.add(j)
		if body is None:
			body, prologue = build_stub(
				start, encoding, operands, mnemonic, window, displaced,
				stub_address, scratch, pool, preceding, strategy, spill_base)
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
		if strategy is not None and strategy[0] == "pair":
			# A ymm pair carries no `displaced` list -- both instructions
			# are lowered together -- but the store's boundary disappears
			# just the same, and the verifier is right to want it named.
			# A zero store is one instruction and loses no extra boundary.
			swallowed.add(start + len(encoding))
		if strategy is not None and strategy[0] == "run":
			# Same again over a longer stretch: every boundary from the one
			# after the first load to the last store's own disappears.
			_helpers, entries = strategy[1]
			for entry in entries[1:]:
				swallowed.add(entry[4])
	return placed, blob, swallowed, overlapped, refused


def apply_all(binary, listing, output):
	patches, candidates, _stats, _skipped, _declined = collect(binary,
	                                                          listing)
	data = bytearray(open(binary, "rb").read())
	vaddr, raddr, _size = inplace.text_mapping(binary)

	# The in-place work first: it does not move anything, so the addresses
	# the detours are computed against are unaffected either way.
	for address, original, replacement, _kind, _mnemonic in patches:
		offset = raddr + (address - vaddr)
		if bytes(data[offset:offset + len(original)]) != original:
			raise SystemExit(f"0x{address:x}: bytes on disk do not match")
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
	placed, blob, _swallowed, overlapped, refused = place_stubs(
		candidates, stub_base, spill_base)

	for site, window, stub_address, _length, _prologue in placed:
		offset = raddr + (site - vaddr)
		jump = encode_jump(site + 5, stub_address)
		pad = window - 5
		data[offset:offset + window] = jump + inplace.nop_padding(pad)

	staged = bytes(data)
	pe = struct.unpack_from("<I", staged, 0x3C)[0]
	image_base = struct.unpack_from("<Q", staged, pe + 24 + 24)[0]
	if SPILL == SPILL_POOL:
		staged, data_va = add_section(staged, DATA_NAME, bytes(16), DATA_FLAGS)
		assert data_va == spill_base - image_base, "spill section moved"
	image, section_va = add_section(staged, SECTION_NAME, bytes(blob),
	                                SECTION_FLAGS)
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
	assert got == pdata_rva, "function table moved"
	image = bytearray(image)
	pe = struct.unpack_from("<I", bytes(image), 0x3C)[0]
	struct.pack_into("<II", image, pe + 24 + 112 + EXCEPTION_DIRECTORY * 8,
	                 pdata_rva, len(pdata))

	open(output, "wb").write(bytes(image))
	print(f"apply: {len(patches):,} in-place patches, {len(placed):,} detours, "
	      f"{len(overlapped):,} skipped for overlap, {len(refused):,} refused")
	print(f"apply: stub section .avxsse at 0x{stub_base:x}, "
	      f"{len(blob):,} bytes")
	print(f"apply: {len(pdata) // 12:,} function table entries "
	      f"({len(xdata):,} bytes of unwind info) at 0x{pdata_rva + image_base:x}")
	return 0


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
	if a[raddr + size:] != b[raddr + size:len(a)]:
		print("verify: FAILED -- sections after .text changed", file=sys.stderr)
		problems += 1
	else:
		print("verify: every section after .text is byte-identical")

	before_bounds, before_vex = inplace.disassemble(original)
	after_bounds, after_vex = inplace.disassemble(patched)
	print(f"verify: VEX in .text {len(before_vex):,} -> {len(after_vex):,}"
	      f"  ({len(before_vex) - len(after_vex):,} removed, "
	      f"{100.0 * (len(before_vex) - len(after_vex)) / len(before_vex):.1f}%)")
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

	_patches, candidates, _stats, _skipped, _declined = collect(original,
	                                                           listing)
	# The same call apply makes, so the two cannot drift apart.
	_placed, _blob, swallowed, _overlapped, _refused = place_stubs(
		candidates, stub_base_of(open(original, "rb").read()))
	groups = target_set.collect(original)
	reachable = set()
	for values in groups.values():
		reachable |= values

	unexplained = lost - swallowed
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

	done = subprocess.run(["objdump", "-d", "-j", ".avxsse", patched],
	                      capture_output=True, text=True, errors="replace")
	stub_vex = sum(1 for line in done.stdout.splitlines()
	               if len(line.split("\t")) >= 3
	               and line.split("\t")[1].split()[:1] in (["c4"], ["c5"]))
	jumps = done.stdout.count("\tjmp ")
	print(f"verify: stub section has {stub_vex:,} VEX instructions "
	      f"(must be 0) and {jumps:,} jumps back")
	if stub_vex:
		problems += 1
	return 1 if problems else 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
