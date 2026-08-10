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

JMP_REL32 = 0xE9
SECTION_NAME = b".avxsse\0"
# CODE | EXECUTE | READ
SECTION_FLAGS = 0x60000020


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
               strategy=None):
	"""The stub body for one window, placed at stub_address.

	`start` is the window's first byte, which is the site's own address
	unless the window was widened backwards -- in which case `preceding`
	holds the instructions that come before the site and must execute first.

	`strategy` names a lowering the plain rules cannot express, because it
	rests on something the collector proved about the surrounding code rather
	than on the instruction alone. `("pair", ...)` is a 256-bit copy and takes
	the whole window; `("zero", None)` is a 256-bit store of a register a
	VEX.128 zeroing idiom emptied, and is an ordinary one-site window in every
	other respect.
	"""
	kind = strategy[0] if strategy is not None else None
	if kind == "pair":
		# A 256-bit copy: both instructions become four 128-bit moves, so
		# neither is lowered on its own.
		body = lower_ymm_pair(strategy[1], stub_address)
		if body is None:
			return None
		return bytes(body) + encode_jump(stub_address + len(body) + 5,
		                                 start + window)

	body = bytearray()
	for entry in preceding:
		fixed = moved_instruction(entry, stub_address + len(body), pool)
		if fixed is None:
			return None
		body += fixed

	site = start + sum(len(entry[1]) for entry in preceding)
	if kind == "zero":
		vex = inplace.decode_vex(encoding)
		lowered = lower_ymm_zero_store(vex, encoding[vex["length"]:], site,
		                               len(encoding), stub_address + len(body))
	else:
		lowered = lower_vex(site, encoding, operands, mnemonic,
		                    stub_address + len(body), scratch, pool)
	if lowered is None:
		return None
	body += lowered

	for entry in displaced:
		fixed = moved_instruction(entry, stub_address + len(body), pool)
		if fixed is None:
			return None
		body += fixed

	# Back to the instruction after the WINDOW, which is not the instruction
	# after the original once the window has been widened.
	body += encode_jump(stub_address + len(body) + 5, start + window)
	return bytes(body)


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
		if vex["L"] and index + 1 < len(instructions):
			following = instructions[index + 1]
			pair = ymm_pair(instructions[index], following)
			if pair is not None:
				window = len(encoding) + len(following[1])
				held = operands.rpartition(",")[2]
				if following[0] != address + len(encoding):
					skipped["ymm pair not adjacent"] += 1
					declined[address] = "ymm pair not adjacent"
					continue
				if following[0] in blocked:
					skipped["ymm store is a branch target"] += 1
					declined[address] = "ymm store is a branch target"
					continue
				if upper_half_read_later(instructions, index + 1, held,
				                         positions=positions):
					skipped["ymm upper half read later"] += 1
					declined[address] = "ymm upper half read later"
					continue
				if not inplace.covered_by(ranges, address, window):
					skipped["outside .pdata"] += 1
					declined[address] = "outside .pdata"
					continue
				# The stub's address decides a RIP displacement, and it is not
				# known yet; the site's own address stands in, which is what
				# the Class C probe below does for the same reason.
				if lower_ymm_pair(pair, address) is None:
					skipped["ymm pair operand cannot be offset"] += 1
					declined[address] = "ymm pair operand cannot be offset"
					continue
				candidates.append((address, encoding, operands, mnemonic,
				                   window, [], None, [], ("pair", pair)))
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
	rewritten = {address for address, _window, _at in placed}
	covered = set()
	for address, window, _at in placed:
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
	mode = argv[0]

	if mode == "selftest":
		return selftest()

	if mode == "census":
		return census(argv[1], argv[2], argv[3])

	if mode == "plan":
		_patches, candidates, stats, skipped, _declined = \
			collect(argv[1], argv[2])
		print(f"detour candidates (A/B/C) {len(candidates):>10,}")
		for reason, count in skipped.most_common():
			print(f"  skipped, {reason:<24} {count:>10,}")
		print(f"\nstub bytes (estimate)     {len(candidates) * 15:>10,}")
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


def place_stubs(candidates, stub_base):
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
		body = None
		if extension:
			j, extra, grew = extension
			body = build_stub(start, encoding, operands, mnemonic,
			                  window + grew, list(displaced) + extra,
			                  stub_address, scratch, pool, preceding, strategy)
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
			body = build_stub(start, encoding, operands, mnemonic, window,
			                  displaced, stub_address, scratch, pool,
			                  preceding, strategy)
		if body is None:
			refused.add(start)
			continue
		placed.append((start, window, stub_address))
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
	placed, blob, _swallowed, overlapped, refused = place_stubs(candidates,
	                                                            stub_base)

	for site, window, stub_address in placed:
		offset = raddr + (site - vaddr)
		jump = encode_jump(site + 5, stub_address)
		pad = window - 5
		data[offset:offset + window] = jump + inplace.nop_padding(pad)

	image, section_va = add_section(bytes(data), SECTION_NAME, bytes(blob),
	                                SECTION_FLAGS)
	pe = struct.unpack_from("<I", bytes(data), 0x3C)[0]
	image_base = struct.unpack_from("<Q", bytes(data), pe + 24 + 24)[0]
	assert section_va == stub_base - image_base, "stub section moved"
	open(output, "wb").write(image)
	print(f"apply: {len(patches):,} in-place patches, {len(placed):,} detours, "
	      f"{len(overlapped):,} skipped for overlap, {len(refused):,} refused")
	print(f"apply: stub section .avxsse at 0x{stub_base:x}, "
	      f"{len(blob):,} bytes")
	return 0


def verify(original, patched, listing=None):
	a = open(original, "rb").read()
	b = open(patched, "rb").read()
	problems = 0
	print(f"verify: {len(a):,} -> {len(b):,} bytes "
	      f"(+{len(b) - len(a):,} for the stub section)")

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

	dangerous = swallowed & reachable
	if dangerous:
		print(f"verify: FAILED -- {len(dangerous):,} swallowed instructions "
		      f"are branch targets", file=sys.stderr)
		problems += 1
	else:
		print(f"verify: none of the {len(swallowed):,} swallowed instructions "
		      f"is reachable by any branch")

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
