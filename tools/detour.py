#!/usr/bin/env python3
"""Detours: a stub section, and a jump at every site that will not fit.

tools/patch.py rewrites the sites whose SSE form is no longer than the VEX
one. Everything else that HAS a lowering comes here -- Class C by
construction, and the class A and B sites whose SSE encoding happens to be
one byte longer. Class C is the obvious case -- `vaddss %xmm2,%xmm1,%xmm0` is four bytes
and becomes `movaps` plus `addss`, which is seven -- so the expansion has to
live somewhere else and the site has to jump to it.

**Only sites already five bytes or longer are detoured, and that is what
makes this sound.** A near jump is five bytes, so overwriting a five-byte
instruction with one leaves both its start and its end address exactly where
they were. Nothing can branch into the middle of an instruction, so there is
no address whose meaning changes. The four-byte register-to-register forms
would have to swallow the instruction after them to make room, and that
reopens a question this cannot answer: an indirect branch through a jump
table can target that instruction, and jump tables in x64 MSVC hold
table-relative offsets that no relocation records, so they cannot be
enumerated. Those sites are left alone.

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
		return None
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


def build_stub(site, encoding, operands, mnemonic, window, displaced,
               stub_address, scratch=None, pool=0):
	"""The stub body for one site, placed at stub_address."""
	body = bytearray()
	lowered = lower_vex(site, encoding, operands, mnemonic, stub_address,
	                    scratch, pool)
	if lowered is None:
		return None
	body += lowered

	for address, moved, comment, moved_operands, moved_mnemonic in displaced:
		at = stub_address + len(body)
		if moved and moved[0] in (0xC4, 0xC5):
			# The swallowed instruction is VEX as well. Lower it here
			# rather than carry it across.
			fixed = lower_vex(address, moved, moved_operands, moved_mnemonic, at)
		else:
			# objdump comments a resolved target for several shapes, so the
			# comment only means a RIP displacement when the operand says
			# (%rip). Anything else copies across untouched.
			rip = comment if "(%rip)" in moved_operands else None
			fixed = relocate(moved, address, at, rip)
		if fixed is None:
			return None
		body += fixed

	# Back to the instruction after the WINDOW, which is not the instruction
	# after the original once the window has been widened.
	body += encode_jump(stub_address + len(body) + 5, site + window)
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
	for i, (address, _e, mnemonic, operands, _c) in enumerate(instructions):
		if mnemonic.startswith(("j", "call", "loop")) and operands:
			first = operands.split()[0]
			if first.startswith("0x"):
				try:
					blocked.add(int(first, 16))
				except ValueError:
					pass

	# The code oracle, in two parts. .pdata is the binary's own statement
	# about where its functions are and needs no disassembly to read, but the
	# x64 ABI lets a leaf function omit its unwind data -- and refusing those
	# was the largest single reason sites survived. tools/outside.py recovers
	# them, under conditions strict enough that data cannot pass: bracketed
	# by int3, entered by a call or jump, ending in a control transfer, and
	# containing no byte objdump failed to decode.
	described = inplace.function_ranges(binary)
	ranges = sorted(described + outside.leaf_ranges(plain, described, blocked))
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
	for index, (address, encoding, mnemonic, operands,
	            _comment) in enumerate(instructions):
		if not encoding or encoding[0] not in (0xC4, 0xC5):
			continue
		if address in already:
			continue
		vex = inplace.decode_vex(encoding)
		if vex is None or mnemonic in inplace.DESTINATION_IN_VVVV:
			continue
		# There was a `mnemonic not in nds` test here, left over from when
		# this only handled Class C. It quietly excluded every mnemonic
		# that is DIRECT-only -- vcomiss and the rest -- as well as the
		# sequences, long after the code below had learned to handle them.
		needs_sequence = (mnemonic in SEQUENCE_MNEMONICS
		                  or FMA_PATTERN.match(mnemonic) is not None)
		if not inplace.has_direct_sse_form(mnemonic) and not needs_sequence:
			skipped["no direct SSE form"] += 1
			continue
		fields = inplace.split_operands(operands)
		registers = [o for o in fields if not o.startswith("$")]
		if not needs_sequence and len(registers) not in (2, 3):
			skipped["operand shape not A/B/C"] += 1
			continue

		# A sequence may need somewhere to put an intermediate. Ask the
		# liveness scan; a site with no dead register is left alone rather
		# than spilled, because a stub that moves rsp breaks stack walking
		# (see tools/scratch.py).
		# A Class C site whose src2 IS the destination needs one too, for the
		# reason spelled out in lower_vex: the movaps that sets up the
		# destination would destroy src2 first.
		aliased = (not needs_sequence and len(registers) == 3
		           and registers[-1] != registers[-2]
		           and registers[0] == registers[-1])
		scratch = None
		if needs_sequence or aliased:
			scratch = scratch_finder.find_scratch(plain, index)
			trial = lower_vex(address, encoding, operands, mnemonic,
			                  address, scratch, address)
			if trial is None:
				if aliased:
					skipped["src2 aliases dst, no scratch"] += 1
				else:
					skipped["sequence with no usable scratch"
					        if scratch is None
					        else "sequence shape not handled"] += 1
				continue
		displaced = []
		window = len(encoding)

		if window < 5:
			# Too short for a jump on its own. Widen over the instruction
			# that follows, which is safe only when nothing can branch to
			# it -- see tools/targets.py for how that set is built.
			if index + 1 >= len(instructions):
				skipped["nothing follows"] += 1
				continue
			nxt_address, nxt_encoding, nxt_mnemonic, _ops, nxt_comment = \
				instructions[index + 1]
			if nxt_address != address + window:
				skipped["next instruction not adjacent"] += 1
				continue
			if nxt_address in blocked:
				skipped["next instruction is a branch target"] += 1
				continue
			if nxt_mnemonic.startswith(CONTROL_PREFIXES):
				skipped["next instruction transfers control"] += 1
				continue
			displaced.append((nxt_address, nxt_encoding, nxt_comment,
			                  instructions[index + 1][3], nxt_mnemonic))
			window += len(nxt_encoding)
			if window < 5:
				skipped["still too short"] += 1
				continue

		if not inplace.covered_by(ranges, address, window):
			skipped["outside .pdata"] += 1
			continue
		candidates.append((address, encoding, operands, mnemonic, window,
		                   displaced, scratch))
	return patches, candidates, stats, skipped


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


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	mode = argv[0]

	if mode == "selftest":
		return selftest()

	if mode == "plan":
		_patches, candidates, stats, skipped = collect(argv[1], argv[2])
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
	refused = overlapped = 0
	committed_to = 0
	for (site, encoding, operands, mnemonic, window, displaced,
	     scratch) in sorted(candidates, key=lambda c: c[0]):
		if site < committed_to:
			overlapped += 1
			continue
		stub_address = stub_base + len(blob)
		body = build_stub(site, encoding, operands, mnemonic, window,
		                  displaced, stub_address, scratch, pool)
		if body is None:
			refused += 1
			continue
		placed.append((site, window, stub_address))
		committed_to = site + window
		blob += body
		for address, _moved, _comment, _ops, _mn in displaced:
			swallowed.add(address)
	return placed, blob, swallowed, overlapped, refused


def apply_all(binary, listing, output):
	patches, candidates, _stats, _skipped = collect(binary, listing)
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
	      f"{overlapped:,} skipped for overlap, {refused:,} refused")
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

	_patches, candidates, _stats, _skipped = collect(original, listing)
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
