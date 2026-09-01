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
import re
import struct
import subprocess
import sys
from collections import Counter

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

# rax, rcx, rdx and r8-r11 by number, which is what an encoding wants.
GPR_NUMBERS = {"rax": 0, "rcx": 1, "rdx": 2,
               "r8": 8, "r9": 9, "r10": 10, "r11": 11}


def encode_tls_base(block, index, index_va, at):
	"""Put this module's TLS block in `block`, using `index` as scratch.

	    movq %gs:0x58,%block
	    mov  tls_index(%rip),%indexd
	    movq (%block,%index,8),%block

	`at` is where the sequence starts, because the middle instruction is
	rip-relative and a displacement is measured from the END of it.

	Both registers are clobbered and neither is put back. That is the whole
	reason this needs `gpr_live_out` rather than a save: there is nowhere to
	save a general-purpose register to that does not need a register to
	address, which is the circularity Finding 69 met and Finding 141 broke
	by finding registers that were already dead.
	"""
	out = bytearray()
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
	return bytes(out)


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
	successors, unresolved, leaving = control_successors(
		plain, first, last, inside_targets)
	everything = frozenset(VOLATILE_GPRS)
	effects = {}
	for position in range(first, last):
		_a, _e, mnemonic, operands = plain[position]
		effects[position] = gpr_effect(mnemonic, operands or "")

	# Seeded once: what is live on the way OUT of a position, before any
	# successor has been accounted for.
	base = {}
	for position in range(first, last):
		out = set()
		if position in unresolved or position in leaving:
			out |= everything
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
			if inner:
				for why, count in inner.items():
					reasons["moved: " + why.replace("lower: ", "")] += count
			else:
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
			free = set(VOLATILE_XMM) - taken - set(own)
			for position in list(stores) + [load_at]:
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


def span_operand_shape(vex, tail, operands, tracked):
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
	if len(fields) == 2 and len(wide) == 1:
		if "(" in fields[0] and wide[0] == fields[1]:
			return ("load", canonical_ymm(fields[1]))
		if "(" in fields[1] and wide[0] == fields[0]:
			return ("store", canonical_ymm(fields[0]))
		return None
	if len(fields) == 3 and len(wide) == 2 and "(" in fields[0] \
			and fields[1] == fields[2]:
		# `op mem,%ymmD,%ymmD` -- src1 IS the destination, so the SSE form
		# is the prefix dropped and nothing rearranged.
		return ("lane", canonical_ymm(fields[2]))
	return None


def slot_tail(register, base, slot):
	"""modrm and SIB for `slot(%rsp)` with modrm.reg = `register`.

	The same address `encode_spill` writes, built as a TAIL so that
	`sse_encoding` can put any opcode in front of it -- which is what makes
	an upper half an operand of the operation rather than only something
	moved in and out.
	"""
	offset = base + slot * SLOT
	return bytes([0x80 | ((register & 7) << 3) | 4, 0x24]) \
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
		out.append((kind, address, encoding, mnemonic, operands,
		            slots.get(register), moved))
	return out


def lower_ymm_span(entries, base, helper, at, pool):
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
	"""
	body = bytearray()
	for kind, address, encoding, mnemonic, operands, slot, moved in entries:
		if kind == "plain":
			fixed = moved_instruction(moved[:5], at + len(body), pool)
			if fixed is None:
				return None
			body += fixed
			continue
		vex = inplace.decode_vex(encoding)
		if vex is None or not vex["L"]:
			return None
		tail = encoding[vex["length"]:]
		shape = span_operand_shape(vex, tail, operands, None)
		if shape is None or slot is None:
			return None
		what = shape[0]
		if what == "load":
			low = narrow_piece(vex, tail, 0, address, len(encoding),
			                   at + len(body))
			if low is None:
				return None
			body += low
			high_vex, high_tail = retarget(vex, tail, helper)
			piece = narrow_piece(high_vex, high_tail, SLOT, address,
			                     len(encoding), at + len(body))
			if piece is None:
				return None
			body += piece
			body += encode_spill(helper, True, at + len(body), 0, slot, base)
			continue
		if what == "store":
			low = narrow_piece(vex, tail, 0, address, len(encoding),
			                   at + len(body))
			if low is None:
				return None
			body += low
			body += encode_spill(helper, False, at + len(body), 0, slot,
			                     base)
			high_vex, high_tail = retarget(vex, tail, helper)
			piece = narrow_piece(high_vex, high_tail, SLOT, address,
			                     len(encoding), at + len(body))
			if piece is None:
				return None
			body += piece
			continue
		# A lane-wise operation whose other source is memory. The low half
		# is the instruction with L cleared; the upper half is the same
		# opcode between the slot and the helper.
		low = inplace.sse_encoding(dict(vex, L=0), tail)
		if low is None:
			return None
		body += low
		body += encode_spill(helper, False, at + len(body), 0, slot, base)
		high_vex, high_tail = retarget(vex, tail, helper)
		piece = narrow_piece(high_vex, high_tail, SLOT, address,
		                     len(encoding), at + len(body))
		if piece is None:
			return None
		body += piece
		body += encode_spill(helper, True, at + len(body), 0, slot, base)
	return bytes(body)


def span_helper(scope, address, entries):
	"""One xmm free across the whole span, or None.

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
		return None
	for _kind, _address, _encoding, _mnemonic, operands, _slot, _moved \
			in entries:
		free -= set(scratch_finder.xmm_numbers(operands or ""))
	return min(free) if free else None


def span_candidate(instructions, plain, positions, index, blocked, home,
                   ranges, scope):
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
	base = window_borrow(home, address, window)
	if base is None or peak > SLOTS_PER_REGION:
		# The first increment takes the callee home space only: 32 bytes,
		# two slots, at one displacement for the whole window. The shadow
		# and a per-thread block are what Finding 143 priced and neither is
		# wired here.
		return None
	slots = {}
	for _kind, _position, register in members:
		if register is not None and register not in slots:
			slots[register] = len(slots)
	if len(slots) > SLOTS_PER_REGION:
		return None
	entries = span_entries(members, instructions, slots, scope, plain)
	helper = span_helper(scope, address, entries)
	if helper is None:
		return None
	if lower_ymm_span(entries, base, helper, address, address) is None:
		return None
	return (address, encoding, operands, mnemonic, window, [], None, [],
	        ("span", (entries, helper)))


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


def reaching_definition(instructions, index, register, blocked, limit=640,
                        sources=None, depth=4):
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
	if instructions[index][0] in blocked:
		if not value_survives_loop(instructions, index, register, blocked,
		                           sources):
			return None
	narrow = "%xmm" + register[len("%ymm"):]
	for step in range(1, limit + 1):
		position = index - step
		if position < 0:
			return None
		address, _encoding, mnemonic, operands, _comment = \
			instructions[position]
		if mnemonic.startswith(CONTROL_PREFIXES) \
				and not conditional_branch(mnemonic):
			return None
		if mnemonic in UPPER_HALF_KILLERS:
			# It decides the upper half and names nothing, so the operand
			# test below cannot see it. Returning its position refuses both
			# callers, which is right for `constant_ymm` -- the upper half is
			# no longer the constant's -- and costs `zeroed_ymm` nothing it
			# was measured to have: zero of the 10,933 zero stores this scan
			# reaches have one between the idiom and the store, because MSVC
			# emits `vzeroupper` before a call or a return and the walk stops
			# at either.
			return position
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
				return position
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
				return None
			return reaching_definition(instructions, position, register,
			                           blocked, limit, sources, depth - 1)
		# A pure source, or no mention at all: the value is unchanged.
	return None


def zeroed_ymm(instructions, index, register, blocked, limit=640,
               sources=None, depth=4):
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
                 limit=640, sources=None, depth=4):
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
	position = reaching_definition(instructions, index, register, blocked,
	                              limit, sources, depth)
	if position is None:
		return None
	return constant_load(instructions[position], readonly)


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
	return False


def emit_swallowed(entry, body, stub_address, pool, spill_base, reasons,
                   base):
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
	if borrowing and base is None:
		if reasons is not None:
			reasons["the window will not hold one borrow displacement"] += 1
		return None
	out = bytearray()
	if borrowing:
		saved = encode_spill(entry[5], True, stub_address + len(body),
		                     spill_base, 0, base)
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
		restored = encode_spill(entry[5], False,
		                        stub_address + len(body) + len(out),
		                        spill_base, 0, base)
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
		tls_pair = None
		if base is None and tls is not None:
			available = sorted(window_gpr_free(home, start, window))
			if len(available) >= 2:
				# r11 and r10 first where they are free: neither is ever an
				# argument or a return value, so taking them disturbs the
				# fewest other things this tool might later want.
				ordered = sorted(available, key=lambda n: -n)
				tls_pair = (ordered[0], ordered[1])
		if base is None and tls_pair is None:
			if reasons is not None:
				reasons["the site will not hold one borrow displacement"] += 1
			return None, 0
		if SPILL == SPILL_STACK:
			body += STACK_OPEN
			# Where the allocation is complete, which is what the unwind
			# code's offset means and why it is measured rather than assumed
			# to be zero: a backward-widened window emits its swallowed
			# instructions first.
			prologue = len(body)
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
		if SPILL == SPILL_STACK:
			body += STACK_CLOSE
		lowered = b""
	elif kind == "span":
		# **The upper halves live in the callee home space for the length
		# of the window**, which is why the displacement has to be one
		# number over all of it -- `window_borrow`'s argument, and the
		# reason a span holding a `push` is refused rather than restored
		# from somewhere the save never wrote.
		entries, helper = strategy[1]
		if base is None:
			if reasons is not None:
				reasons["the span will not hold one slot displacement"] += 1
			return None, 0
		lowered = lower_ymm_span(entries, base, helper,
		                         stub_address + len(body), pool)
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

	for entry in displaced:
		fixed = emit_swallowed(entry, body, stub_address, pool,
		                       spill_base, reasons, base)
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
			found = tls_slot(image.read())
		if found is not None:
			tls_slot_offset = found
	# Where a 256-bit load can be taken at its word. Only the headers are
	# read: the ranges come from the section table, and the bytes inside them
	# are the CPU's business rather than this tool's.
	with open(binary, "rb") as image:
		readonly = readonly_ranges(image.read(1 << 16))
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
					if inplace.covered_by(ranges, address, span) \
							and lower_zero_run(entries, address) is not None:
						candidates.append(
							(address, encoding, operands, mnemonic, span,
							 [], None, [], ("splatrun", entries)))
						continue
				if inplace.covered_by(ranges, address, window) \
						and lower_ymm_zero_store(*splat, at=address) \
						is not None:
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
					if inplace.covered_by(ranges, address, window) \
							and lower_splat_operation(*triple, at=address) \
							is not None:
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
			                         blocked, home, ranges, scope)
			if spanned is not None:
				candidates.append(spanned)
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
					if lower_long_half(vex, tail, address, len(encoding),
					                   address, shadow) is not None:
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
				if SPILL in HOME_SPILLS \
						and borrow_offset(home, address) is None:
					# **The home space first, always.** It needs no
					# register to address and no directory raised, so
					# `--spill=tls` differs from `--spill=home` only where
					# the home space said no. Two registers, because the
					# addressing needs two and one is worth nothing to it.
					if SPILL != SPILL_TLS or tls_slot_offset is None \
							or len(gpr_free_at(home, address)) < 2:
						skipped["no home space to borrow"] += 1
						declined[address] = "no home space to borrow"
						continue
				borrowed = borrow_that_lowers(address, encoding, operands,
				                              mnemonic, address, address)
				if borrowed is not None:
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
					displaced.append((nxt_address, nxt_encoding, nxt_comment,
					                  nxt_operands, nxt_mnemonic,
					                  taken if borrow is None else borrow,
					                  borrow is not None))
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
				elif previous[2].startswith(CONTROL_PREFIXES) \
						and not swallowable_transfer(
							previous[1], previous[2], previous[3],
							previous[4], previous[0]):
					pass		# does not fall through into the site
				elif len(previous[1]) + len(encoding) < 5:
					pass
				else:
					taken = swallowed_scratch(
						plain, index - 1, previous[0], previous[1],
						previous[3], previous[2], scope)
					borrow = None
					if taken is None:
						borrow = swallowed_borrow(
							plain, previous[0], previous[1], previous[3],
							previous[2], home)
					preceding.append((previous[0], previous[1], previous[4],
					                  previous[3], previous[2],
					                  taken if borrow is None else borrow,
					                  borrow is not None))
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
	failures += gpr_selftest()
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
TLS_ENCODINGS = [
	("movq %gs:0x58,%rax / mov (%rip),%edx / movq (%rax,%rdx,8),%rax",
	 "65488b0425580000008b155f332211488b04d0",
	 ("base", 0, 2, 0x1122336e, 0)),
	("the same with r10 and r11, which need every REX bit",
	 "654c8b142558000000448b1d653322114f8b14da",
	 ("base", 10, 11, 0x11223375, 0)),
	("movups %xmm2,0x3260(%rax)", "0f119060320000",
	 ("spill", 2, True, 0, 0x3260)),
	("movups %xmm2,0x3260(%r10), which needs REX.B", "410f119260320000",
	 ("spill", 2, True, 10, 0x3260)),
	("movups %xmm9,0x3260(%r10), REX.R and REX.B", "450f118a60320000",
	 ("spill", 9, True, 10, 0x3260)),
	("and the restore, which differs by one opcode byte",
	 "450f108a60320000", ("spill", 9, False, 10, 0x3260)),
]


def tls_selftest():
	"""Prove the TLS encodings still say what `as` said. Failures, or 0."""
	failures = 0
	for what, want, call in TLS_ENCODINGS:
		got = (encode_tls_base(*call[1:]) if call[0] == "base"
		       else encode_tls_spill(*call[1:])).hex()
		if got != want:
			print(f"selftest: {what}: encoded {got}, want {want}",
			      file=sys.stderr)
			failures += 1
	if not failures:
		print(f"selftest: {len(TLS_ENCODINGS)} tls encodings match the "
		      f"assembler byte for byte")
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
	covered, refused, fit = set(), Counter(), Counter()
	tls_covered, tls_reason = set(), Counter()
	forms = Counter()
	for index, (address, encoding, _m, _o, _c) in enumerate(instructions):
		if address not in survivors:
			continue
		vex = inplace.decode_vex(encoding)
		if vex is None or not vex["L"]:
			continue
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
	_patches, candidates, _stats, _skipped, declined, home = collect(
		binary, listing)
	placed, _blob, swallowed, overlapped, refused = place_stubs(
		candidates, stub_base_of(open(binary, "rb").read()), home=home,
		tls=tls_pair_of(tls_for(binary)))
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

	print(f"detour.py: unknown mode {mode!r}", file=sys.stderr)
	return 2


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
		return tls_slot(image.read())


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
				preceding, strategy, spill_base, home=home, tls=tls)
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
					detail[start] = (next(iter(per)), window,
					                 list(preceding), list(displaced))
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
			entries = strategy[1][1]
			for entry in entries[1:]:
				swallowed.add(entry[4])
		if strategy is not None and strategy[0] == "span":
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
	patches, candidates, _stats, _skipped, _declined, home = collect(
		binary, listing)
	data = bytearray(open(binary, "rb").read())
	# Read from the ORIGINAL bytes, before anything is appended: the
	# directory's own contents do not move, and reading it later would make
	# the answer depend on how far the rewrite had got.
	tls_here = tls_for(binary)
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
	# **The largest remaining bucket was the one with no reason.** `build_stub`
	# returned None and nothing said why, so 3,959 refusals reconciled to
	# "refused" and stopped there -- and Finding 45 had to walk its three
	# steps by hand to find out that a swallowed instruction wanted a scratch.
	# Every failure path names itself now. Finding 88.
	stub_reasons = Counter()
	placed, blob, _swallowed, overlapped, refused = place_stubs(
		candidates, stub_base, spill_base, stub_reasons, home=home,
		tls=tls_pair_of(tls_here))

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
	print(f"apply: {len(patches):,} in-place patches, {len(placed):,} detours, "
	      f"{len(overlapped):,} skipped for overlap, {len(refused):,} refused")
	for why, count in stub_reasons.most_common():
		print(f"apply:   refused, {why:<38} {count:>8,}")
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
		if found is not None:
			at = found[0] + 32 - (raddr + size)
			if 0 <= at and at + 4 <= len(tail_a) and len(tail_a) == len(tail_b):
				restored = bytearray(tail_a)
				restored[at:at + 4] = tail_b[at:at + 4]
				if bytes(restored) == bytes(tail_b):
					raised = struct.unpack_from("<I", bytes(tail_b), at)[0]
		if raised is None:
			print("verify: FAILED -- sections after .text changed",
			      file=sys.stderr)
			problems += 1
		else:
			print(f"verify: every section after .text is byte-identical "
			      f"except SizeOfZeroFill, raised to {raised} so the "
			      f"loader allocates the per-thread slot")

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

	_patches, candidates, _stats, _skipped, _declined, home = collect(
		original,
	                                                           listing)
	# The same call apply makes, so the two cannot drift apart.
	placed, _blob, swallowed, _overlapped, _refused = place_stubs(
		candidates, stub_base_of(open(original, "rb").read()), home=home,
		tls=tls_pair_of(tls_for(original)))
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
