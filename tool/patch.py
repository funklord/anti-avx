#!/usr/bin/env python3
"""In-place VEX to SSE patching, for the classes that fit.

Milestone 4 was specified as classes A/B/C/Z through the Ddisasm pipeline.
Milestone 3 blocked on memory, so this takes the other road: **patch the
bytes where the SSE encoding is no longer than the VEX one.**

That road exists because of an encoding accident. A VEX prefix carries the
legacy prefix, the REX bits, the opcode map and an extra register operand in
two or three bytes; the SSE form spells the same things out as a legacy
prefix, a REX byte and a 0F escape. Often those come to the same length, and
when the SSE form is shorter the difference is padded with a nop.

What that buys is the whole of hard part 2. Nothing moves, so every address
is unchanged, and `.pdata`, `.xdata`, the base relocations, the jump tables
and the import tables are all still correct **because they were never
touched**. The output is the same size as the input, byte-identical outside
the patched instructions.

What it cannot do is Class C. `vaddss %xmm2,%xmm1,%xmm0` is four bytes and
becomes `movaps` plus `addss`, which is seven. An instruction that grows
needs somewhere to put the growth, and that needs the relocation machinery
this file exists to avoid. So Class C is left alone here and the binary
still faults -- later, and at a site this tool can name, which is what
milestone 4 asks for.

  plan    <binary> <listing>        what fits, and what does not
  apply   <binary> <listing> <out>  write the patched binary
  verify  <original> <patched>      check the invariants hold

Both plan and apply restrict themselves to functions .pdata describes.
`--all` lifts that, which is unsound and exists only to measure the cost of
the restriction.
"""

import bisect
import re
import struct
import subprocess
import sys
from collections import Counter

# Legacy prefix implied by the VEX pp field.
PP_PREFIX = {0: None, 1: 0x66, 2: 0xF3, 3: 0xF2}

# Opcode-map escape implied by the VEX mmmmm field.
MAP_ESCAPE = {1: (0x0F,), 2: (0x0F, 0x38), 3: (0x0F, 0x3A)}

# A one-byte nop, and the multi-byte forms, so padding does not cost more
# decode slots than it has to.
NOPS = {
	1: b"\x90",
	2: b"\x66\x90",
	3: b"\x0f\x1f\x00",
	4: b"\x0f\x1f\x40\x00",
	5: b"\x0f\x1f\x44\x00\x00",
	6: b"\x66\x0f\x1f\x44\x00\x00",
	7: b"\x0f\x1f\x80\x00\x00\x00\x00",
	8: b"\x0f\x1f\x84\x00\x00\x00\x00\x00",
}

def has_direct_sse_form(mnemonic):
	"""True if stripping the VEX prefix alone yields a real SSE instruction.

	The mnemonic tables in lower.py do not list the compare forms, because
	objdump folds the predicate into the name -- `vcmpneqps` rather than
	`vcmpps` with an immediate. The encoding still carries the predicate as
	an imm8, so the SSE form really is a plain prefix strip.

	Only for the eight predicates SSE has, though. AVX widened the field to
	thirty-two, and an SSE `cmpps` carrying one of the new values is not a
	valid instruction -- those need the operand exchange in lower.py and
	belong in a sequence, not here.
	"""
	if mnemonic in lower.DIRECT_MNEMONICS or mnemonic in lower.NDS_MNEMONICS:
		return True
	predicate = lower.compare_predicate(mnemonic)
	if predicate is None:
		return False
	name, avx_only = predicate
	return not avx_only and name in lower.SSE_PREDICATES


def nop_padding(length):
	"""Padding of any length, built from the longest nops available.

	The table above stops at eight because that is all an in-place patch
	ever needs. A detour window widened over a following instruction can
	need more, and a KeyError there is a crash rather than a wrong answer
	-- but only because the table was indexed directly. Compose instead.
	"""
	out = bytearray()
	while length > 0:
		take = min(length, 8)
		out += NOPS[take]
		length -= take
	return bytes(out)


# Instructions whose VEX form puts the DESTINATION in vvvv rather than in
# the modrm reg field, which holds an opcode extension instead.
#
# These are the trap in this whole exercise. The test for "the destination
# already equals the first source, so the third operand can be dropped" is
# `vvvv == reg`, and for these that comparison is meaningless -- reg is a
# constant like /6, so a destination that happens to be xmm6 would pass the
# test and be rewritten into an instruction that writes the wrong register.
#
# They are excluded wholesale rather than handled. Together they are a few
# hundred sites out of eight hundred thousand, and the shift group mixes NDD
# immediate forms with NDS register forms under one mnemonic, so telling
# them apart needs the opcode rather than the name.
DESTINATION_IN_VVVV = frozenset("""
	vpsllw vpslld vpsllq vpsrlw vpsrld vpsrlq vpsraw vpsrad
	vpslldq vpsrldq
""".split())


sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
import lower			# noqa: E402  -- after the sys.path fix above
import resync			# noqa: E402


# objdump renders a redundant REX prefix as its own token -- `rex.W jmp *m64`
# rather than `jmp`. See parse_listing.
REX_PREFIX = re.compile(r"^rex(\.[RXBW]+)?$")


def parse_listing(path):
	"""Yield (address, encoding, mnemonic, operands) from an objdump listing.

	objdump wraps an encoding longer than seven bytes onto a continuation
	line carrying an address and bytes but no mnemonic:

	    1402aa9db:\tc5 f8 10 1d 8d cb 79
	    1402aa9e2:\t04

	**Those trailing bytes are part of the instruction.** Reading only the
	first line makes an eight-byte instruction look like seven, and a
	patcher that believes it writes a seven-byte replacement over it leaves
	the last byte of the original stranded and corrupts both. That is not
	hypothetical: it is what the first version of this file did, to every
	instruction with a 32-bit displacement.
	"""
	pending = None
	for line in open(path, "r", errors="replace"):
		parts = line.split("\t")
		if len(parts) == 2 and pending is not None:
			# A continuation: more bytes for the instruction just yielded.
			try:
				pending[1].extend(bytes.fromhex(parts[1].strip()))
			except ValueError:
				pass
			continue
		if pending is not None:
			yield (pending[0], bytes(pending[1]), pending[2], pending[3])
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
		if not encoding:
			continue
		body = parts[2]
		hash_at = body.find("#")
		if hash_at >= 0:
			body = body[:hash_at]
		fields = body.strip().split(None, 1)
		if not fields:
			continue
		mnemonic = fields[0]
		operands = fields[1] if len(fields) > 1 else ""
		# **objdump prints a redundant REX prefix as a token of its own**, so
		# `48 ff 25` -- the encoding every import thunk ends with -- reads as
		# the mnemonic `rex.W` with `jmp *0x...(%rip)` as its operands. Every
		# test in this tree that asks what an instruction IS then answers
		# wrongly about it, and they are the tests that decide where a window
		# may reach and where a scan must stop.
		#
		# Measured in the listing: 38,465 instructions are printed this way
		# and **5,477 of them are jumps**, invisible to any
		# `startswith(CONTROL_PREFIXES)` check. outside.py rejects a thunk
		# that plainly ends in one, which is what led here. Finding 85.
		#
		# A lone prefix with no instruction after it is left alone: that is
		# objdump decoding data as code, and it is not a jump.
		if REX_PREFIX.match(mnemonic) and operands:
			rest = operands.split(None, 1)
			mnemonic = rest[0]
			operands = rest[1] if len(rest) > 1 else ""
		pending = [address, bytearray(encoding), mnemonic, operands]
	if pending is not None:
		yield (pending[0], bytes(pending[1]), pending[2], pending[3])


def decode_vex(encoding):
	"""Decode a VEX prefix. Returns a dict, or None if this is not VEX."""
	if len(encoding) < 3:
		return None
	if encoding[0] == 0xC5:
		second = encoding[1]
		return {
			"length": 2,
			"map": 1,
			"pp": second & 3,
			"L": (second >> 2) & 1,
			"vvvv": (~(second >> 3)) & 0xF,
			"R": (~(second >> 7)) & 1,
			"X": 0, "B": 0, "W": 0,
		}
	if encoding[0] == 0xC4 and len(encoding) >= 4:
		second, third = encoding[1], encoding[2]
		return {
			"length": 3,
			"map": second & 0x1F,
			"pp": third & 3,
			"L": (third >> 2) & 1,
			"vvvv": (~(third >> 3)) & 0xF,
			"R": (~(second >> 7)) & 1,
			"X": (~(second >> 6)) & 1,
			"B": (~(second >> 5)) & 1,
			"W": (third >> 7) & 1,
		}
	return None


# **Legacy SSE faults on a 16-byte memory operand that is not 16-byte
# aligned; VEX does not.** These are the legacy forms, by (map, pp, opcode),
# whose memory operand carries NO such requirement -- a scalar or narrower
# operand, an explicitly unaligned move, or an instruction whose VEX form
# required alignment already (`movaps`, `movdqa`, the non-temporals), where
# lowering changes nothing. Every other form with a memory operand needs it
# aligned. pp: 0 none, 1 66, 2 F3, 3 F2. Finding 341.
_ANY = (0, 1, 2, 3)
ALIGN_GUARD = True
ALIGNMENT_FREE = set()
for _pp, _ops in (((0, 1), (0x10, 0x11, 0x12, 0x13, 0x16, 0x17, 0x28, 0x29,
                             0x2B, 0x2E, 0x2F, 0xAE, 0xC4)),
                  ((2, 3), tuple(range(0x10, 0x12)) + (0x2C, 0x2D, 0x2A,
                             0x51, 0x52, 0x53, 0x58, 0x59, 0x5A, 0x5C, 0x5D,
                             0x5E, 0x5F, 0xC2, 0x7E, 0xD6)),
                  ((2,), (0x6F, 0x7F, 0x2C, 0x2D)),
                  ((3,), (0x12, 0xF0, 0x7C, 0x7D)),
                  ((1,), (0x6F, 0x7F, 0xE7, 0x6E, 0x7E, 0xD6, 0xC4, 0xC5,
                          0x2B, 0x28, 0x29, 0x2E, 0x2F, 0x12, 0x13, 0x16,
                          0x17))):
	for _p in _pp:
		for _op in _ops:
			ALIGNMENT_FREE.add((1, _p, _op))
for _op in (0x6E, 0x7E, 0x5A):
	ALIGNMENT_FREE.add((1, 0, _op))
# movsldup/movshdup are F3 0F 12/16 with an m128 that must be aligned, and
# movhlps-style 12/13/16/17 are m64 only under none/66; take those back.
ALIGNMENT_FREE.discard((1, 2, 0x12))
ALIGNMENT_FREE.discard((1, 2, 0x16))
# haddps/hsubps (F2 7C/7D) are m128 and aligned; take those back too.
ALIGNMENT_FREE.discard((1, 3, 0x7C))
ALIGNMENT_FREE.discard((1, 3, 0x7D))
for _op in list(range(0x20, 0x26)) + list(range(0x30, 0x36)) + [0x2A]:
	ALIGNMENT_FREE.add((2, 1, _op))		# pmovsx/pmovzx (narrow), movntdqa
for _op in (0x0A, 0x0B, 0x14, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22,
            0x60, 0x61, 0x62, 0x63):
	ALIGNMENT_FREE.add((3, 1, _op))		# scalar rounds, extracts, inserts,
						# and pcmpXstrX, which SSE4.2 exempts


def memory_operand(tail):
	"""The memory operand's kind: None for a register, "rip", or "other"."""
	if len(tail) < 2:
		return None
	mod, rm = tail[1] >> 6, tail[1] & 7
	if mod == 3:
		return None
	return "rip" if mod == 0 and rm == 5 else "other"


def needs_alignment(vex, tail):
	"""Whether the legacy form of this needs its memory operand aligned
	where the VEX form did not. See `ALIGNMENT_FREE`."""
	if memory_operand(tail) is None:
		return False
	return (vex["map"], vex["pp"], tail[0]) not in ALIGNMENT_FREE


def sse_encoding(vex, tail, guarded=False):
	"""The SSE bytes equivalent to a VEX prefix plus everything after it.

	**Refuses VEX.L, and that refusal is the whole point of this guard being
	here rather than in the callers.** There is no SSE encoding of a 256-bit
	instruction. Dropping the prefix from one produces a perfectly valid
	128-bit instruction that assembles, disassembles, carries no VEX, and
	writes half as many bytes as it should -- `vmovups %ymm0,(%rax)` becomes
	`movups %xmm0,(%rax)` and stores 16 bytes where the program wrote 32.

	It was reachable, and it was reached: 32,749 sites, 31,829 of them
	`vmovups`, were being truncated exactly that way. Every structural check
	passed, because every one of them is about shape. The lowering tests
	missed it because they only ever generated 128-bit operands.

	A Y strategy will want 128-bit encodings built from a 256-bit source --
	that is what splitting a ymm into halves means -- and it must say so by
	passing a vex with L cleared, one half at a time. Silence is not
	consent here.
	"""
	if vex["map"] not in MAP_ESCAPE or vex["L"]:
		return None
	# **A compare's predicate has to be one SSE has.** `0F C2` reads
	# imm8[2:0] and calls the rest reserved, so a VEX-only predicate does
	# not fail -- it becomes a different compare. 16-23 are 0-7 with the
	# QNaN signalling flipped and compute the same mask, so they are
	# rewritten to it; 8-15 and 24-31 add the unordered sense, and
	# `$0x1e` (GT_OQ) ran as NLE, true on a NaN where GT is false. Every
	# path that strips a VEX prefix comes through here, which is why the
	# guard does too: three emitters had already carried such a predicate
	# into a stub. The imm8 is the tail's last byte in every form.
	# Finding 334.
	if vex["map"] == 1 and len(tail) >= 3 and tail[0] == 0xC2:
		predicate = tail[-1]
		if not (predicate < 8 or 16 <= predicate < 24):
			return None
		tail = tail[:-1] + bytes([predicate & 7])
	# **And a memory operand legacy SSE needs aligned, where nothing says it
	# is.** `vmulps -0x8(%rax),%xmm2,%xmm1` reads any address; `mulps` the
	# same operand faults unless it is 16-byte aligned, and Starfield ran
	# one into a general-protection fault 158 seconds in. A RIP operand's
	# address is fixed, and `verify` checks each one; anything else is
	# refused here, and `lower_vex` loads it with `movups` first. Every path
	# that strips a VEX prefix comes through here, but only a caller with
	# somewhere else to go asks for the refusal: the in-place pass, whose
	# site becomes a detour, and `lower_vex`, which loads first. The 256-bit
	# emitters have no fallback yet and `verify` counts what they leave.
	# Finding 341.
	if guarded and ALIGN_GUARD and needs_alignment(vex, tail) \
			and memory_operand(tail) != "rip":
		return None
	out = bytearray()
	legacy = PP_PREFIX[vex["pp"]]
	if legacy is not None:
		out.append(legacy)
	rex = 0x40 | (vex["W"] << 3) | (vex["R"] << 2) | (vex["X"] << 1) | vex["B"]
	if rex != 0x40:
		out.append(rex)
	out.extend(MAP_ESCAPE[vex["map"]])
	out.extend(tail)
	return bytes(out)


def offset_operand(tail, delta):
	"""`tail` with its memory displacement moved by `delta` bytes, or None.

	Needed to address the second half of a 256-bit memory operand: the same
	address plus sixteen. The displacement is not always there to adjust --
	`(%rax)` has none and has to grow one -- and it is not always wide
	enough, so a disp8 that overflows becomes a disp32 and the instruction
	gets longer. That is free here, because everything using this is being
	emitted into a stub.

	RIP-relative operands are refused here rather than adjusted, and that is
	a division of labour rather than a limitation. Their displacement is
	measured from the end of the instruction, so moving one has to account
	both for the +16 and for wherever the stub put it -- and this function is
	not told where the stub put it. `detour.narrow_piece` is, and does both
	corrections together; it reaches this one first and falls back.
	"""
	if len(tail) < 2:
		return None
	modrm = tail[1]
	mod, rm = (modrm >> 6) & 3, modrm & 7
	if mod == 3:
		return None			# a register operand has no displacement
	head = bytearray(tail[:2])
	rest = tail[2:]
	sib = b""
	if rm == 4:
		if not rest:
			return None
		sib, rest = rest[:1], rest[1:]

	def rebuilt(width, value):
		if width == 1 and -128 <= value <= 127:
			return bytes(head) + sib + struct.pack("<b", value)
		if not -(1 << 31) <= value < (1 << 31):
			return None
		head[1] = (modrm & 0x3F) | 0x80
		return bytes(head) + sib + struct.pack("<i", value)

	if mod == 0:
		if rm == 5:
			return None		# RIP-relative; see the docstring
		if rm == 4 and (sib[0] & 7) == 5:
			if len(rest) < 4:
				return None
			value = struct.unpack_from("<i", rest, 0)[0] + delta
			out = rebuilt(4, value)
			return None if out is None else out + rest[4:]
		# No displacement at all, so one has to be grown.
		head[1] = (modrm & 0x3F) | (0x40 if -128 <= delta <= 127 else 0x80)
		out = rebuilt(1 if -128 <= delta <= 127 else 4, delta)
		return None if out is None else out + rest
	if mod == 1:
		if not rest:
			return None
		value = struct.unpack_from("<b", rest, 0)[0] + delta
		out = rebuilt(1, value)
		return None if out is None else out + rest[1:]
	if len(rest) < 4:
		return None
	value = struct.unpack_from("<i", rest, 0)[0] + delta
	out = rebuilt(4, value)
	return None if out is None else out + rest[4:]


def split_operands(text):
	"""Split an AT&T operand list on top-level commas."""
	out, depth, start = [], 0, 0
	for i, ch in enumerate(text):
		if ch == "(":
			depth += 1
		elif ch == ")":
			depth -= 1
		elif ch == "," and depth == 0:
			out.append(text[start:i].strip())
			start = i + 1
	tail = text[start:].strip()
	if tail:
		out.append(tail)
	return out


def classify(mnemonic, vex, operands, direct, nds):
	"""Return 'A', 'B', 'Z' if this site can be patched in place, else None.

	**Which form this is cannot be read off the encoding.** VEX stores vvvv
	in one's complement, and an unused vvvv is required to be 1111b -- which
	is exactly what a vvvv naming xmm0 also encodes. A two-operand vmovss
	and a three-operand one whose first source is xmm0 have the same bits
	there, and only the opcode says which is which.

	So the form comes from the operand list, which is what tool/lower.py
	uses and what the disassembler already worked out.
	"""
	if mnemonic == "vzeroupper":
		return "Z"
	# For these the destination lives in vvvv and modrm.reg is an opcode
	# extension, so modrm.rm names the SOURCE. The SSE form is two-operand
	# with the destination in rm, which makes it the same instruction only
	# when destination and source are already the same register -- and then
	# the two encodings are the same length, so it patches in place. Where
	# they differ the write would silently move, and the site goes to
	# detour.py to have the source copied into the destination first.
	if mnemonic in DESTINATION_IN_VVVV:
		shift = [o for o in operands if not o.startswith("$")]
		if len(shift) == 2 and shift[0] == shift[1]:
			return "V"
		return None
	if not has_direct_sse_form(mnemonic):
		return None

	registers = [o for o in operands if not o.startswith("$")]
	if len(registers) == 1:
		# **A one-operand form, and this binary has exactly two of them**:
		# `vldmxcsr` and `vstmxcsr` name a memory operand and nothing else.
		# VEX.vvvv is unused and required to be 1111b, which is the same
		# test the two-operand case makes and for the same reason.
		#
		# The tests below were both written against a form with a
		# destination register, so these fell off the end -- and so did the
		# collector's own `len(registers) not in (2, 3)`, which is a
		# separate copy of the same assumption. Nine sites refused twice and
		# named once, with a lowering rule and a correct encoding waiting
		# for them the whole time. Finding 110.
		return "A" if vex["vvvv"] == 0 else None
	if len(registers) == 2:
		# A genuine two-operand form. vvvv is unused and must be encoded
		# 1111b, which decodes to zero here; anything else means this is
		# not the form it appears to be, so leave it alone.
		return "A" if vex["vvvv"] == 0 else None
	if len(registers) == 3:
		destination, source = registers[-1], registers[-2]
		return "B" if destination == source else None
	return None


def load_tables():
	"""The mnemonic tables from tool/lower.py, so there is one authority."""
	sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
	import lower
	return lower.DIRECT_MNEMONICS, lower.NDS_MNEMONICS


def build_patches(listing, ranges=None):
	"""Work out every in-place patch. Returns (patches, statistics)."""
	direct, nds = load_tables()
	patches = []
	stats = Counter()
	blocked = Counter()

	for address, encoding, mnemonic, operands in parse_listing(listing):
		# **A byte objdump could not decode is not an instruction**, and
		# this is the in-place path, which rewrites bytes where they lie.
		# `decode_vex` below rejects on LENGTH alone and never checks the
		# map field, so a constant pool's `c5 32 00` reaches here and is
		# turned away only by `classify` finding no table entry for the
		# mnemonic -- the same incidental guard the detour candidate loop
		# had, at the site where a wrong answer edits the image rather than
		# building a stub. It also counted them: `vex sites` was inflated
		# by every data byte carrying a VEX prefix. Finding 223.
		if mnemonic == "(bad)":
			stats["(bad) rows refused"] += 1
			continue
		vex = decode_vex(encoding)
		if vex is None:
			continue
		stats["vex sites"] += 1

		if mnemonic == "vzeroupper":
			patches.append((address, encoding, NOPS[len(encoding)], "Z",
			                mnemonic))
			stats["Z"] += 1
			continue

		tail = encoding[vex["length"]:]
		kind = classify(mnemonic, vex, split_operands(operands), direct, nds)
		if kind is None:
			stats["not A/B/Z"] += 1
			blocked[mnemonic] += 1
			continue

		replacement = sse_encoding(vex, tail, guarded=True)
		if replacement is None:
			stats["unencodable"] += 1
			continue
		grew = len(replacement) - len(encoding)
		if grew > 0:
			stats["would grow"] += 1
			blocked[f"{mnemonic} (+{grew}B)"] += 1
			continue
		if grew < 0:
			# Pad at the FRONT, not the back.
			#
			# A RIP-relative displacement is measured from the end of the
			# instruction, so an encoding that shrinks and is padded
			# afterwards ends one byte early and every such displacement
			# points somewhere else. Padding first keeps the end address
			# fixed, and a branch to the original start lands on the nop
			# and falls straight through -- so both the entry address and
			# the end address survive.
			replacement = nop_padding(-grew) + replacement
		if ranges is not None and not covered_by(ranges, address, len(encoding)):
			stats["outside .pdata"] += 1
			blocked[f"{mnemonic} (no unwind data)"] += 1
			continue
		patches.append((address, encoding, replacement, kind, mnemonic))
		stats[kind] += 1

	return patches, stats, blocked


def function_ranges(path):
	"""Sorted (start, end) of every function .pdata describes.

	This is the code oracle. A patcher driven by a linear sweep is only as
	sound as the sweep, and a linear sweep has no way to know it has walked
	into data -- bytes that happen to decode as a VEX instruction get
	"patched", which corrupts them. .pdata is the binary's own statement
	about where its functions are, needs no disassembly to read, and cannot
	be desynchronised.

	It is not complete: the x64 ABI lets a leaf function that neither
	allocates stack nor calls anything omit its unwind data, and this binary
	has 14,162 patchable sites in such functions. Those are left alone here.
	Being 2.4% less effective is the right trade against being wrong.
	"""
	data = open(path, "rb").read(0x1000)
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
	sections = struct.unpack_from("<H", data, pe + 6)[0]
	opt_size = struct.unpack_from("<H", data, pe + 20)[0]
	table = pe + 24 + opt_size
	pdata = None
	for i in range(sections):
		off = table + i * 40
		name = data[off:off + 8].rstrip(b"\0").decode("latin1")
		_vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off + 8)
		if name == ".pdata":
			pdata = (raddr, rsize)
	if pdata is None:
		return None
	raddr, rsize = pdata
	blob = open(path, "rb")
	blob.seek(raddr)
	raw = blob.read(rsize)
	ranges = []
	for i in range(len(raw) // 12):
		begin, end, _unwind = struct.unpack_from("<III", raw, i * 12)
		if end > begin:
			ranges.append((base + begin, base + end))
	ranges.sort()
	return ranges


def covered_by(ranges, address, length):
	"""True if [address, address+length) lies wholly inside one function."""
	i = bisect.bisect_right(ranges, (address, 1 << 62)) - 1
	return i >= 0 and address + length <= ranges[i][1]


def text_mapping(path):
	"""(virtual address, file offset, size) of .text."""
	data = open(path, "rb").read(0x1000)
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	sections = struct.unpack_from("<H", data, pe + 6)[0]
	opt_size = struct.unpack_from("<H", data, pe + 20)[0]
	base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
	table = pe + 24 + opt_size
	for i in range(sections):
		off = table + i * 40
		name = data[off:off + 8].rstrip(b"\0").decode("latin1")
		vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off + 8)
		if name == ".text":
			return base + vaddr, raddr, rsize
	raise SystemExit("no .text section")


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	mode = argv[0]

	if mode == "plan":
		ranges = None if "--all" in argv else function_ranges(argv[1])
		patches, stats, blocked = build_patches(argv[2], ranges)
		total = stats["vex sites"]
		print(f"VEX sites            {total:>10,}")
		for key in ("A", "B", "Z"):
			print(f"  patchable, class {key} {stats[key]:>10,}"
			      f"   {100.0 * stats[key] / total:5.2f}%")
		fits = stats["A"] + stats["B"] + stats["Z"]
		print(f"  patchable, total   {fits:>10,}   "
		      f"{100.0 * fits / total:5.2f}%")
		print(f"  needs relocation   {stats['not A/B/Z']:>10,}   "
		      f"{100.0 * stats['not A/B/Z'] / total:5.2f}%")
		print(f"  would grow in place{stats['would grow']:>10,}   "
		      f"{100.0 * stats['would grow'] / total:5.2f}%")
		print(f"  outside .pdata     {stats['outside .pdata']:>10,}   "
		      f"{100.0 * stats['outside .pdata'] / total:5.2f}%")
		print("\nmost common sites that cannot be patched in place:")
		for name, count in blocked.most_common(12):
			print(f"    {name:<28} {count:>10,}")
		return 0

	if mode == "apply":
		binary, listing, output = argv[1], argv[2], argv[3]
		ranges = None if "--all" in argv else function_ranges(binary)
		patches, stats, _ = build_patches(listing, ranges)
		vaddr, raddr, _size = text_mapping(binary)
		data = bytearray(open(binary, "rb").read())
		written = 0
		for address, original, replacement, _kind, _mnemonic in patches:
			offset = raddr + (address - vaddr)
			if bytes(data[offset:offset + len(original)]) != original:
				raise SystemExit(
					f"refusing to patch 0x{address:x}: the bytes on disk are "
					f"not the bytes the listing described")
			if len(replacement) != len(original):
				raise SystemExit(
					f"refusing to patch 0x{address:x}: length changed")
			data[offset:offset + len(original)] = replacement
			written += 1
		open(output, "wb").write(bytes(data))
		print(f"apply: patched {written:,} sites into {output}")
		return 0

	if mode == "verify":
		return verify(argv[1], argv[2])

	print(f"patch.py: unknown mode {mode!r}", file=sys.stderr)
	return 2


def verify(original, patched):
	"""Check the invariants an in-place patch has to hold."""
	a = open(original, "rb").read()
	b = open(patched, "rb").read()
	problems = 0

	if len(a) != len(b):
		print(f"verify: FAILED -- size changed, {len(a):,} -> {len(b):,}",
		      file=sys.stderr)
		return 1
	print(f"verify: size unchanged, {len(a):,} bytes")

	vaddr, raddr, size = text_mapping(original)

	# Chunked, because a byte-at-a-time loop over 102 MB in an interpreter
	# is minutes rather than seconds. Only chunks that differ are examined
	# byte by byte.
	differing = 0
	outside = 0
	step = 1 << 16
	for base in range(0, len(a), step):
		chunk_a = a[base:base + step]
		chunk_b = b[base:base + step]
		if chunk_a == chunk_b:
			continue
		for i, (x, y) in enumerate(zip(chunk_a, chunk_b)):
			if x == y:
				continue
			differing += 1
			if not (raddr <= base + i < raddr + size):
				outside += 1
	if outside:
		print(f"verify: FAILED -- {outside:,} bytes differ OUTSIDE .text",
		      file=sys.stderr)
		problems += 1
	else:
		print(f"verify: {differing:,} bytes differ, every one inside .text")

	# The headers carry the section table, the data directories and the
	# entry point. Nothing here should have touched them.
	if a[:raddr] != b[:raddr]:
		print("verify: FAILED -- headers changed", file=sys.stderr)
		problems += 1
	else:
		print(f"verify: headers byte-identical ({raddr:,} bytes)")

	before_bounds, before_vex, _before_bad = disassemble(original)
	after_bounds, after_vex, _after_bad = disassemble(patched)
	print(f"verify: VEX-encoded instructions {len(before_vex):,} -> "
	      f"{len(after_vex):,}  ({len(before_vex) - len(after_vex):,} removed, "
	      f"{100.0*(len(before_vex)-len(after_vex))/len(before_vex):.1f}%)")

	# The invariant that matters, and the one that catches a patch which
	# changed an instruction's length without meaning to. Every address
	# that began an instruction before must still begin one; the patched
	# binary may have MORE boundaries, because a front-pad nop adds one.
	#
	# A desynchronised sweep fails this immediately, which is how the
	# continuation-line bug and the RIP-relative bug were both found.
	lost = before_bounds - after_bounds
	if lost:
		print(f"verify: FAILED -- {len(lost):,} instruction boundaries no "
		      f"longer decode as boundaries", file=sys.stderr)
		for address in sorted(lost)[:8]:
			print(f"    0x{address:x}", file=sys.stderr)
		problems += 1
	else:
		print(f"verify: all {len(before_bounds):,} instruction boundaries "
		      f"preserved")

	# And every patched site must actually have stopped being VEX.
	return 1 if problems else 0


def disassemble(path):
	"""(instruction start addresses, VEX start addresses) for .text.

	**A VEX start address is one that DECODES**, and until 2026-09-19 it was
	any row whose first byte is `c4` or `c5`. A `(bad)` row has three
	tab-separated fields like any other, so 180 byte sequences in Starfield
	that objdump cannot decode were being counted as surviving VEX
	instructions -- 5.9% of the frontier, in the number the README and
	`project.md` both quote.

	They are not instructions. `c5 32 00` is a two-byte VEX whose opcode is
	`00`, which is not a VEX form in any map, and one of them is a lone
	`c4`. Either a linear sweep desynchronised into data and landed there,
	which is the hazard Finding 8 named, or they are unreachable padding;
	real compiled code does not hold an invalid instruction on a path
	anything reaches.

	**They are returned rather than dropped**, because objdump is wrong
	about this image at least twice already -- `isa_guard` carries two known
	misdecodes -- so silently discarding every `(bad)` row could hide a real
	survivor. The caller reports both and the frontier counts the decoded
	ones. Finding 290.
	"""
	# **Through `resync`, as the listing is**, or the two disagree wherever
	# the linear sweep runs out of step into a function: the original
	# image reads boundaries there that the patched one, its bytes
	# rewritten, does not, and `verify` reported one lost at 0x1424bfb7b.
	# Finding 347.
	done = subprocess.Popen(["objdump", "-d", "-j", ".text", path],
	                        stdout=subprocess.PIPE, text=True, errors="replace")
	bounds, vex, undecoded = set(), set(), set()
	lines = (line for chunk in resync.resync(path, done.stdout)
	         for line in chunk.splitlines())
	for line in lines:
		parts = line.split("\t")
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
		bounds.add(address)
		encoding = parts[1].split()
		if encoding and encoding[0] in ("c4", "c5"):
			if parts[2].strip().startswith("(bad)"):
				undecoded.add(address)
			else:
				vex.add(address)
	if done.wait():
		raise SystemExit(f"objdump failed on {path}: {done.returncode}")
	return bounds, vex, undecoded


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
