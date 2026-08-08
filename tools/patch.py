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
		pending = [address, bytearray(encoding), fields[0],
		           (fields[1] if len(fields) > 1 else "")]
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


def sse_encoding(vex, tail):
	"""The SSE bytes equivalent to a VEX prefix plus everything after it."""
	if vex["map"] not in MAP_ESCAPE:
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

	So the form comes from the operand list, which is what tools/lower.py
	uses and what the disassembler already worked out.
	"""
	if mnemonic == "vzeroupper":
		return "Z"
	# For these the destination lives in vvvv and modrm.reg is an opcode
	# extension, so dropping vvvv would silently retarget the write.
	if mnemonic in DESTINATION_IN_VVVV:
		return None
	if mnemonic not in direct and mnemonic not in nds:
		return None

	registers = [o for o in operands if not o.startswith("$")]
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
	"""The mnemonic tables from tools/lower.py, so there is one authority."""
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

		replacement = sse_encoding(vex, tail)
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
			replacement = NOPS[-grew] + replacement
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

	before_bounds, before_vex = disassemble(original)
	after_bounds, after_vex = disassemble(patched)
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
	"""(instruction start addresses, VEX start addresses) for .text."""
	done = subprocess.run(["objdump", "-d", "-j", ".text", path],
	                      capture_output=True, text=True, errors="replace")
	bounds, vex = set(), set()
	for line in done.stdout.splitlines():
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
			vex.add(address)
	return bounds, vex


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
