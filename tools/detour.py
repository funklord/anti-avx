#!/usr/bin/env python3
"""Class C by detour: a stub section, and a jump at every site.

tools/patch.py rewrites the classes whose SSE form is no longer than the VEX
one. Class C is not one of them -- `vaddss %xmm2,%xmm1,%xmm0` is four bytes
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

import struct
import subprocess
import sys
from collections import Counter

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
import lower
import patch as inplace

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


def encode_jump(from_end, to_address):
	"""jmp rel32, whose displacement is measured from the end of the jump."""
	return bytes([JMP_REL32]) + struct.pack("<i", to_address - from_end)


def build_stub(site, encoding, vex, tail, has_immediate, stub_address):
	"""The stub body for one Class C site, placed at stub_address.

	Returns the bytes, or None if this site cannot be expressed.
	"""
	destination, source = registers_of(vex, tail)
	body = bytearray(encode_movaps(destination, source))

	operation = inplace.sse_encoding(vex, tail)
	if operation is None:
		return None

	if rip_relative(tail):
		# The displacement is relative to the end of the instruction, and
		# the instruction has moved. Recompute it against where it now
		# ends. The field sits four bytes from the end, or five when an
		# immediate follows it.
		offset = len(operation) - 4 - (1 if has_immediate else 0)
		if offset < 0:
			return None
		old = struct.unpack_from("<i", operation, offset)[0]
		target = site + len(encoding) + old
		new_end = stub_address + len(body) + len(operation)
		operation = (operation[:offset]
		             + struct.pack("<i", target - new_end)
		             + operation[offset + 4:])
	body += operation

	# Back to the instruction after the original, which is not the same as
	# the instruction after the jump unless the site was exactly five bytes.
	body += encode_jump(stub_address + len(body) + 5, site + len(encoding))
	return bytes(body)


def collect(binary, listing):
	"""(in-place patches, class C detour candidates, statistics)."""
	ranges = inplace.function_ranges(binary)
	patches, stats, _blocked = inplace.build_patches(listing, ranges)
	nds = lower.NDS_MNEMONICS

	candidates = []
	skipped = Counter()
	for address, encoding, mnemonic, operands in inplace.parse_listing(listing):
		if not encoding or encoding[0] not in (0xC4, 0xC5):
			continue
		vex = inplace.decode_vex(encoding)
		if vex is None or mnemonic in inplace.DESTINATION_IN_VVVV:
			continue
		if mnemonic not in nds:
			continue
		fields = inplace.split_operands(operands)
		registers = [o for o in fields if not o.startswith("$")]
		if len(registers) != 3 or registers[-1] == registers[-2]:
			continue			# not Class C
		if len(encoding) < 5:
			skipped["shorter than a jump"] += 1
			continue
		if not inplace.covered_by(ranges, address, len(encoding)):
			skipped["outside .pdata"] += 1
			continue
		candidates.append((address, encoding, vex,
		                   encoding[vex["length"]:],
		                   any(o.startswith("$") for o in fields)))
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


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	mode = argv[0]

	if mode == "plan":
		_patches, candidates, stats, skipped = collect(argv[1], argv[2])
		print(f"class C detour candidates {len(candidates):>10,}")
		for reason, count in skipped.most_common():
			print(f"  skipped, {reason:<24} {count:>10,}")
		print(f"\nstub bytes (estimate)     {len(candidates) * 15:>10,}")
		return 0

	if mode == "apply":
		return apply_all(argv[1], argv[2], argv[3])

	if mode == "verify":
		return verify(argv[1], argv[2])

	print(f"detour.py: unknown mode {mode!r}", file=sys.stderr)
	return 2


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
	pe = struct.unpack_from("<I", bytes(data), 0x3C)[0]
	opt = pe + 24
	alignment = struct.unpack_from("<I", bytes(data), opt + 32)[0]
	sections = struct.unpack_from("<H", bytes(data), pe + 6)[0]
	opt_size = struct.unpack_from("<H", bytes(data), pe + 20)[0]
	table = opt + opt_size
	highest = 0
	for i in range(sections):
		off = table + i * 40
		vsize, va, _rsize, _raddr = struct.unpack_from("<IIII", bytes(data), off + 8)
		highest = max(highest, va + vsize)
	image_base = struct.unpack_from("<Q", bytes(data), opt + 24)[0]
	stub_base = image_base + (highest + alignment - 1) // alignment * alignment

	blob = bytearray()
	placed = []
	for site, encoding, vex, tail, has_immediate in candidates:
		stub_address = stub_base + len(blob)
		body = build_stub(site, encoding, vex, tail, has_immediate, stub_address)
		if body is None:
			continue
		placed.append((site, encoding, stub_address))
		blob += body

	for site, encoding, stub_address in placed:
		offset = raddr + (site - vaddr)
		jump = encode_jump(site + 5, stub_address)
		pad = len(encoding) - 5
		data[offset:offset + len(encoding)] = jump + (
			inplace.NOPS[pad] if pad else b"")

	image, section_va = add_section(bytes(data), SECTION_NAME, bytes(blob),
	                                SECTION_FLAGS)
	assert section_va == stub_base - image_base, "stub section moved"
	open(output, "wb").write(image)
	print(f"apply: {len(patches):,} in-place patches, {len(placed):,} detours")
	print(f"apply: stub section .avxsse at 0x{stub_base:x}, "
	      f"{len(blob):,} bytes")
	return 0


def verify(original, patched):
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
	lost = before_bounds - after_bounds
	if lost:
		print(f"verify: FAILED -- {len(lost):,} instruction boundaries lost",
		      file=sys.stderr)
		for address in sorted(lost)[:8]:
			print(f"    0x{address:x}", file=sys.stderr)
		problems += 1
	else:
		print(f"verify: all {len(before_bounds):,} .text boundaries preserved")

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
