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


def encode_jump(from_end, to_address):
	"""jmp rel32, whose displacement is measured from the end of the jump."""
	return bytes([JMP_REL32]) + struct.pack("<i", to_address - from_end)


def lower_vex(address, encoding, operands, mnemonic, at):
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
	if (mnemonic not in lower.DIRECT_MNEMONICS
			and mnemonic not in lower.NDS_MNEMONICS):
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
		operation = (operation[:offset]
		             + struct.pack("<i", target - new_end)
		             + operation[offset + 4:])
	body += operation
	return bytes(body)


def build_stub(site, encoding, operands, mnemonic, window, displaced,
               stub_address):
	"""The stub body for one site, placed at stub_address."""
	body = bytearray()
	lowered = lower_vex(site, encoding, operands, mnemonic, stub_address)
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
	ranges = inplace.function_ranges(binary)
	patches, stats, _blocked = inplace.build_patches(listing, ranges)
	nds = lower.NDS_MNEMONICS

	# Everything anything can branch to. A window may not contain one of
	# these anywhere but at its first byte.
	groups = target_set.collect(binary)
	blocked = set()
	for values in groups.values():
		blocked |= values
	instructions = list(parse_with_comments(listing))
	for i, (address, _e, mnemonic, operands, _c) in enumerate(instructions):
		if mnemonic.startswith(("j", "call", "loop")) and operands:
			first = operands.split()[0]
			if first.startswith("0x"):
				try:
					blocked.add(int(first, 16))
				except ValueError:
					pass

	candidates = []
	skipped = Counter()
	for index, (address, encoding, mnemonic, operands,
	            _comment) in enumerate(instructions):
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
		has_immediate = any(o.startswith("$") for o in fields)
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
		                   displaced))
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
		return verify(argv[1], argv[2], argv[3] if len(argv) > 3 else None)

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
	# Windows must not overlap. Two Class C sites can sit next to each
	# other, and then the first one's widened window swallows the second --
	# which would otherwise be patched a second time, on top of the jump
	# already written there. Taking them in address order and refusing any
	# site that starts inside a committed window is the whole fix.
	refused = overlapped = 0
	committed_to = 0
	for site, encoding, operands, mnemonic, window, displaced in sorted(candidates):
		if site < committed_to:
			overlapped += 1
			continue
		stub_address = stub_base + len(blob)
		body = build_stub(site, encoding, operands, mnemonic, window,
		                  displaced, stub_address)
		if body is None:
			refused += 1
			continue
		placed.append((site, window, stub_address))
		committed_to = site + window
		blob += body

	for site, window, stub_address in placed:
		offset = raddr + (site - vaddr)
		jump = encode_jump(site + 5, stub_address)
		pad = window - 5
		data[offset:offset + window] = jump + inplace.nop_padding(pad)

	image, section_va = add_section(bytes(data), SECTION_NAME, bytes(blob),
	                                SECTION_FLAGS)
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
	swallowed = set()
	committed_to = 0
	for site, _encoding, _operands, _mnemonic, window, displaced in sorted(candidates):
		if site < committed_to:
			continue			# same overlap rule apply() uses
		committed_to = site + window
		for address, _moved, _comment, _ops, _mn in displaced:
			swallowed.add(address)
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
