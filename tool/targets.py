#!/usr/bin/env python3
"""Enumerate every address something can branch to.

A detour that widens its window past the instruction it replaces needs to
know that nothing enters the window part-way through. Direct branches are
in the disassembly. Indirect ones are not, and "cannot enumerate them" is
what stopped tool/detour.py at the four-byte sites.

They can mostly be enumerated, from four sources, and the interesting part
is which of them is sound:

  .reloc   Every absolute address stored anywhere in the image has a base
           relocation, because the loader has to fix it up if the image
           moves. So vtables, function pointers and TLS callbacks are all
           here. This is COMPLETE for absolute targets -- not a heuristic --
           and it is the reason the problem is tractable at all.

           It does NOT cover exception handling on x64, and this used to say
           it did. Every EH structure there is image-relative: UNWIND_INFO's
           handler slot, FuncInfo's dispOfHandler, and the scope table's
           Handler and JumpTarget are all RVAs, and an RVA needs no fixup
           when the image moves, so the loader records nothing for one.
           Measured on Starfield: of the 29 handler and scope addresses
           recovered from .xdata below, .reloc names zero. The claim was
           true of a 32-bit image and was carried across. See project.md,
           Finding 112.

  .pdata   Every function with unwind data, which is every non-leaf
           function. Complete for what it covers.

           It is also the ONLY thing covering a C++ catch funclet, which is
           worth knowing before anyone trims it. 85,139 of this binary's
           functions name __CxxFrameHandler4, whose FuncInfo holds the
           funclet addresses, and nothing here parses that -- see
           scope_targets. Of the 489 catch funclets in the image, 488 are in
           the set for this reason and no other: no relocation names them,
           no branch does, no lea does. So trimming this group is not the
           local change it looks like.

  .xdata   Exception handler and funclet addresses, stored as RVAs and
           reachable from .pdata's unwind information.

  tables   Switch tables. These are the hard ones: MSVC x64 stores entries
           as offsets relative to the table's own address, so **no
           relocation records them** and nothing in the file marks them as
           addresses. They are found here by their code pattern -- a
           `lea reg,[rip+table]` feeding an indexed load and an indirect
           jump -- and by scanning read-only data for runs of values that
           are self-consistently .text offsets.

The last source is a heuristic, and that is stated plainly rather than
buried: a switch table this misses is a switch table whose targets are not
in the set. What makes that survivable is how the set is used -- a window is
widened only when no interior address is in it, so a *missing* target is the
dangerous direction and the scan is deliberately over-inclusive.

  dump   <binary>          counts per source
  list   <binary>          every target, one per line
"""

import struct
import sys
from collections import Counter


def sections_of(data):
	"""{name: (virtual address, size, file offset, raw size)} plus the base."""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	count = struct.unpack_from("<H", data, pe + 6)[0]
	opt_size = struct.unpack_from("<H", data, pe + 20)[0]
	opt = pe + 24
	base = struct.unpack_from("<Q", data, opt + 24)[0]
	table = opt + opt_size
	out = {}
	for i in range(count):
		off = table + i * 40
		name = data[off:off + 8].rstrip(b"\0").decode("latin1")
		vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off + 8)
		out[name] = (base + vaddr, max(vsize, rsize), raddr, rsize)
	return out, base, opt


def data_directory(data, opt, index):
	return struct.unpack_from("<II", data, opt + 112 + index * 8)


def in_text(address, text):
	start, size, _raddr, _rsize = text
	return start <= address < start + size


def from_reloc(data, sections, base, opt, text):
	"""Absolute addresses the loader would fix up. Complete, not a guess."""
	rva, size = data_directory(data, opt, 5)
	if not rva:
		return set()
	# Find the file offset of the relocation directory.
	offset = None
	for _name, (vaddr, vsize, raddr, _rsize) in sections.items():
		if vaddr <= base + rva < vaddr + vsize:
			offset = raddr + (base + rva - vaddr)
	if offset is None:
		return set()

	targets = set()
	end = offset + size
	while offset < end - 8:
		page_rva, block_size = struct.unpack_from("<II", data, offset)
		if block_size < 8 or offset + block_size > end:
			break
		for i in range((block_size - 8) // 2):
			entry = struct.unpack_from("<H", data, offset + 8 + i * 2)[0]
			kind, low = entry >> 12, entry & 0xFFF
			if kind != 10:			# IMAGE_REL_BASED_DIR64
				continue
			where = base + page_rva + low
			# Read the pointer that lives there.
			for _n, (vaddr, vsize, raddr, rsize) in sections.items():
				if vaddr <= where < vaddr + vsize and raddr:
					file_at = raddr + (where - vaddr)
					if file_at + 8 <= len(data):
						value = struct.unpack_from("<Q", data, file_at)[0]
						if in_text(value, text):
							targets.add(value)
					break
		offset += block_size
	return targets


def from_pdata(data, sections, base, text):
	"""Function starts, and the handler addresses their unwind info names."""
	if ".pdata" not in sections:
		return set(), set()
	_vaddr, _vsize, raddr, rsize = sections[".pdata"]
	starts, handlers = set(), set()
	for i in range(rsize // 12):
		begin, end, unwind = struct.unpack_from("<III", data, raddr + i * 12)
		if end <= begin:
			continue
		starts.add(base + begin)
		# The unwind info may carry an exception handler RVA after the
		# unwind codes; a funclet's handler is a branch target.
		for _n, (vaddr, vsize, xraddr, _xrsize) in sections.items():
			if vaddr <= base + unwind < vaddr + vsize and xraddr:
				at = xraddr + (base + unwind - vaddr)
				if at + 4 > len(data):
					break
				version_flags, _prologue, codes, _frame = data[at:at + 4]
				flags = version_flags >> 3
				if flags & 0x3:			# EHANDLER or UHANDLER
					after = at + 4 + ((codes + 1) & ~1) * 2
					if after + 4 <= len(data):
						handler = base + struct.unpack_from("<I", data, after)[0]
						if in_text(handler, text):
							handlers.add(handler)
						handlers |= scope_targets(data, after + 4, base, text)
				break
	return starts, handlers


def scope_targets(data, at, base, text):
	"""Addresses named by a `__C_specific_handler` SCOPE_TABLE.

	What follows the handler RVA depends on which handler it is, and for
	MSVC's `__try`/`__except` it is:

	    DWORD Count
	    { DWORD Begin, End, Handler, JumpTarget } * Count

	`JumpTarget` is where execution resumes once the `__except` body has run
	and `Handler` is a filter funclet. **Both are code the unwinder enters,
	no branch instruction names either, and no relocation records them** --
	so without this a window is free to swallow one, which is the hazard
	Finding 16 exists to prevent for switch tables.

	Measured on Starfield: 23 targets, 8 of which nothing else knew about,
	and none swallowed. A latent hazard rather than a live bug, closed
	because it costs nothing to close.

	**Parsing is permissive and validated rather than trusted.** A C++ EH
	function carries a `FuncInfo` here instead, which this will read as
	nonsense -- so every field is checked to be a plausible `.text` address
	before any of it is believed. Getting that wrong in the generous
	direction costs a refused site; getting it wrong in the other direction
	costs correctness.

	**What refusing `FuncInfo` costs is measured now, and it is not
	nothing.** The 21 functions using `__C_specific_handler` are the ones
	this reads; 85,593 use a C++ handler and are skipped, and the 489 catch
	funclets they hold are then known to the rewriter only because each is a
	`.pdata` function start. Parsing `FuncInfo` and its compressed
	`FuncInfo4` form would make that a redundancy rather than a sole
	dependency, and it is the thing to build before anyone reconsiders the
	`.pdata` group. Finding 112.
	"""
	if at + 4 > len(data):
		return set()
	count = struct.unpack_from("<I", data, at)[0]
	if not 1 <= count <= 64 or at + 4 + count * 16 > len(data):
		return set()
	found = set()
	for i in range(count):
		begin, end, handler, jump = struct.unpack_from("<IIII", data,
		                                              at + 4 + i * 16)
		if not (0 < begin < end and in_text(base + begin, text)
		        and in_text(base + end, text)):
			return set()		# not a scope table; believe none of it
		if handler not in (0, 1) and not in_text(base + handler, text):
			return set()
		if jump and not in_text(base + jump, text):
			return set()
		if jump:
			found.add(base + jump)
		if handler not in (0, 1):
			found.add(base + handler)
	return found


def from_switch_tables(data, sections, base, text):
	"""Switch tables, found by self-consistency rather than by relocation.

	An MSVC x64 switch table holds `target - table`, so a run of entries at
	address T is a table when T + entry lands in .text for several entries
	in a row. Nothing in the file says so; this is inference, and it is the
	one source here that can be incomplete.
	"""
	targets = set()
	tables = 0
	for name in (".rdata", "_RDATA", ".text"):
		if name not in sections:
			continue
		vaddr, _vsize, raddr, rsize = sections[name]
		if not raddr:
			continue
		blob = data[raddr:raddr + rsize]
		i = 0
		limit = len(blob) - 4
		while i < limit:
			table_address = vaddr + i
			run = []
			j = i
			while j < limit:
				value = struct.unpack_from("<i", blob, j)[0]
				candidate = table_address + value
				if not in_text(candidate, text):
					break
				run.append(candidate)
				j += 4
			# Four consecutive plausible entries is a strong signal; two is
			# noise in a binary this size.
			if len(run) >= 4:
				targets.update(run)
				tables += 1
				i = j
			else:
				i += 4
	return targets, tables


def collect(path):
	data = open(path, "rb").read()
	sections, base, opt = sections_of(data)
	text = sections[".text"]

	reloc = from_reloc(data, sections, base, opt, text)
	starts, handlers = from_pdata(data, sections, base, text)
	tables, table_count = from_switch_tables(data, sections, base, text)
	return {
		"reloc (absolute pointers)": reloc,
		"pdata (function starts)": starts,
		"xdata (EH handlers)": handlers,
		f"switch tables ({table_count:,} found)": tables,
	}


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	mode, path = argv[0], argv[1]
	groups = collect(path)
	union = set()
	for name, values in groups.items():
		union |= values
	if mode == "dump":
		for name, values in groups.items():
			print(f"{name:<34}{len(values):>12,}")
		print(f"{'union':<34}{len(union):>12,}")
		return 0
	if mode == "list":
		for address in sorted(union):
			print(f"{address:x}")
		return 0
	print(f"targets.py: unknown mode {mode!r}", file=sys.stderr)
	return 2


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
