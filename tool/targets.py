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


def file_offset(sections, base, rva):
	"""Where an RVA's bytes are in the file, or None."""
	for _n, (vaddr, vsize, raddr, rsize) in sections.items():
		if vaddr <= base + rva < vaddr + vsize and raddr \
				and base + rva - vaddr < rsize:
			return raddr + (base + rva - vaddr)
	return None


def from_pdata(data, sections, base, text):
	"""Function starts, the handler addresses their unwind info names, and
	what the C++ handlers' data names.

	Returns `(starts, handlers, chained, cxx)`. `chained` is the begins of
	`UNW_FLAG_CHAININFO` records whose function the C++ parse vouches for:
	its root carries no handler, or one `cxx_targets` read cleanly. Those
	are in `starts` too -- they are still where something MAY arrive, for
	every caller that asks that -- and `collect` reports them as a group of
	their own so that `detour` can tell them apart. Finding 364.
	"""
	if ".pdata" not in sections:
		return set(), set(), set(), set()
	_vaddr, _vsize, raddr, rsize = sections[".pdata"]
	starts, handlers = set(), set()
	parent, carried = {}, {}
	for i in range(rsize // 12):
		begin, end, unwind = struct.unpack_from("<III", data, raddr + i * 12)
		if end <= begin:
			continue
		starts.add(base + begin)
		at = file_offset(sections, base, unwind)
		if at is None or at + 4 > len(data):
			continue
		version_flags, _prologue, codes, _frame = data[at:at + 4]
		flags = version_flags >> 3
		after = at + 4 + ((codes + 1) & ~1) * 2
		if flags & 0x4 and after + 12 <= len(data):	# CHAININFO
			parent[begin] = struct.unpack_from("<III", data, after)
		elif flags & 0x3 and after + 4 <= len(data):	# E- or UHANDLER
			# The unwind info carries an exception handler RVA after the
			# unwind codes; a funclet's handler is a branch target.
			handler = struct.unpack_from("<I", data, after)[0]
			if in_text(base + handler, text):
				handlers.add(base + handler)
			handlers |= scope_targets(data, after + 4, base, text)
			carried[begin] = (handler, after + 4)
	cxx, vouched = cxx_targets(data, sections, base, text, carried)
	chained = set()
	for begin in parent:
		root, depth = parent[begin], 0
		while root[0] in parent and depth < 32:
			root, depth = parent[root[0]], depth + 1
		if root[0] not in parent and (root[0] not in carried
		                              or root[0] in vouched):
			chained.add(base + begin)
	return starts, handlers, chained, cxx


def read_unsigned(data, at):
	"""FH4's compressed unsigned integer at `at`: (value, next offset).

	The low bits of the first byte say how long it is -- a clear bit 0 for
	one byte, `01` for two, `011` for three, `0111` for four, `1111` for a
	whole dword after the tag byte -- and the value is the rest.
	"""
	tag = data[at]
	if tag & 1 == 0:
		return tag >> 1, at + 1
	if tag & 3 == 1:
		return struct.unpack_from("<H", data, at)[0] >> 2, at + 2
	if tag & 7 == 3:
		return (struct.unpack_from("<I", data, at)[0] & 0xFFFFFF) >> 3, at + 3
	if tag & 15 == 7:
		return struct.unpack_from("<I", data, at)[0] >> 4, at + 4
	return struct.unpack_from("<I", data, at + 1)[0], at + 5


def read_int(data, at):
	return struct.unpack_from("<i", data, at)[0], at + 4


def funcinfo3(data, sections, base, at):
	"""RVAs a `FuncInfo` names: unwind actions and catch funclets.

	The 32-bit-era layout, `__CxxFrameHandler3`'s, recognised by its magic.
	A catch funclet here returns its continuation in `rax`, so the
	continuation is named by code rather than by data.
	"""
	_magic, states, unwind, tries, try_map = struct.unpack_from(
		"<IiIiI", data, at)
	out = set()
	if unwind:
		where = file_offset(sections, base, unwind)
		for i in range(states):
			out.add(struct.unpack_from("<iI", data, where + 8 * i)[1])
	if tries:
		where = file_offset(sections, base, try_map)
		for i in range(tries):
			catches, array = struct.unpack_from("<iI", data,
			                                    where + 20 * i + 12)
			table = file_offset(sections, base, array)
			for j in range(catches):
				out.add(struct.unpack_from("<i", data,
				                           table + 20 * j + 12)[0])
	return out - {0}


def funcinfo4(data, sections, base, at, begin):
	"""RVAs a `FuncInfo4` names: unwind actions, catch funclets, and the
	continuations a catch resumes at.

	`__CxxFrameHandler4`'s compressed form. **A continuation is where
	control arrives after a catch, and nothing but this data names it**:
	measured on Starfield, every catch funclet that returns gives back 0 in
	`rax`, which tells the runtime to read the address from here. One
	stored function-relative is relative to the record's own `begin`.
	"""
	header = data[at]
	at += 1
	if header & 0x04:		# BBT flags
		_bbt, at = read_unsigned(data, at)
	unwind = try_map = None
	if header & 0x08:
		unwind, at = read_int(data, at)
	if header & 0x10:
		try_map, at = read_int(data, at)
	out = set()
	if unwind:
		where = file_offset(sections, base, unwind)
		count, where = read_unsigned(data, where)
		for _ in range(count):
			kind, where = read_unsigned(data, where)
			if kind & 3 in (1, 2):		# a destructor and its object
				action, where = read_int(data, where)
				_object, where = read_unsigned(data, where)
				out.add(action)
			elif kind & 3 == 3:		# an unwind funclet
				action, where = read_int(data, where)
				out.add(action)
	if try_map:
		where = file_offset(sections, base, try_map)
		count, where = read_unsigned(data, where)
		for _ in range(count):
			for _field in range(3):		# try low, try high, catch high
				_value, where = read_unsigned(data, where)
			array, where = read_int(data, where)
			table = file_offset(sections, base, array)
			catches, table = read_unsigned(data, table)
			for _ in range(catches):
				kind = data[table]
				table += 1
				if kind & 0x01:
					_adjectives, table = read_unsigned(data, table)
				if kind & 0x02:
					_type, table = read_int(data, table)
				if kind & 0x04:
					_object, table = read_unsigned(data, table)
				funclet, table = read_int(data, table)
				out.add(funclet)
				for _ in range((kind >> 4) & 3):
					if kind & 0x08:
						resume, table = read_int(data, table)
					else:
						resume, table = read_unsigned(data, table)
						resume += begin
					out.add(resume)
	return out


def cxx_targets(data, sections, base, text, carried):
	"""(addresses, vouched begins) from every C++ handler's data.

	**A handler routine counts as C++ only if every one of its functions
	parses**, and every address read lands in `.text`. Nothing here knows
	the routines' names, and the data after a handler RVA means something
	else for each: `__GSHandlerCheck`'s is a cookie offset, which read as a
	`FuncInfo4` happened to parse for 8 of its 264 functions and produced
	2,732 addresses outside the image. Judged per routine, the C++ ones
	parse 85,593 of 85,593 and the others are refused whole. Measured on
	Starfield: 489 catch funclets -- the count Finding 112 enumerated by
	other means, all of them `.pdata` primaries -- and 18 continuations,
	each an instruction start. Finding 364.
	"""
	by_routine = {}
	for begin, (handler, at) in carried.items():
		by_routine.setdefault(handler, []).append((begin, at))
	found, vouched = set(), set()
	for handler, users in by_routine.items():
		names, ok = set(), True
		for begin, at in users:
			try:
				info = struct.unpack_from("<I", data, at)[0]
				where = file_offset(sections, base, info)
				if where is None or in_text(base + info, text):
					ok = False
					break
				if struct.unpack_from("<I", data, where)[0] & ~3 \
						== 0x19930520:
					read = funcinfo3(data, sections, base, where)
				else:
					read = funcinfo4(data, sections, base, where, begin)
			except (struct.error, TypeError, IndexError):
				ok = False
				break
			if not all(in_text(base + rva, text) for rva in read):
				ok = False
				break
			names |= read
		if ok:
			found |= {base + rva for rva in names}
			vouched |= {begin for begin, _at in users}
	return found, vouched


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


def collect(path):
	data = open(path, "rb").read()
	sections, base, opt = sections_of(data)
	text = sections[".text"]

	reloc = from_reloc(data, sections, base, opt, text)
	starts, handlers, chained, cxx = from_pdata(data, sections, base, text)
	# **No switch tables here any more; see `detour.switch_targets`.**
	# `from_switch_tables` looked for runs of `table + value`, which is the
	# MSVC x86 form, and this x64 binary holds RVAs. It found 14,789
	# addresses of which **3** were real switch targets: they land on an
	# instruction boundary 24.67% of the time against a 27.09% baseline,
	# which is chance. Over-blocking is safe and only costs sites, so the
	# 14,737 that were noise cost sites for nothing.
	#
	# It is removed rather than corrected because the correction needs a
	# disassembly this module does not have: the dispatch is read --
	# a scaled load off `__ImageBase`, an `add` of the base, an indirect
	# `jmp` -- and the table walked until an entry stops naming an
	# instruction. That lives in `detour`, which has the listing, and all
	# 3 of the real targets are in its set. Findings 174 and 177.
	return {
		"reloc (absolute pointers)": reloc,
		"pdata (function starts)": starts - chained,
		"pdata (chained fragments)": chained,
		"xdata (EH handlers)": handlers,
		"xdata (C++ EH)": cxx,
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
