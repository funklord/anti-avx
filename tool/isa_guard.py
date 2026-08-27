#!/usr/bin/env python3
"""The feature tests must survive the rewrite, byte for byte.

179 EVEX instructions in this image are unreachable on a pre-AVX host only
because a runtime CPUID/XGETBV test says so. Nothing checked that the
rewrite left that test alone, and the failure it would cause does not look
like a rewriting fault: the program selects a path its CPU cannot run and
dies somewhere else entirely. Finding 5 named the risk and left it open.

**The invariant is narrow enough to be exact.** Take every `cpuid` and
`xgetbv` in `.text`, take the RUNTIME_FUNCTION that contains each, and
compare those functions between the two images instruction by instruction.
Inside such a function, **only a VEX-encoded instruction may differ.**
Nothing else -- not the leaf number in `eax`, not the AND mask, not the CMP
immediate, not the SETcc, not the Jcc, and not an instruction a widened
window swallowed on its way past. Any of those differing is a dispatcher
that no longer decides what it decided.

That rule is not a guess about what the rewriter does; it is what the
rewriter's own guarantee reduces to here. A same-length lowering changes
the VEX site and nothing else. A detour writes a five-byte jump over a site
at least five bytes long, so it changes that site and nothing else. A
*widened* window is the one shape that reaches past its site, and reaching
past a site inside a feature test is exactly the thing this refuses.

Measured on the shipped pair: ten functions hold the 34 sites, 1,346
instructions between them, 24 of which differ, and every one of the 24 is
VEX.

Two further rules, and one of them is about this check rather than about
the image:

  * **Every EVEX instruction in `.text` must be byte-identical.** The
    rewriter's job at 512 bits is to recognise EVEX and leave it alone.
  * **The comparison is run against a deliberately corrupted copy first**,
    and must reject it. A comparison that inspects the wrong offsets, or an
    empty span, reports success exactly as loudly as one that inspected the
    dispatcher -- so the run proves it can fail before it is allowed to
    pass.

Usage:

    isa_guard.py <original> <patched> <listing>

or from `detour.py verify`, which already holds all three.
"""

import bisect
import hashlib
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour
# `cpuid` and `xgetbv`, by encoding. Matching bytes AND mnemonic means a
# disassembler that renames one cannot hide a site, and a byte pattern
# sitting inside some other instruction cannot invent one.
FEATURE_OPCODES = {b"\x0f\xa2": "cpuid", b"\x0f\x01\xd0": "xgetbv"}
# What the shipped image holds. A count that has moved means the binary
# gained or lost a feature test, and the manifest below is describing
# something else -- which is a finding, not a pass.
EXPECTED_SITES = 34
# Instructions the listing decodes from an EVEX prefix: 179 real ones in
# the two AVX-512 kernels, plus the two Finding 5 names as misdecodes --
# 0x142d511ac and 0x14319e280, both sitting in `(bad)` runs after a
# `ret`/`nop`. A further 106 rows open with 0x62 and do not decode at all;
# those are data and are deliberately not asserted on, since a byte inside
# a `(bad)` run carries no claim about what it is.
EXPECTED_EVEX = 181
EVEX_MISDECODES = (0x142d511ac, 0x14319e280)
# The instruction that must be corrupted for the control, and the byte in
# it to corrupt: the `jae` at the end of the OSXSAVE test in the AVX-512
# dispatcher. Chosen because flipping it is precisely the fault this check
# exists to catch -- the branch that keeps 179 instructions unexecuted.
CONTROL_SITE = 0x1434ddd88

# **Consumers are named, because they cannot be discovered.** A function
# that reads a feature word and picks a code path holds no `cpuid` of its
# own, so the sweep above cannot see it. These two are the whole chain
# between the AVX-512 feature bit and the AVX-512 kernels: the second
# builds the function-pointer table from the struct the dispatcher filled,
# and is the only place the addresses of the EVEX bodies are selected; the
# first calls it and jumps through the table.
#
# The digest is of the ORIGINAL's bytes and its only job is to say when
# this list has gone stale. A mismatch means the manifest was written
# against a different image, which is worth a failure rather than a
# silently narrower check.
CONSUMERS = [
	(0x1434d3cf0, 0x1434d3d44, "7b2849d3dc1ae918",
	 "calls the table builder and jumps through the table"),
	(0x1434d3d50, 0x1434d3fd4, "ff80c2eeef777e11",
	 "builds the function-pointer table from the feature struct"),
]

LISTING_LINE = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+?)\s*(?:\t(.*))?$")


def listing_instructions(path):
	"""Yield (address, encoding, text) from an objdump listing.

	objdump wraps an encoding longer than seven bytes onto a continuation
	line carrying an address and bytes but no mnemonic, and those bytes are
	part of the instruction. Reading only the first line makes an eight-byte
	instruction look like seven, which is how a comparison over "the
	instruction" ends up comparing part of it.
	"""
	pending = None
	for line in open(path, "r", errors="replace"):
		found = LISTING_LINE.match(line.rstrip("\n"))
		if not found:
			continue
		address = int(found.group(1), 16)
		try:
			encoding = bytes.fromhex(found.group(2).replace(" ", ""))
		except ValueError:
			continue
		text = found.group(3)
		if text is None and pending and address == pending[0] + len(pending[1]):
			pending = (pending[0], pending[1] + encoding, pending[2])
			continue
		if pending:
			yield pending
		pending = (address, encoding, text)
	if pending:
		yield pending


def image_base(data):
	"""Where the image says it loads. Read, not assumed.

	The manifest below is Starfield's and its addresses are absolute, so a
	hardcoded base would agree with it by construction and disagree with
	every other binary silently.
	"""
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	return struct.unpack_from("<Q", data, pe + 24 + 24)[0]


def text_window(data):
	"""(virtual address, file offset, size) of .text, or raise."""
	found = detour.section_named(data, b".text")
	if found is None:
		raise SystemExit("isa_guard: no .text section")
	vaddr, vsize, raddr, rsize = found
	return image_base(data) + vaddr, raddr, min(vsize, rsize)


def enclosing(pdata, begins, address, base):
	"""The RUNTIME_FUNCTION containing a virtual address, or None."""
	rva = address - base
	index = bisect.bisect_right(begins, rva) - 1
	if index < 0:
		return None
	begin, end, _unwind = pdata[index]
	return (begin, end) if begin <= rva < end else None


def scan(original, listing, base):
	"""One streaming pass over the listing.

	Returns the feature sites, the EVEX instructions, and every instruction
	that lies inside a guard span -- a guard span being the RUNTIME_FUNCTION
	holding a feature site. The spans are not known until the sites are, so
	this keeps the instructions of every function that turns out to hold one
	by remembering the function currently being walked and dropping it again
	the moment it ends without a site in it.
	"""
	pdata = detour.existing_pdata(original)
	begins = [begin for begin, _end, _unwind in pdata]
	sites, evex, spans = [], [], {}
	current, held, has_site = None, [], False
	for address, encoding, text in listing_instructions(listing):
		if text is None:
			# Bytes objdump could not decode. They are still bytes of the
			# function and are compared as such.
			text = ""
		if current is None or not (current[0] <= address < current[1]):
			if has_site:
				spans[current] = held
			found = enclosing(pdata, begins, address, base)
			current = ((base + found[0], base + found[1])
			           if found else None)
			held, has_site = [], False
		if current is not None:
			held.append((address, encoding, text))
		if encoding[:1] == b"\x62" and text and not text.startswith("(bad)"):
			evex.append((address, encoding, text))
		name = FEATURE_OPCODES.get(encoding[:2]) or \
			FEATURE_OPCODES.get(encoding[:3])
		if name and text and text.split()[:1] == [name]:
			sites.append((address, name, current))
			has_site = True
	if has_site:
		spans[current] = held
	return sites, evex, spans


def differing(original, patched, raddr, vaddr, instructions):
	"""Instructions whose bytes moved, those that are not VEX, and strays.

	`illegal` is the failure: everything in `moved` that is VEX is a
	lowering the rewriter is entitled to make, and anything else is a byte
	of a feature test that changed.

	`stray` closes the way this whole comparison could pass having compared
	nothing. Hand it a listing of the PATCHED image instead of the original
	and every encoding matches the patched bytes, so `moved` comes back
	empty and the run is green for the worst possible reason. Each
	instruction is therefore checked against the ORIGINAL's bytes first, and
	a listing that is not the original's own is a failure rather than a
	silent pass.
	"""
	moved, illegal, stray = [], [], []
	for address, encoding, text in instructions:
		at = raddr + (address - vaddr)
		if original[at:at + len(encoding)] != encoding:
			stray.append((address, encoding, text))
			continue
		if patched[at:at + len(encoding)] == encoding:
			continue
		moved.append((address, encoding, text))
		if encoding[:1] not in (b"\xc4", b"\xc5"):
			illegal.append((address, encoding, text))
	return moved, illegal, stray


def check(original_path, patched_path, listing):
	"""Returns the number of problems; prints what it inspected either way."""
	original = open(original_path, "rb").read()
	patched = open(patched_path, "rb").read()
	base = image_base(original)
	vaddr, raddr, _size = text_window(original)
	problems = 0

	sites, evex, spans = scan(original, listing, base)

	# **The manifest below is one image's, and every count in it is that
	# image's.** On any other binary the generic invariant still holds --
	# only a VEX instruction may differ inside a function holding a feature
	# test -- but the counts, the named consumers and the control site are
	# meaningless. Recognise the image by its consumers' digests and say so,
	# rather than either failing every other target or checking less without
	# mentioning it.
	known = all(hashlib.sha1(
		original[raddr + (low - vaddr):raddr + (low - vaddr) + (high - low)]
	).hexdigest()[:16] == digest for low, high, digest, _why in CONSUMERS)
	if not known:
		print("isa_guard: this is not the image the manifest was measured "
		      "against -- the counts, the named consumers and the control "
		      "site are skipped; the span comparison below is not")
	if not sites:
		print("isa_guard: no cpuid or xgetbv in .text, so there is no "
		      "dispatcher to guard")
		return problems

	# **The vacuous-pass gate, and it is first for a reason.** Everything
	# below reports success over an empty list exactly as loudly as over a
	# full one, so the list is checked for being the list before it is used.
	if known and len(sites) != EXPECTED_SITES:
		print(f"isa_guard: FAILED -- {len(sites)} cpuid/xgetbv sites, "
		      f"expected {EXPECTED_SITES}; the image or the listing is not "
		      f"the one this was measured against", file=sys.stderr)
		problems += 1
	if known and len(evex) != EXPECTED_EVEX:
		print(f"isa_guard: FAILED -- {len(evex)} EVEX-prefixed instructions "
		      f"decode, expected {EXPECTED_EVEX} (179 real, plus the two "
		      f"misdecodes at " +
		      ", ".join(f"0x{a:x}" for a in EVEX_MISDECODES) + ")",
		      file=sys.stderr)
		problems += 1

	# Every site re-read from the original's own bytes. Without this the
	# whole comparison could be reading the wrong file offsets and finding
	# them identical in both images, which is a pass that inspected nothing.
	for address, name, _span in sites:
		encoding = next(key for key, value in FEATURE_OPCODES.items()
		                if value == name)
		at = raddr + (address - vaddr)
		if original[at:at + len(encoding)] != encoding:
			print(f"isa_guard: FAILED -- 0x{address:x} does not hold "
			      f"{name} in the original", file=sys.stderr)
			problems += 1
	# A site outside every RUNTIME_FUNCTION has no span to compare, and a
	# check that quietly skips it is the case this file exists to avoid.
	orphans = [address for address, _name, span in sites if span is None]
	for address in orphans:
		print(f"isa_guard: FAILED -- 0x{address:x} is in no RUNTIME_FUNCTION, "
		      f"so it has no guard span", file=sys.stderr)
		problems += 1

	inspected = sum(len(rows) for rows in spans.values())
	print(f"isa_guard: {len(sites)} cpuid/xgetbv sites in {len(spans)} "
	      f"functions, {inspected:,} instructions compared")

	moved_total, illegal_total, stray_total = 0, 0, 0
	for (low, high), rows in sorted(spans.items()):
		moved, illegal, stray = differing(original, patched, raddr, vaddr,
		                                  rows)
		moved_total += len(moved)
		illegal_total += len(illegal)
		stray_total += len(stray)
		for address, encoding, text in stray[:4]:
			print(f"isa_guard: FAILED -- 0x{address:x} does not hold "
			      f"{encoding.hex(' ')} in the original; this listing is not "
			      f"the original's", file=sys.stderr)
		for address, encoding, text in illegal:
			at = raddr + (address - vaddr)
			print(f"isa_guard: FAILED -- 0x{address:x} in the feature test "
			      f"at 0x{low:x} changed and is not a VEX site",
			      file=sys.stderr)
			print(f"    was {encoding.hex(' ')}  {text}", file=sys.stderr)
			print(f"    now {patched[at:at + len(encoding)].hex(' ')}",
			      file=sys.stderr)
	problems += illegal_total + stray_total
	if not illegal_total and not stray_total:
		print(f"isa_guard: {moved_total} instruction(s) differ inside those "
		      f"functions, every one VEX-encoded")

	# The 512-bit half. EVEX must come through untouched.
	changed = [row for row in evex
	           if patched[raddr + (row[0] - vaddr):
	                      raddr + (row[0] - vaddr) + len(row[1])] != row[1]]
	for address, encoding, text in changed[:8]:
		print(f"isa_guard: FAILED -- EVEX at 0x{address:x} changed: {text}",
		      file=sys.stderr)
	problems += len(changed)
	if not changed:
		print(f"isa_guard: all {len(evex)} EVEX-prefixed instructions "
		      f"byte-identical ({len(evex) - len(EVEX_MISDECODES)} real, "
		      f"{len(EVEX_MISDECODES)} known misdecodes)")

	# The consumers, which hold no cpuid and so cannot be discovered.
	for low, high, digest, why in (CONSUMERS if known else []):
		at = raddr + (low - vaddr)
		body = original[at:at + (high - low)]
		if hashlib.sha1(body).hexdigest()[:16] != digest:
			print(f"isa_guard: FAILED -- the consumer manifest is stale: "
			      f"0x{low:x} does not match its recorded digest",
			      file=sys.stderr)
			problems += 1
			continue
		if patched[at:at + (high - low)] != body:
			print(f"isa_guard: FAILED -- consumer 0x{low:x}-0x{high:x} "
			      f"changed ({why})", file=sys.stderr)
			problems += 1
	if known:
		print(f"isa_guard: {len(CONSUMERS)} named consumer(s) checked, "
		      f"{sum(high - low for low, high, _d, _w in CONSUMERS)} bytes")

	# **The control.** Corrupt one byte of one dispatcher in a copy of the
	# patched image and require the comparison to reject it. A green result
	# above means nothing until this has been red.
	site = CONTROL_SITE if known else min(address for address, _n, _s in sites)
	span = next((key for key in spans if key[0] <= site < key[1]), None)
	if span is None:
		print(f"isa_guard: FAILED -- the control site 0x{site:x} is "
		      f"in no guard span, so the check is unproven", file=sys.stderr)
		problems += 1
	else:
		at = raddr + (site - vaddr)
		spoiled = bytearray(patched)
		spoiled[at] ^= 0x01
		_moved, illegal, _stray = differing(original, bytes(spoiled), raddr,
		                                    vaddr, spans[span])
		if site not in [address for address, _e, _t in illegal]:
			print(f"isa_guard: FAILED -- the control was not rejected; this "
			      f"check cannot detect a perturbed dispatcher and its pass "
			      f"means nothing", file=sys.stderr)
			problems += 1
		else:
			print(f"isa_guard: control passed -- one flipped byte at "
			      f"0x{site:x} is rejected, so the comparison "
			      f"discriminates")
	return problems


def main(argv):
	if len(argv) != 3:
		print(__doc__.strip())
		return 0
	return 1 if check(argv[0], argv[1], argv[2]) else 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
