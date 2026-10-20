#!/usr/bin/env python3
"""The code `.pdata` does not describe, and how to know it is code.

`.pdata` is the rewriter's code oracle: a run of bytes it covers is certainly
code, so a detour written there certainly lands on an instruction boundary.
Everything else is refused, and that refusal became the single largest reason
sites survived -- 16,256 of the 23,923 left, more than twice every other
reason combined.

`patch.function_ranges` already names the cause: the x64 ABI lets a function
that neither allocates stack nor calls anything omit its unwind data, so a
leaf function legitimately has no `.pdata` entry. What it could not say was
how much of the refused set was that, and how much was objdump walking into
data -- and those need opposite work. A leaf function's VEX must be lowered;
a constant pool that happens to decode as VEX must be left alone, because
"patching" it corrupts the data.

Measured, on 3,006 regions outside `.pdata` holding 17,604 VEX sites:

    called, and ends in a transfer     1,418 regions    6,534 sites
    uncalled, ends in a transfer       1,524 regions   10,622 sites
    called, but runs off the end          40 regions      120 sites
    contains (bad) -- not code            20 regions      315 sites
    uncalled, runs off the end             4 regions       13 sites

The "uncalled" majority was an artifact of asking the wrong set. It is not
that nothing calls them: `targets.py` recovers branch targets from `.reloc`,
`.pdata`, `.xdata` and switch tables, and **a `call rel32` is none of those**
-- it is PC-relative, so it carries no relocation and appears in no table.
Scanning the disassembly for direct calls and jumps finds them. 0x1402a9fa0
is the shape of the whole class:

    vmovaps %xmm1,%xmm2        ; called twice, from 0x142661c35
    vxorps  %xmm1,%xmm1,%xmm1  ; and 0x142661d14
    vmovss  %xmm2,%xmm1,%xmm2
    vinsertps $0x30,%xmm2,%xmm0,%xmm0
    ret

Pure register work and a `ret`: it touches no stack and calls nothing, so
MSVC omits its unwind data exactly as the ABI permits.

So the oracle extends, and `leaf_ranges` states the conditions it extends
under. All four must hold, and each rules out a different way of being
wrong:

  * **Bracketed by `int3`.** MSVC pads between functions with `cc`, so
    padding is where a function provably ends. Splitting there is what makes
    the chunk start at a function start rather than mid-padding.
  * **Starts at something that enters it.** A call, a jump, or a
    RIP-relative `lea` taking its address. A constant pool is none of those.
    This is the positive evidence that the bytes are entered as code, and
    the `lea` half was the last of the three to be found -- see
    `lea_targets`, which is why 865 chunks that looked unreferenced were
    not.
  * **Ends in a control transfer.** Compiler output does not fall off the
    end of a function into padding. A chunk ending any other way is one the
    disassembler desynchronised inside, so its boundaries are not trustworthy
    even if its first byte was.
  * **No `(bad)`.** objdump emits it for bytes that decode to no
    instruction. Real compiler output contains none, so one anywhere in the
    chunk is near-proof the sweep is out of step.

The 20 `(bad)` regions and the 44 that run off the end stay refused. That is
the trade `function_ranges` describes, kept: being slightly less effective
is the right price for not corrupting data.

The "uncalled" row above was itself measured twice for the same reason. With
calls and jumps alone it held 868 chunks; adding `lea` moved 865 of them into
the accepted row, and those 865 are 99.9% 16-byte aligned and 813 of them end
in `ret`. They are address-taken leaf functions -- a copy constructor at
0x1402ce510 that does a `vmovups` pair and a `lock xadd` on a refcount, a
setter at 0x140544cf0 that stores one float and returns `this`. Nothing calls
them because every call site inlined them, and the linker kept the out-of-line
COMDAT copy that the address-taking needs.

  report <binary> <listing>
"""

import bisect
import sys
from collections import Counter

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
import patch as inplace
import targets as target_set

# How a function ends. `int3` cannot appear here -- it terminates a chunk
# before this is consulted -- but a tail call and a plain return both can.
TERMINATORS = ("ret", "retq", "jmp", "jmpq", "ud2")


def pads(encoding, mnemonic):
	"""Whether a row is a `nop` of any length, however objdump spells it.

	**objdump names the two-byte nop `xchg %ax,%ax`**, and the longer ones
	behind an operand-size prefix `data16 nopw` or `data16 data16 cs
	nopw`, so the mnemonic alone misses them: `66 90` aligning the switch
	table after 0x1422cf7a0 was read as the function's last instruction,
	the piece "ran off the end", and its `vmovaps` stayed VEX and faulted
	in the game. The encoding says it plainly -- `90` or `0f 1f` behind
	nothing but `66` and `2e` prefixes. Finding 357.
	"""
	if mnemonic.startswith("nop"):
		return True
	body = encoding.lstrip(b"\x66\x2e")
	return body == b"\x90" or body.startswith(b"\x0f\x1f")


def covered(starts, ranges, address):
	i = bisect.bisect_right(starts, address) - 1
	return i >= 0 and address < ranges[i][1]


def lea_targets(listing):
	"""Addresses taken by a RIP-relative `lea`, which nothing else records.

	This is the third way a function is reachable and the last one found.
	`lea rax,[rip+f]` is how MSVC takes a function's address, and it is
	**PC-relative, so it produces no relocation** -- `.reloc` is complete for
	absolute addresses and this is not one. It is not a call either. So a
	function whose address is only ever taken this way is invisible to both
	of the other two scans, and 865 of the 868 chunks that looked entirely
	unreferenced turned out to be exactly that: address-taken leaf functions,
	stored as pointers and called indirectly.

	164,395 addresses across the binary. None of them fell inside a detour
	window when that was measured, so nothing was wrong in the output -- but
	that was an observation about one binary rather than a property of the
	rewriter, and an indirect call landing in the middle of a window is not
	something to leave resting on luck.
	"""
	import detour				# late: detour imports this module
	found = set()
	for _address, _encoding, mnemonic, operands, comment in \
			detour.parse_with_comments(listing):
		if mnemonic == "lea" and isinstance(comment, int) \
				and "(%rip)" in operands:
			found.add(comment)
	return found


def call_targets(instructions):
	"""Direct call and jump destinations, which no relocation records."""
	found = set()
	for _address, _encoding, mnemonic, operands in instructions:
		if not operands or not mnemonic.startswith(("j", "call", "loop")):
			continue
		first = operands.split()[0]
		if not first.startswith("0x"):
			continue
		try:
			found.add(int(first, 16))
		except ValueError:
			pass
	return found


def chunks(instructions, ranges, data=None):
	"""Runs of instructions outside .pdata, split at int3 padding.

	Splitting at padding is the part that matters. A run typically *begins*
	with the padding that follows the previous function, so a chunk taken
	without splitting starts at a `cc` -- and then every test of "does
	anything call this address" asks about the padding and answers no.

	**With `known`, split at every entry point as well, because padding
	finds where a function ENDS and an entry point finds where one
	BEGINS.** Between two `.pdata` functions MSVC packs several leaf
	functions and their embedded constants with no `int3` between them, so
	one chunk spans the lot: it is entered, it contains the constants as
	`(bad)`, and it ends wherever the next described function starts rather
	than at a `ret`. Classified whole it fails three of the four conditions
	at once and 319 sites went with it.

	Cutting at an entry point costs nothing and is not a new argument: a
	call, jump or `lea` destination is a true instruction boundary, which is
	exactly what the second condition already asserts about a chunk start.
	Each piece is then classified by the SAME four conditions, and the ones
	that are entered, end in a transfer and hold no `(bad)` are admitted --
	141 of the 319. The rest stay refused, which is `function_ranges`'
	trade kept rather than widened. Finding 313.

	It under-admits on purpose. An internal jump target inside a genuine
	leaf function cuts it in two, and the first piece then ends at the loop
	head rather than at a `ret` and is refused. Losing a piece is the right
	direction to be wrong in.

	**`data` ends a chunk the way padding does.** It is the rows of the
	switch tables the caller resolved, which MSVC places straight after the
	function that dispatches through them. Running into them left the last
	piece holding `(bad)`, and the setters at 0x14087d770 and 0x14087da40
	-- a `vmovss` and a `ret` per case -- were refused whole, and faulted in
	the game. A resolved table is known data, so where it starts the
	function has ended.

	**A trailing `nop` is not where a function ends**, so it is not what
	"ends in a transfer" reads: the table is aligned, the `nop` before it
	is padding, and recording it as the last instruction refused the same
	setters a second time. The last instruction that is not a `nop` must
	still be a transfer. Finding 338.
	"""
	starts = [start for start, _end in ranges]
	out = []
	current = None
	for address, encoding, mnemonic, _operands in instructions:
		padding = mnemonic == "int3" or (data is not None and address in data)
		inside = covered(starts, ranges, address)
		if inside or padding or (current and address != current[1]):
			if current:
				out.append(current)
				current = None
			if inside or padding:
				continue
		if not current:
			current = [address, address, 0, 0, 0, ""]
		current[1] = address + len(encoding)
		current[2] += 1
		if not pads(encoding, mnemonic):
			current[5] = mnemonic
		if encoding[:1] in (b"\xc4", b"\xc5"):
			current[3] += 1
		if mnemonic == "(bad)":
			current[4] += 1
	if current:
		out.append(current)
	return out


def jump_sources(instructions):
	"""{target: [source, ...]} for direct jumps, conditional or not.

	Calls are left out on purpose: a call's destination is an entry point,
	which is what `split_refused` is asking about, and a jump's is not
	necessarily one.
	"""
	found = {}
	for address, _encoding, mnemonic, operands in instructions:
		if not operands or not mnemonic.startswith(("j", "loop")):
			continue
		first = operands.split()[0]
		if not first.startswith("0x"):
			continue
		try:
			target = int(first, 16)
		except ValueError:
			continue
		found.setdefault(target, []).append(address)
	return found


def split_refused(instructions, found, known, entries=None):
	"""`found`, with every REFUSED chunk re-cut at its entry points.

	**Padding says where a function ends and an entry point says where one
	begins, and between two `.pdata` functions MSVC leaves no padding.** It
	packs several leaf functions and their embedded constants there, so one
	chunk spans the lot: entered at its first byte, holding the constants as
	`(bad)`, and ending wherever the next described function starts rather
	than at a `ret`. Classified whole it fails three conditions at once, and
	319 of Starfield's surviving sites went with it.

	Re-cutting is not a new argument. A call, jump or `lea` destination is a
	true instruction boundary, which is precisely what the second condition
	already asserts about a chunk start -- so each piece is handed to
	`classify` and judged by the same conditions, with the third one
	tightened because the first no longer holds: see `classify`. 133 VEX
	sites in 1,003 pieces are admitted; the rest stay refused, which keeps
	`function_ranges`' trade rather than widening it.

	**Only refused chunks, and that bound is measured rather than cautious.**
	Cutting every chunk turned 3,006 into 108,688 pieces and admitted 14,174
	VEX sites -- a hundredfold change to the oracle, from a change meant to
	recover 141 sites. Two properties said so: the admitted pieces were 71.9%
	16-byte aligned against 93.9% for the refused ones, inverting the test
	that validated the original 865, and 2,216 of them ended in a CONDITIONAL
	jump, which is mid-function. Both come from cutting genuine functions at
	their internal loop heads. A chunk that already passes has nothing to
	gain from being cut and everything to lose, so it is left whole.

	**With `entries`, a jump target the chunk's own jumps alone reach is
	not a cut.** Cutting there split a genuine leaf function in two, and the
	first piece then ended at a conditional jump and was refused: the setter
	at 0x14087da40, reached through a vtable, branches over its own store to
	0x14087da5e, and its `vmovss` stayed VEX and faulted in the game.
	`entries` holds the addresses that ARE entry points whatever branches to
	them -- relocated, tabled, called, address-taken -- and a jump target is
	cut at only when it is one of those or a jump from outside the chunk
	reaches it. That cuts less, never more, so every piece still begins at
	an entry and is judged by the same strict conditions. Without `entries`
	every known address cuts, as before. Finding 338.
	"""
	out = []
	sources = jump_sources(instructions) if entries is not None else {}
	order = [address for address, _e, _m, _o in instructions]
	rows = {address: (encoding, mnemonic)
	        for address, encoding, mnemonic, _o in instructions}
	place = {address: i for i, address in enumerate(order)}
	for chunk in found:
		if classify(chunk, known)[1] or chunk[0] not in place:
			out.append(chunk)
			continue
		piece = None
		i = place[chunk[0]]
		while i < len(order) and order[i] < chunk[1]:
			address = order[i]
			encoding, mnemonic = rows[address]
			if piece is not None and address in known and address != piece[0] \
					and cuts(address, chunk, entries, sources):
				out.append(piece)
				piece = None
			if piece is None:
				piece = [address, address, 0, 0, 0, "", True]
			piece[1] = address + len(encoding)
			piece[2] += 1
			if not pads(encoding, mnemonic):
				piece[5] = mnemonic
			if encoding[:1] in (b"\xc4", b"\xc5"):
				piece[3] += 1
			if mnemonic == "(bad)":
				piece[4] += 1
			i += 1
		if piece is not None:
			out.append(piece)
	return out


def cuts(address, chunk, entries, sources):
	"""Whether a recut starts a new piece at `address`. See `split_refused`."""
	if entries is None or address in entries:
		return True
	return any(not chunk[0] <= source < chunk[1]
	           for source in sources.get(address, ()))


def classify(chunk, known):
	"""(verdict, accepted as code) for one chunk.

	**A recut piece is held to a stricter third condition, because it has
	lost the first.** A whole chunk is bracketed by `int3`, so "ends in a
	transfer" only has to rule out a desync; a conditional jump is enough,
	being a thing compiler output does at the end of a padded block. A piece
	cut at an entry point has no padding either side, so that condition is
	carrying the whole weight of "this is where the function ends" -- and a
	conditional jump is exactly where a function does NOT end. Requiring a
	`ret` or an unconditional `jmp` costs 9 VEX sites of 142 and drops 236 of
	1,239 pieces, which is a cheap price for the condition that was dropped.
	Finding 313.
	"""
	_first, _end, _count, _vex, bad, last = chunk[:6]
	recut = len(chunk) > 6 and chunk[6]
	terminates = last in TERMINATORS if recut else \
		last in TERMINATORS or (last.startswith("j") and last != "(bad)")
	if bad:
		return "contains (bad) -- not code", False
	called = chunk[0] in known
	if called and terminates:
		return "called, and ends in a transfer", True
	if called:
		return "called, but runs off the end", False
	if terminates:
		return "uncalled, ends in a transfer", False
	return "uncalled, runs off the end", False


def control():
	"""Refuse to answer unless `classify` still tells the two cases apart.

	**The recut rule is a distinction, and a distinction is what rots
	silently.** If the seventh field stops being read, every recut piece
	falls back to the loose terminator test and 236 mid-function pieces come
	back with it -- and nothing downstream would say so, because the oracle
	would simply be bigger. A control that lives beside the tool is run when
	somebody remembers; this one is run when they do not.

	Each case is one that has to hold for `split_refused`'s argument to
	stand, and the conditional-jump pair is the whole of it: the SAME chunk
	is accepted whole and refused recut. Finding 313.
	"""
	entry = 0x1000
	known = {entry}
	cases = (
		("whole, ends in a conditional jump", [entry, 0x1010, 4, 1, 0, "jne"],
		 True),
		("recut, ends in a conditional jump",
		 [entry, 0x1010, 4, 1, 0, "jne", True], False),
		("recut, ends in ret", [entry, 0x1010, 4, 1, 0, "ret", True], True),
		("recut, ends in an unconditional jmp",
		 [entry, 0x1010, 4, 1, 0, "jmp", True], True),
		("recut, holds a (bad)", [entry, 0x1010, 4, 1, 1, "ret", True], False),
		("recut, nothing enters it",
		 [0x2000, 0x2010, 4, 1, 0, "ret", True], False),
	)
	for name, chunk, want in cases:
		got = classify(chunk, known)[1]
		if got is not want:
			raise SystemExit(
				f"outside.py: the control failed -- {name} was "
				f"{'accepted' if got else 'refused'} and must be "
				f"{'accepted' if want else 'refused'}. No result below "
				f"means anything.")
	# **And the cut rule, on the game's own shape**: a setter that jumps
	# over its store to 0x100c, followed by data the whole chunk refuses
	# on. The piece from 0x1000 must be admitted when only its own jump
	# reaches 0x100c, and refused when a jump from outside does. Finding
	# 338.
	rows = [(0x1000, b"\x48\x8b\x51\x08", "mov", "0x8(%rcx),%rdx"),
	        (0x1004, b"\x75\x06", "jne", "0x100c"),
	        (0x1006, b"\xc5\xfa\x11\x42\x40\x90", "vmovss", "%xmm0,0x40(%rdx)"),
	        (0x100c, b"\x48\x8b\x51\x08", "mov", "0x8(%rcx),%rdx"),
	        (0x1010, b"\xc3", "ret", ""),
	        (0x1011, b"\xff", "(bad)", "")]
	whole = [[0x1000, 0x1012, 6, 1, 1, "(bad)"]]
	for name, extra, want in (("its own jump alone", [], True),
	                          ("a jump from outside", [(0x2000, b"\xeb\x00",
	                                                    "jmp", "0x100c")],
	                           False)):
		pieces = split_refused(rows + extra, whole, {0x1000, 0x100c, 0x1011},
		                       {0x1000, 0x1011})
		got = any(piece[0] == 0x1000 and classify(piece, {0x1000})[1]
		          for piece in pieces)
		if got is not want:
			raise SystemExit(
				f"outside.py: the control failed -- with {name} reaching "
				f"0x100c the piece from 0x1000 was "
				f"{'accepted' if got else 'refused'}. No result below "
				f"means anything.")
	# **A resolved switch table ends a chunk like padding**: the case
	# `vmovss; ret` followed by its table must be accepted when the table's
	# rows are named as data, and refused when they are not. Finding 338.
	case = [(0x3000, b"\xc5\xfa\x10\x05\0\0\0\0", "vmovss",
	         "0x0(%rip),%xmm0"),
	        (0x3008, b"\xc3", "ret", ""),
	        (0x3009, b"\x90", "nop", ""),
	        (0x300a, b"\xa5\xd7\x87\x00", "(bad)", "")]
	aligned = case[:2] + [(0x3009, b"\x66\x90", "xchg", "%ax,%ax"),
	                      (0x300b, b"\xa5\xd7\x87\x00", "(bad)", "")]
	for name, rows, data, want in (
			("named as data", case, {0x300a}, True),
			("not named", case, None, False),
			("aligned by xchg %ax,%ax", aligned, {0x300b}, True)):
		got = any(chunk[0] == 0x3000 and classify(chunk, {0x3000})[1]
		          for chunk in chunks(rows, [], data))
		if got is not want:
			raise SystemExit(
				f"outside.py: the control failed -- a case ending in its "
				f"switch table, {name}, was "
				f"{'accepted' if got else 'refused'}. No result below "
				f"means anything.")


def leaf_ranges(instructions, ranges, known, entries=None, data=None):
	"""(start, end) of every chunk outside .pdata that is provably code.

	Returned in the same shape as `patch.function_ranges`, so the two
	concatenate into one oracle. See the module docstring for why each of
	the four conditions is required.
	"""
	control()
	return sorted((first, end)
	              for chunk in split_refused(
	                  instructions, chunks(instructions, ranges, data), known,
	                  entries)
	              for first, end in [(chunk[0], chunk[1])]
	              if classify(chunk, known)[1])


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	if argv[0] != "report":
		print(f"outside.py: unknown mode {argv[0]!r}", file=sys.stderr)
		return 2
	binary, listing = argv[1], argv[2]

	ranges = inplace.function_ranges(binary)
	instructions = list(inplace.parse_listing(listing))

	known = set()
	for group in target_set.collect(binary).values():
		known |= group
	relocated = len(known)
	known |= call_targets(instructions)
	called = len(known)
	known |= lea_targets(listing)

	print(f"branch targets from .reloc/.pdata/.xdata/tables {relocated:>9,}")
	print(f"  plus direct call and jump destinations        {called:>9,}")
	print(f"  plus addresses taken by a RIP-relative lea    {len(known):>9,}")
	print()

	found = split_refused(instructions, chunks(instructions, ranges), known)
	with_vex = [c for c in found if c[3]]
	print(f"chunks outside .pdata               {len(found):>9,}")
	print(f"  of which contain a VEX site       {len(with_vex):>9,}")
	print(f"  VEX sites in them                 {sum(c[3] for c in with_vex):>9,}")
	print()

	verdicts, sites, examples = Counter(), Counter(), {}
	accepted_sites = 0
	for chunk in with_vex:
		verdict, accepted = classify(chunk, known)
		verdicts[verdict] += 1
		sites[verdict] += chunk[3]
		if accepted:
			accepted_sites += chunk[3]
		examples.setdefault(verdict, chunk)

	print(f"{'verdict':<36}{'chunks':>8}{'VEX sites':>11}   example")
	for verdict, count in verdicts.most_common():
		first, end, insns, vex, _bad, _last = examples[verdict][:6]
		print(f"  {verdict:<34}{count:>8,}{sites[verdict]:>11,}"
		      f"   0x{first:x} {end - first}B {insns} insns")
	print()
	print(f"accepted as code by leaf_ranges: {accepted_sites:,} VEX sites in "
	      f"{len(leaf_ranges(instructions, ranges, known)):,} chunks")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
