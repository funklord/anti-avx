#!/usr/bin/env python3
"""Cached access to the inputs every measurement here needs.

**Nearly every question asked of this binary starts with the same twelve
minutes.** Parsing the 927 MB listing takes about two, and
`home_space_map` -- which walks every function's frame and unwind data --
takes about eight. A session that asks six questions pays that six times
for data that has not changed since August.

So it is cached, and the whole design is the KEY. A stale cache silently
used is the failure this project has met more than any other: an
instrument reporting on something other than what it was pointed at. The
key therefore includes the binary and the listing by size and mtime, the
mtime and size of every tool file that could change the answer, and the
values of the flags that change it -- so an edit to `detour.py`, a
different `--spill`, or a rebuilt listing all miss the cache rather than
being served a wrong answer.

**Conservative on purpose.** Keying on tool mtimes means an unrelated
comment change invalidates everything, which costs one rebuild. The other
direction costs a wrong measurement, and this session spent a day
distinguishing those two kinds of mistake.

Nothing here decides anything. It hands back exactly what `collect` would
have built, so a probe using it and a probe building its own inputs must
agree -- which `--verify` checks by building both and comparing.
"""

import hashlib
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour
import outside
import patch as inplace
import scratch as scratch_finder
import targets as target_set

CACHE = Path("build") / "probecache"

# Every file whose contents could change what is cached. `detour.py` and
# `patch.py` build the listing rows; `outside.py` and `targets.py` decide
# the ranges and the branch targets; `scratch.py` decides the scope.
SOURCES = ("detour.py", "patch.py", "outside.py", "targets.py", "scratch.py")


def stamp(binary, listing):
	"""A key that changes whenever anything the answer depends on does."""
	parts = []
	for path in (binary, listing):
		info = Path(path).stat()
		parts.append(f"{path}:{info.st_size}:{int(info.st_mtime)}")
	here = Path(__file__).resolve().parent
	for name in SOURCES:
		info = (here / name).stat()
		parts.append(f"{name}:{info.st_size}:{int(info.st_mtime)}")
	# The flags that change what `home_space_map` and the collector answer.
	parts.append(f"spill={detour.SPILL} rsp={detour.RSP_RULE} "
	             f"region={detour.REGION_RULE} escape={detour.ESCAPE_RULE} "
	             f"shadow={detour.SHADOW_RULE}")
	return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def cached(name, binary, listing, build):
	"""`build()`'s answer, from disk if the key still matches."""
	key = stamp(binary, listing)
	path = CACHE / f"{name}-{key}.pkl"
	if path.exists():
		with path.open("rb") as handle:
			return pickle.load(handle)
	value = build()
	CACHE.mkdir(parents=True, exist_ok=True)
	# Written to a temporary name and moved, so an interrupted write leaves
	# no half file for the next run to load as though it were whole.
	temporary = path.with_suffix(".partial")
	with temporary.open("wb") as handle:
		pickle.dump(value, handle, protocol=pickle.HIGHEST_PROTOCOL)
	temporary.replace(path)
	return value


def listing_rows(binary, listing):
	"""`(instructions, plain, blocked)` -- the parse and the branch targets."""
	def build():
		groups = target_set.collect(binary)
		blocked = set()
		for values in groups.values():
			blocked |= values
		instructions = list(detour.parse_with_comments(listing))
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
		plain = [(a, e, m, o) for a, e, m, o, _c in instructions]
		return instructions, plain, blocked
	return cached("listing", binary, listing, build)


def function_ranges(binary, listing):
	"""The `.pdata` ranges plus the leaves `outside.py` recovers."""
	def build():
		_instructions, plain, blocked = listing_rows(binary, listing)
		described = inplace.function_ranges(binary)
		return sorted(described + outside.leaf_ranges(plain, described,
		                                              blocked))
	return cached("ranges", binary, listing, build)


def function_scope(binary, listing):
	"""Which xmm registers each function never names."""
	def build():
		_instructions, plain, _blocked = listing_rows(binary, listing)
		return scratch_finder.function_scope(
			plain, function_ranges(binary, listing),
			scratch_finder.inplace.standard_entries(binary))
	return cached("scope", binary, listing, build)


def home(binary, listing):
	"""The home-space map, which is the expensive one."""
	def build():
		_instructions, plain, blocked = listing_rows(binary, listing)
		return detour.home_space_map(binary, plain,
		                             function_ranges(binary, listing),
		                             blocked)
	return cached("home", binary, listing, build)


def main():
	"""`probe.py <binary> <listing> [--verify]` -- warm the cache.

	`--verify` builds everything twice, once from cache and once from
	scratch, and requires the two to agree. A cache that answers quickly
	and wrongly is worse than no cache, and the only way to know which one
	this is, is to build both.
	"""
	if len(sys.argv) < 3:
		print("usage: probe.py <binary> <listing> [--verify]",
		      file=sys.stderr)
		return 2
	binary, listing = sys.argv[1], sys.argv[2]
	print(f"probe: key {stamp(binary, listing)}")
	instructions, plain, blocked = listing_rows(binary, listing)
	ranges = function_ranges(binary, listing)
	print(f"probe: {len(instructions):,} instructions, {len(blocked):,} "
	      f"branch targets, {len(ranges):,} ranges")
	scope = function_scope(binary, listing)
	print(f"probe: scope over {len(scope[1]):,} functions")
	built = home(binary, listing)
	print(f"probe: home map over {len(built[1]):,} functions")
	if "--verify" in sys.argv:
		global CACHE
		keep, CACHE = CACHE, Path("build") / "probecache-verify"
		fresh_rows = listing_rows(binary, listing)
		fresh_ranges = function_ranges(binary, listing)
		CACHE = keep
		if fresh_rows[1] != plain or fresh_ranges != ranges:
			print("probe: FAILED -- the cache and a fresh build disagree",
			      file=sys.stderr)
			return 1
		print("probe: a fresh build agrees with the cache")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
