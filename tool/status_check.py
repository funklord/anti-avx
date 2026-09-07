#!/usr/bin/env python3
"""Do the documents still say what the rewriter does?

`project.md` and `README.md` both open with a status line quoting how many
VEX sites are rewritten, how many detours carry them and how many are left.
Those numbers were 797,907 / 202,115 / 7,224 while the tool measured
799,458 / 202,838 / 5,673 -- stale by 1,551 sites in the most-read line of
each document, and in TWO places, so correcting one would have left the
other (Finding 241).

The remedy this workspace prescribes for a count quoted often is to stop
quoting it from memory: a target that compares the number in the document
against what the run reports, and fails with both. That is this.

It reads a `verify` log rather than running one, because the Starfield
verify takes half an hour and this has to be cheap enough to run after
editing a sentence.

Usage:  status_check.py <verify.log> <document> [document ...]

**What it does NOT check**, so the pass is not read for more than it is:
only the three counts and the percentage. A status line can be wrong about
anything else -- the frontier address, the module count, whether an
invariant holds -- and this will pass. Those have no measurement to compare
against here.
"""
import re
import sys

# `verify: VEX in .text 805,131 -> 5,673  (799,458 removed, 99.3%)`
MEASURED = re.compile(r"VEX in \.text\s+([\d,]+)\s*->\s*([\d,]+)\s*"
                      r"\(([\d,]+) removed,\s*([\d.]+)%\)")


def number(text):
	return int(text.replace(",", ""))


def main(argv):
	if len(argv) < 2:
		print("usage: status_check.py <verify.log> <document> ...",
		      file=sys.stderr)
		return 2
	log = open(argv[0], encoding="utf-8", errors="replace").read()
	found = MEASURED.search(log)
	if found is None:
		# **A log with no measurement is not a pass.** Reading a truncated
		# or failed run and reporting "the documents agree" is the vacuous
		# pass this file exists to prevent one level down.
		print(f"status: FAILED -- no 'VEX in .text' line in {argv[0]}",
		      file=sys.stderr)
		return 2
	total, left, removed, percent = (number(found.group(1)),
	                                 number(found.group(2)),
	                                 number(found.group(3)),
	                                 found.group(4))
	print(f"status: measured {removed:,} of {total:,} rewritten "
	      f"({percent}%), {left:,} left")

	# **Check what a document CLAIMS, rather than demanding it claim
	# everything.** README quotes the percentage and the remainder;
	# project.md quotes the removed count and the detours. Requiring all
	# four of both reported a false failure on the first run. A document
	# that drops a claim passes -- this is about staleness, not coverage.
	claims = (
		("rewritten", re.compile(r"([\d,]+) of ([\d,]+) VEX"), removed),
		("left", re.compile(r"([\d,]+) sites are left"), left),
		("detours", re.compile(r"through \*?\*?([\d,]+) detours"), None),
		("percent", re.compile(r"([\d.]+)% of ([\d,]+) VEX"), None),
		("percent", re.compile(r"sites -- ([\d.]+)%"), None),
	)
	problems = checked = 0
	for path in argv[1:]:
		text = open(path, encoding="utf-8", errors="replace").read()
		# Only the status paragraph: a findings log quotes old measurements
		# on purpose, and rewriting those would destroy the record.
		head = text[:text.index("\n## ")] if "\n## " in text else text[:4000]
		for what, pattern, want in claims:
			found = pattern.search(head)
			if found is None:
				continue
			checked += 1
			said = found.group(1)
			if what == "percent":
				if said != percent:
					print(f"status: FAILED -- {path} says {said}%, "
					      f"measured {percent}%", file=sys.stderr)
					problems += 1
			elif what == "detours":
				print(f"status: {path} says {said} detours "
				      f"(no measurement here to check it against)")
			elif number(said) != want:
				print(f"status: FAILED -- {path} says {said} {what}, "
				      f"measured {want:,}", file=sys.stderr)
				problems += 1
	if problems:
		return 1
	print(f"status: {checked} claim(s) across {len(argv) - 1} document(s) "
	      f"agree with the measurement")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
