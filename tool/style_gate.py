#!/usr/bin/env python3
# Copied from ~/.claude/tool/style_gate.py -- the source. Keep in sync;
# fix drift the moment you notice it.
"""The indentation and whitespace gate for private projects.

One tool, merged from three that had grown apart:

  fuzzypickles/tools/tabify.py    the C/C++ fixer (brace-nesting lexer)
  beerssh/tools/tabify.py         a copy of it, drifted in the docstring only
  */tools/check-indent.sh         file enumeration plus the collapse floor
  situ/tools/lint_conventions.py  the checker: ASCII, tabs, trailing space,
                                  final newline, with a tokenize-based
                                  exemption for Python string literals
                                  (C/C++ literals are exempt here too, by a
                                  scanner written for the purpose)

The two tabify.py copies were byte-identical in code and differed only in
their docstrings, which is the cheap kind of drift. The two check-indent.sh
copies had genuinely diverged -- different discovery, different scope,
different floor -- and both were right for their own tree, which is why
those differences are configuration here rather than a winner.

A fourth capability existed in none of them: fixing Python. tabify.py's
lexer counts braces and cannot see a Python block, so apt-emerge's
conversion was done by a throwaway script. That approach is folded in.

Every fixer carries a proof rather than a promise:

  C/C++   expanding leading tabs back to `indent_width` columns must give
          the original file. Only leading whitespace is ever rewritten.
  Python  the AST must be identical before and after. ast.dump() without
          attributes is position-free but carries every string constant,
          so an identical dump means no block and no literal moved.

A fixer that cannot prove its own edit refuses to write it.

Usage:
    style_gate.py check [--root DIR] [PATH...]
    style_gate.py fix   [--root DIR] PATH...
    style_gate.py list  [--root DIR]      # what would be checked, and why
    style_gate.py docs  [--root DIR]      # hold project.md to the tree

Configuration is `.style-gate.toml` at the project root; every key is
optional. See DEFAULTS below for the meaning and the shipped values.
"""
from __future__ import annotations

import ast
import io
import fnmatch
import re
import subprocess
import sys
import tokenize
from pathlib import Path
from types import ModuleType
from typing import Any, NoReturn

try:
	import tomllib as _tomllib
except ModuleNotFoundError:		# pragma: no cover - 3.10 and older
	_tomllib = None			# type: ignore[assignment]

#: Bound through a name of its own so the optional import has a type that
#: admits absence. Annotating the `import` itself is not possible, and
#: without this a checker decides the module is always present and calls the
#: "no tomllib" branch -- which is the branch that refuses to run with the
#: wrong file set -- unreachable.
tomllib: ModuleType | None = _tomllib

#: A loaded configuration: string keys, and values of whatever shape the
#: matching default has -- an int, a string, or a list of strings.
#:
#: `Any` rather than a union, deliberately. The values are read back in a
#: dozen places as the shape their default implies, and what makes that safe
#: is `type_problems`, which compares every loaded value against its
#: default's type at load time and refuses the file otherwise. The guarantee
#: is the check, not the annotation; a union here would only move the same
#: assertion to a dozen call sites.
Config = dict[str, Any]

DEFAULTS: Config = {
	# A MIGRATION parameter, not a style setting. It is how many columns a
	# level occupied in a space-indented file that is being converted, and it
	# is read only while converting one. Once a file is tab-indented no width
	# applies to it ever again: the tab carries the level, spaces carry
	# alignment measured from the content, and the viewer decides how wide a
	# tab looks. Checking never uses this value.
	"indent_width": 4,

	# Minimum plausible file count. Below it the gate fails loudly instead
	# of passing. A gate that has quietly stopped matching anything reads
	# exactly like a clean tree -- see the note on collapse() below.
	#
	# Prefer a fraction: `floor = 0.3` means the gated count must be at
	# least that share of every path git lists, before any filtering. A
	# fraction stays calibrated as the tree grows; a whole number was right
	# on the day it was chosen and decays silently after -- measured at
	# between 22% and 80% of the real count across fourteen projects.
	"floor": 1,

	# ASCII-only content. Off by default: three projects require it, one
	# explicitly exempts Markdown, and it is not yet a global rule.
	# In Python and in C/C++ it means ASCII *outside string literals*, which
	# is what the rule has always said -- a tick a program prints is output,
	# not prose. Every other language still gets the whole file, having no
	# lexer here, and so does a file in either of those two that will not
	# lex: see python_ascii_problems and c_ascii_problems.
	"ascii_only": False,
	"ascii_exclude_markdown": True,


	# Scope. Empty include means the whole repository.
	"include": [],
	# The two discovery paths must agree. git's --exclude-standard drops
	# tool state on its own; the plain walk used when there is no repo -- as
	# in a container CI that copies the source in without .git -- does not,
	# and would check a pytest cache README and the local editor settings.
	# They happen to conform, so the gate would pass on luck.
	"exclude": ["attic", "third_party", "vendor", "build", "target",
	            "dist", ".pytest_cache", ".claude"],

	# `Makefile` is deliberately absent from indent_names. A recipe line must
	# begin with a literal tab, so it is compliant by construction; and the
	# body of an `ifeq`/`ifdef` is indented with SPACES precisely because a
	# leading tab there would be read as a recipe. Both spellings are correct
	# and required in the same file, so the tab rule has nothing to say about
	# Makefiles. They still get the text checks.
	#
	# Files whose indentation is ours to govern.
	# `.rs` is deliberately absent. This tool has no Rust parser, so the line
	# rule cannot tell a string literal from code and reports the usage text
	# inside one as space-indented -- 97 such findings in netcfgd, none real.
	# Rust is not unchecked: `rustfmt` with `hard_tabs = true` enforces the
	# same rule and does have a parser. Check what you can read; defer the
	# rest to something that can, rather than guessing loudly.
	"indent_suffixes": [".c", ".h", ".cpp", ".hpp", ".cc", ".hh", ".py",
	                    ".situ", ".ebnf", ".lua"],
	"indent_names": [],

	# Files that get the text checks (trailing space, final newline, and
	# ASCII when enabled) but not necessarily the tab rule.
	"text_suffixes": [".md", ".json", ".toml", ".cfg", ".map"],

	# The design document `docs` mode holds to the tree, and the backticked
	# paths in it that are known not to be files -- globs, examples, things
	# named before they exist. Listing one is a claim that it is deliberate.
	"doc_file": "project.md",
	"doc_ignore": [],
	# Paths are checked in TABLE ROWS only, and that restriction is what
	# makes the check work. A table in a design document is a declared
	# inventory: every entry claims a file exists. Prose is not -- it names
	# `main.c` as an example, or a file without the directory it lives in,
	# and neither is wrong. Checking prose produced dozens of findings
	# across every project and none of them real; checking table rows
	# produces zero false positives across all eight.
	"doc_check_paths": True,
}

SKIP_DIR_NAMES = frozenset({"__pycache__", ".git"})


# ------------------------------------------------------------- reporting

def reject(message: str, *consequence: str) -> NoReturn:
	"""Report a fault that makes this run's answer meaningless, and stop.

	Lifted out of reject_config the day discovery gained a failure of its
	own. The two are the same shape and want the same report: one line
	naming what went wrong, indented lines saying what continuing would
	have cost. Exit 2 in both, so a broken instrument is never confused
	with the 1 that a real violation returns.
	"""
	print(f"style-gate: {message}", file=sys.stderr)
	for line in consequence:
		print(f"style-gate:   {line}", file=sys.stderr)
	raise SystemExit(2)


# ---------------------------------------------------------------- config

def reject_config(path: Path, problem: str, *consequence: str) -> NoReturn:
	"""Report a config that cannot be applied as written, and stop.

	Every caller is the same failure and it is worth naming once: the file
	exists, so somebody wrote it to change what the gate looks at, and it did
	not take effect. Continuing on the defaults would then check a DIFFERENT
	file set and report that as success -- which is the one outcome a gate
	must never produce, because it is indistinguishable from a clean tree.

	So the rule is: a config that is present is read and applied exactly, or
	the run fails. There is no middle setting where it half-applies.
	"""
	reject(f"{path} {problem}", *consequence)


def type_problems(loaded: Config) -> list[str]:
	"""Keys whose value is the wrong shape, judged against the default's.

	The dangerous case is a list written as a bare string, because it is not
	an error anywhere: `indent_names = "emerge"` is valid TOML, and a set()
	of a string is a set of its CHARACTERS, so the name matches nothing and
	the gate quietly checks a smaller tree. Measured before this existed --
	one pair of quotes instead of brackets took a three-file list down to
	one, exit 0, no output but the count.

	bool is checked before int deliberately: it is a subclass of int in
	Python, so `ascii_only = 1` would otherwise pass the int test.
	"""
	problems = []
	for key in sorted(loaded):
		value = loaded[key]
		default = DEFAULTS[key]
		if key == "floor":
			# Two shapes by design: a whole number is the absolute floor,
			# a float strictly inside (0, 1) is a share of the raw
			# population. 1.0 is refused rather than read as 100%: TOML
			# writers reach for `floor = 1.0` meaning the old default, and
			# demanding every raw file be gated would fail every tree.
			ok = ((isinstance(value, int) and not isinstance(value, bool))
			      or (isinstance(value, float) and 0 < value < 1))
			if not ok:
				problems.append(f"floor: want a whole number, or a "
				                f"fraction strictly between 0 and 1, "
				                f"got {value!r}")
			continue
		if isinstance(default, bool):
			ok, want = isinstance(value, bool), "true or false"
		elif isinstance(default, int):
			ok = isinstance(value, int) and not isinstance(value, bool)
			want = "a whole number"
		elif isinstance(default, str):
			ok, want = isinstance(value, str), "a string"
		else:
			ok = (isinstance(value, list)
			      and all(isinstance(item, str) for item in value))
			want = "a list of strings"
		if not ok:
			problems.append(f"{key}: want {want}, got {value!r}")
	return problems


def load_config(root: Path) -> Config:
	cfg = dict(DEFAULTS)
	path = root / ".style-gate.toml"
	if not path.is_file():
		# A directory, and a symlink pointing at nothing, both answer False
		# here -- and both mean somebody intended there to be a config. Only
		# genuine absence may fall back to the defaults.
		if path.exists() or path.is_symlink():
			reject_config(path, "exists but is not a readable file.",
			              "a directory or a broken symlink here reads as "
			              "'no config at all', which would pass.")
		return cfg
	if tomllib is None:
		# Refuse rather than degrade. Ignoring the config means ignoring the
		# scope it widens and the floor it raises, so the gate would run with
		# defaults, check the wrong file set, and report a clean tree.
		reject_config(path, "exists but this Python has no tomllib "
		                    "(needs 3.11+).",
		              "running with defaults would check the wrong files "
		              "and pass.")
	try:
		with path.open("rb") as handle:
			loaded = tomllib.load(handle)
	except OSError as exc:
		# A traceback is a failure too, but it reads as a tool that broke
		# rather than a config that is wrong, and the difference decides who
		# goes looking.
		reject_config(path, f"cannot be read: {exc.strerror}.")
	except tomllib.TOMLDecodeError as exc:
		reject_config(path, f"is not valid TOML: {exc}.")
	unknown = set(loaded) - set(DEFAULTS)
	if unknown:
		# A misspelt key that is silently ignored is a gate that quietly
		# stops enforcing whatever the key was meant to turn on.
		reject_config(path, f"has unknown key(s): "
		                    f"{', '.join(sorted(unknown))}.")
	wrong = type_problems(loaded)
	if wrong:
		reject_config(path, "has values of the wrong type.", *wrong)
	cfg.update(loaded)
	return cfg


# ------------------------------------------------------------ discovery

def in_git_repo(root: Path) -> bool:
	"""True if git will answer for this tree; False if it is not a repo.

	There is a third case, and folding it into the second is the fault
	discover() already guards against one function below, arriving by the
	earlier door. A tree that IS a repository but whose git refuses to
	speak exits non-zero here exactly as a plain directory does -- the
	dubious-ownership guard, on a checkout owned by another user, is the
	way to meet this without anything being broken. Read as "not a
	repository" it falls through to the filesystem walk, and that walk is
	right only for a tree with no `.git` to skip: `.git` itself and every
	ignored build artifact enter the population, the excludes written
	against git's list do not cover them, and the collapse floor is then
	measured against a number with nothing to do with the tree.

	Measured in this repository, 2026-08-31: raw population 1084 instead
	of 18, three quarters of it `.git`, and `make style-source` failed
	with "found 15 files, expected at least 444 -- check include/exclude
	in .style-gate.toml". The excludes were fine. A gate that names the
	wrong suspect costs more than one that says nothing, because the hour
	goes into the file it accused.

	So a `.git` present and git unwilling stops the run, the same way an
	`ls-files` that exits non-zero does, and for the same reason: the tool
	cannot say anything true about a file set it was unable to read. A
	tree with no `.git` still walks, which is the case the fallback was
	built for and the only one it is right for.
	"""
	try:
		out = subprocess.run(["git", "-C", str(root), "rev-parse",
		                      "--is-inside-work-tree"],
		                     capture_output=True, text=True, check=False)
		if out.returncode == 0:
			return out.stdout.strip() == "true"
		detail = out.stderr.strip().splitlines() or [
			f"git rev-parse exited {out.returncode} and said nothing."]
	except OSError as exc:
		detail = [f"git could not be run: {exc}"]
	if (root / ".git").exists():
		reject(f"{root} has a .git, and git will not read it.", *detail,
		       "the fallback from here is a filesystem walk, which is "
		       "right only for a tree that is not a repository.")
	return False


def discover(root: Path, cfg: Config) -> tuple[list[Path], int]:
	"""Every file this project owns, and the raw count it was filtered from.

	The raw count is the second return because the collapse floor needs a
	baseline the failure modes cannot touch. Everything between the git call
	and the kept list -- the exclude set, the include prefixes, the
	extension selection -- is exactly what a bad edit collapses, so a floor
	measured against the kept list of some earlier day goes stale as the
	tree grows and fails by passing. The raw population is upstream of all
	of it, moves with the tree, and costs nothing to return.

	git is preferred because `--cached --others --exclude-standard` gets two
	things right that a walk cannot: ignored build output and vendored
	submodule content drop out on their own, and a NEW file is listed before
	it has been committed. Scoping a pre-commit gate to tracked files only is
	backwards, and did once let a non-conformant new file through.

	The fallback exists so the tool works in a tree that is not a repo yet.
	"""
	if in_git_repo(root):
		out = subprocess.run(
			["git", "-C", str(root), "ls-files", "--cached", "--others",
			 "--exclude-standard"],
			capture_output=True, text=True, check=False)
		# A git that exits non-zero is a broken instrument, not an empty
		# tree, and downstream the two are indistinguishable: both arrive
		# as no output. The case that found this is a truncated .git/index
		# -- what a full filesystem leaves behind -- where ls-files exits
		# 128, prints nothing on stdout and puts the reason on stderr.
		# Read as an empty list it handed the collapse floor a raw
		# population of zero, which no floor can fire against, so `check`
		# printed "0 files conform" and exited 0 and `make style-source`
		# reported a pass. Stop here instead, while git's own message is
		# still in hand to print: the tool cannot say anything true about
		# a file set it was unable to read.
		if out.returncode != 0:
			detail = out.stderr.strip().splitlines() or [
				f"git ls-files exited {out.returncode} and said nothing."]
			reject(f"cannot list the files in {root}.", *detail,
			       "discovery is the whole file set, so continuing "
			       "would check nothing and pass.")
		names = [line for line in out.stdout.splitlines() if line]
		paths = [root / n for n in names]
	else:
		paths = [p for p in root.rglob("*") if p.is_file()]

	include = [str(i).strip("/") for i in cfg["include"]]
	# Excludes come in two kinds. A literal matches a path component
	# exactly, which was the only kind until an ABI-suffixed build
	# directory needed one entry per ABI: build-android-arm64-v8a today,
	# a second literal the day an x86_64 emulator build exists, and a
	# stale literal in any tree that renamed -- hydra carried plain
	# "build-android" for weeks after its directory grew the suffix,
	# hidden only because the git walk never shows ignored files. So an
	# entry containing a glob character is a pattern, matched per
	# component with fnmatch: "build-android-*" covers every ABI and
	# survives the rename that strands a literal.
	raw_exclude = [str(e).strip("/") for e in cfg["exclude"]]
	exclude = {e for e in raw_exclude if not any(c in e for c in "*?[")}
	exclude_globs = [e for e in raw_exclude if any(c in e for c in "*?[")]
	kept = []
	for path in paths:
		if not path.is_file():
			continue
		try:
			rel = path.relative_to(root)
		except ValueError:
			continue
		parts = rel.parts
		if any(p in SKIP_DIR_NAMES or p in exclude
		       or any(fnmatch.fnmatchcase(p, g) for g in exclude_globs)
		       for p in parts):
			continue
		if include and not any(rel.as_posix() == i or rel.as_posix().startswith(i + "/")
		                       for i in include):
			continue
		if wants_text(path, cfg) or wants_indent(path, cfg):
			kept.append(path)
	return sorted(set(kept)), len(paths)


def wants_indent(path: Path, cfg: Config) -> bool:
	if path.suffix in set(cfg["indent_suffixes"]) or path.name in set(cfg["indent_names"]):
		return True
	# A program with no suffix is still ours. Deciding scope on suffix alone
	# excluded exactly the files that matter most: `fmake` IS fmake, `emerge`
	# IS apt-emerge, and `situc` is situ's compiler entry point. The gate
	# checked their documentation, found it clean, and said so -- the precise
	# shape of vacuous pass this tool exists to refuse. A shebang is the
	# file saying it is a program; that is enough.
	return not path.suffix and has_shebang(path)


def has_shebang(path: Path) -> bool:
	try:
		with path.open("rb") as handle:
			return handle.readline(2) == b"#!"
	except OSError:
		return False


def wants_text(path: Path, cfg: Config) -> bool:
	return wants_indent(path, cfg) or path.suffix in set(cfg["text_suffixes"])


def floor_count(raw: int, cfg: Config) -> int:
	"""The smallest gated count this config calls plausible, in files.

	One place computes it because three read it back: collapse() judges
	against it, `list` prints it, and the message a collapse prints quotes
	it. That message used to print `cfg["floor"]` itself, which for a
	fraction read "expected at least 0.35" -- the right number in the
	wrong unit, and one no reader could compare against the file count
	sitting beside it.
	"""
	floor = cfg["floor"]
	if isinstance(floor, float):
		return int(floor * raw)
	return int(floor)


def collapse(count: int, raw: int, cfg: Config) -> bool:
	"""True if the file list has plausibly collapsed rather than come back clean.

	"Found nothing" cannot mean "there is nothing to check" in a tree with
	sources -- it can only mean the pathspec, the glob or the git call stopped
	matching. Reported as success that is the worst outcome available: a gate
	that has stopped looking is indistinguishable from a clean tree and stays
	that way until somebody thinks to doubt it.

	`floor` takes two shapes, and the difference is what it stays true
	against:

	- **A fraction (0 < floor < 1)**: the gated count must be at least that
	  share of the RAW population -- every path git lists before the
	  excludes, the include prefixes and the extension selection run. Those
	  filters are exactly what a bad edit collapses, so the baseline sits
	  upstream of every failure this check exists to catch, and it moves
	  with the tree: a floor of 0.3 chosen when 239 of 800 files were gated
	  is still 0.3 when the tree is twice the size. Measured across
	  fourteen projects before this existed, the absolute form had decayed
	  to between 22% and 80% of the real count -- every number right on the
	  day it was written, wrong later, and silent about it, because a floor
	  that is too low fails by passing.

	- **A whole number**: the old absolute form, kept so an un-migrated
	  config keeps its protection. It catches a collapse; what it cannot do
	  is stay calibrated as the tree grows.

	Neither shape polices a number: adding files never requires touching
	either. And neither promises to catch a single module dropping out --
	that needs a floor within one module of the real count, which fires on
	every legitimate addition. What a floor catches is a collapse. The
	advice that once claimed the finer catch claimed more than any floor
	can deliver.

	A raw population of zero is judged before either shape, because it is
	the one input both are blind to. `count < floor * 0` is `0 < 0`, which
	is False, so the fractional form passed precisely the case this
	docstring names -- the pathspec, the glob or the git call having
	stopped matching -- and was strictly weaker there than the absolute
	form it replaced. Found with a truncated .git/index, where `check`
	printed "0 files conform" and exited 0. discover() now refuses a
	failing git before this is reached, but a floor that only holds
	because some other check closed the door is not a floor.
	"""
	if raw == 0:
		return True
	return count < floor_count(raw, cfg)


# -------------------------------------------------------------- lexing

_CASE_LABEL = re.compile(r"(?:case\b|default\s*:)")

# Identifier runs that turn a following `"` into a C++ raw string literal.
RAW_PREFIXES = frozenset({"R", "LR", "uR", "UR", "u8R"})

# Identifier runs that turn a following `'` into a character literal. Any
# other run before a quote means a digit separator -- see c_ascii_problems.
CHAR_PREFIXES = frozenset({"L", "u", "U", "u8"})

# Control keywords whose parenthesised head may be followed by a single
# statement instead of a block. Their bodies are a real indent level that no
# brace records, so a brace-counting lexer places them one level too shallow
# and then reports correct code as wrong. Braceless bodies are permitted and
# sometimes preferable, so the lexer models them rather than the style being
# bent to suit the lexer.
CTRL_HEADS = frozenset({"if", "for", "while"})


def split_leading_ws(line: str, width: int) -> tuple[int, str]:
	"""(visual column of first non-ws char, remainder). Tabs expand at width."""
	col = 0
	i = 0
	for ch in line:
		if ch == " ":
			col += 1
		elif ch == "\t":
			col += width - (col % width)
		else:
			break
		i += 1
	return col, line[i:]


def leading_whitespace(line: str) -> str:
	return line[: len(line) - len(line.lstrip(" \t"))]


def is_comment_continuation(line: str) -> bool:
	"""A C block-comment body line, whose leading space aligns the asterisk."""
	return line.lstrip().startswith("*")


C_SUFFIXES = frozenset({".c", ".h", ".cpp", ".hpp", ".cc", ".hh"})


def has_fixer(path: Path) -> bool:
	"""True where a depth-aware converter exists, making the line rule redundant."""
	return is_python(path) or path.suffix in C_SUFFIXES


def is_python(path: Path) -> bool:
	"""Python by suffix, or by shebang for a command that has no suffix."""
	if path.suffix == ".py":
		return True
	try:
		with path.open("rb") as handle:
			first = handle.readline(64)
	except OSError:
		return False
	return first.startswith(b"#!") and b"python" in first


def python_ascii_problems(text: str, where: Path) -> list[Problem] | None:
	"""Non-ASCII outside string literals, or None if it cannot be read.

	The rule this enforces has always allowed Unicode in what a program
	*prints* -- "a tick a program prints is output, not prose" -- and
	forbidden it in the text the repository writes about itself. A
	whole-file byte check cannot tell those apart, so a project with two
	status ticks in f-strings had to switch the check off for its comments
	as well, and an em dash duly reached one. tokenize makes the
	distinction for free, and only for Python; everything else keeps the
	byte check.

	Returning None rather than [] when the file will not tokenise matters:
	the caller then falls back to the *stricter* whole-file check. A file
	nobody can parse is not a file that has been cleared, and a
	non-breaking space between two tokens is exactly the kind of thing
	that both breaks tokenize and needs reporting.
	"""
	literal = {tokenize.STRING}
	for name in ("FSTRING_MIDDLE",):
		kind = getattr(tokenize, name, None)
		if kind is not None:
			literal.add(kind)
	problems = []
	try:
		for token in tokenize.generate_tokens(io.StringIO(text).readline):
			if token.type in literal:
				continue
			for offset, char in enumerate(token.string):
				if ord(char) > 127:
					row, col = token.start
					problems.append(Problem(
					    where, row, col + offset + 1,
					    f"non-ASCII {char!r} outside a string literal"))
					break
	except (tokenize.TokenError, SyntaxError, IndentationError):
		return None
	return problems


def splice_len(text: str, i: int) -> int:
	"""Length of a backslash-newline at `i`, or 0.

	Translation phase 2: a backslash at end of line removes the newline
	before anything else looks at the file, so a `//` comment carries on
	into the next line and a string literal spans it. Both shapes appear in
	real headers -- a continued comment above a macro, a long message split
	across lines -- and a scanner that stops at the newline mislabels
	everything after it.
	"""
	if text[i] != "\\":
		return 0
	j = i + 1
	if j < len(text) and text[j] == "\r":
		j += 1
	if j < len(text) and text[j] == "\n":
		return j - i + 1
	return 0


def c_ascii_problems(text: str, where: Path) -> list[Problem] | None:
	"""Non-ASCII outside C/C++ string and character literals, or None.

	The question python_ascii_problems answers, asked in the language the
	rule's own example is written in: a glyph in a button label is output,
	an em dash in a comment is prose. Nothing in the standard library lexes
	C, so this does -- and only as far as the question needs, which is where
	the literals start and stop. Braces, parens and nesting belong to
	convert_c and are deliberately not repeated here; the two scanners
	answer different questions and merging them would give the fixer a
	stake in this one.

	None means the file did not lex, and the caller then falls back to the
	stricter whole-file byte check. That is the direction that matters, and
	it is the same contract the Python side keeps: an unterminated comment,
	string or raw string means the scanner lost its place, and a file whose
	literals cannot be located is not a file whose prose has been cleared.
	"""
	problems: list[Problem] = []
	i, n = 0, len(text)
	line, col = 1, 1

	def step(count: int = 1) -> None:
		nonlocal i, line, col
		for _ in range(count):
			if i >= n:
				return
			if text[i] == "\n":
				line += 1
				col = 1
			else:
				col += 1
			i += 1

	def note(char: str) -> None:
		problems.append(Problem(where, line, col,
		                        f"non-ASCII {char!r} outside a literal"))

	while i < n:
		char = text[i]

		if text.startswith("//", i):
			while i < n and text[i] != "\n":
				spliced = splice_len(text, i)
				if spliced:
					step(spliced)
					continue
				if ord(text[i]) > 127:
					note(text[i])
				step()
			continue

		if text.startswith("/*", i):
			step(2)
			closed = False
			while i < n:
				if text.startswith("*/", i):
					step(2)
					closed = True
					break
				if ord(text[i]) > 127:
					note(text[i])
				step()
			if not closed:
				return None
			continue

		if char in "\"'":
			run = ""
			back = i - 1
			while back >= 0 and (text[back].isalnum() or text[back] == "_"):
				run = text[back] + run
				back -= 1

			# `1'000'000`. C++14's digit separator is spelled like a
			# character literal and is not one, and reading it as one
			# desynchronises the scanner for everything after it -- an odd
			# number of separators on a line swallows the rest of the file.
			# The test is exact rather than heuristic: a character literal
			# is never preceded by an identifier or a digit, because no
			# valid program writes `foo'a'`. The encoding prefixes are the
			# whole of the exception, so `L'x'` and `u8'x'` still lex.
			if char == "'" and run and run not in CHAR_PREFIXES:
				step()
				continue

			if char == '"' and run in RAW_PREFIXES:
				# R"delim( ... )delim" -- delim is at most 16 characters
				# and holds no paren, backslash or whitespace. Qt sources
				# carry whole JavaScript programs this way, quotes and all.
				opened = text.find("(", i + 1)
				delim = text[i + 1:opened] if opened >= 0 else None
				if (delim is not None and len(delim) <= 16
						and not any(c in delim for c in "()\\ \t\r\n")):
					closer = ")" + delim + '"'
					at = text.find(closer, opened + 1)
					if at < 0:
						return None
					step(at + len(closer) - i)
					continue
				# Not a raw string after all; read it as an ordinary one.

			quote = char
			step()
			closed = False
			while i < n:
				spliced = splice_len(text, i)
				if spliced:
					step(spliced)
					continue
				if text[i] == "\\":
					step(2)			# escapes whatever follows
					continue
				if text[i] == quote:
					step()
					closed = True
					break
				if text[i] == "\n":
					break			# unterminated: no valid literal
				step()
			if not closed:
				return None
			continue

		if ord(char) > 127:
			note(char)
		step()

	return problems


def python_literal_lines(text: str) -> frozenset[int]:
	"""Rows inside multi-line Python string literals.

	Their leading whitespace is content, not indentation: a golden diagnostic
	text with a space gutter must survive the tab rule untouched.
	"""
	# Python 3.12 stopped emitting a multi-line f-string as one STRING token
	# and began splitting it into FSTRING_START / MIDDLE / END around its
	# expressions. Matching only STRING therefore left every multi-line
	# f-string unprotected, and the converter reindented the text inside it
	# -- in fmake's `selftest` that text is C++ source the case then
	# compiles. The AST proof refused the write; this is why it stopped
	# being needed for that file.
	FSTART = getattr(tokenize, "FSTRING_START", None)
	FEND = getattr(tokenize, "FSTRING_END", None)
	covered: set[int] = set()
	opened: list[int] = []
	try:
		for token in tokenize.generate_tokens(io.StringIO(text).readline):
			if FSTART is not None and token.type == FSTART:
				opened.append(token.start[0])
				continue
			if FEND is not None and token.type == FEND and opened:
				start = opened.pop()
				if token.end[0] > start:
					covered.update(range(start + 1, token.end[0] + 1))
				continue
			if token.type == tokenize.STRING and token.end[0] > token.start[0]:
				covered.update(range(token.start[0] + 1, token.end[0] + 1))
	except (tokenize.TokenError, SyntaxError, IndentationError):
		# A file that does not tokenise has a real error somebody else will
		# report. Do not also fail it on indentation.
		return frozenset()
	return frozenset(covered)


# --------------------------------------------------------------- checks

class Problem:
	def __init__(self, path: Path, line: int, col: int,
			message: str) -> None:
		self.path    = path
		self.line    = line
		self.col     = col
		self.message = message

	def __str__(self) -> str:
		return f"{self.path}:{self.line}:{self.col}: {self.message}"


def check_text(text: str, where: Path, indent: bool = True,
               skip: frozenset[int] = frozenset(),
               heuristic: bool = True) -> list[Problem]:
	"""The line rules, against text that need not be a file on disk.

	Split out because code a compiler *emits* is governed by nobody: it lands
	in a build directory the gate skips, and before that it lives inside the
	emitter's own string literals, which the literal exemption deliberately
	excludes. One rule, two callers -- the file checker, and a test that runs
	it over generated output.
	"""
	problems: list[Problem] = []
	previous = ""
	for number, line in enumerate(text.splitlines(), start=1):
		# A backslash-continued line's leading whitespace is alignment under
		# whatever it continues, not indentation -- a Makefile variable list
		# aligned under its first entry sits at depth 0 and correctly carries
		# no tab. Without a parser the column-only rule cannot tell the two
		# apart, and this is the case that actually occurs.
		continuation = previous.rstrip().endswith("\\")
		previous = line

		if line != line.rstrip():
			problems.append(Problem(where, number, len(line.rstrip()) + 1,
			                        "trailing whitespace"))
		if "\r" in line:
			problems.append(Problem(where, number, line.index("\r") + 1,
			                        "carriage return"))

		if not indent or number in skip or continuation or is_comment_continuation(line):
			continue

		lead = leading_whitespace(line)
		# Tabs carry the indent level and spaces carry alignment within it,
		# so a space may follow a tab but never precede one.
		# A space before a tab is wrong at every width and needs no parser, so
		# it is checked even where a fixer exists. Only the column heuristic
		# below needs standing down for those, the fixer knowing the real
		# depth and a depth-0 continuation legitimately starting with spaces.
		if " " in lead and "\t" in lead[lead.index(" "):]:
			problems.append(Problem(where, number, lead.index(" ") + 1,
			                        "space before tab in indent"))
		elif heuristic and lead.startswith(" ") and line.strip():
			problems.append(Problem(where, number, 1,
			                        "space-indented line; use tabs"))
	return problems


def check_file(path: Path, root: Path, cfg: Config) -> list[Problem]:
	rel      = path.relative_to(root)
	problems = []
	raw      = path.read_bytes()

	if cfg["ascii_only"] and not (cfg["ascii_exclude_markdown"] and path.suffix == ".md"):
		found = None
		reader = (python_ascii_problems if is_python(path)
		          else c_ascii_problems if path.suffix in C_SUFFIXES
		          else None)
		if reader is not None:
			try:
				found = reader(raw.decode("utf-8"), rel)
			except UnicodeDecodeError:
				found = None            # not UTF-8 either; the bytes decide
		fell_back = found is None
		if found is None:
			try:
				raw.decode("ascii")
			except UnicodeDecodeError as exc:
				offset  = exc.start
				line_no = raw.count(b"\n", 0, offset) + 1
				col_no  = offset - (raw.rfind(b"\n", 0, offset) + 1) + 1
				found = [Problem(rel, line_no, col_no,
				                 f"non-ASCII byte 0x{raw[offset]:02x}")]
			else:
				found = []
		# ASCII findings from a SUCCESSFUL reader join the rest rather
		# than returning early. The return here cost an order of magnitude
		# once: a tree adopting the gate read 371 indentation findings
		# across 7 files, spelled its em dashes out, and read 3347 across
		# 48 -- the 7 were exactly the files that happened to be pure
		# ASCII already. A count that depends on which OTHER rule fired
		# first is not a count.
		#
		# But a finding from the BYTE FALLBACK stands alone, and situ's
		# suite pinned that contract when the first version of this fix
		# broke it: the fallback runs precisely because the file would not
		# lex, so every later check that leans on literal exemptions would
		# report through a model that refused the file. One finding from
		# an unassessable file is the honest answer; hembygd's files all
		# lexed, which is why both cases exist.
		if fell_back and found:
			problems.extend(found)
			return problems
		problems.extend(found or [])

	text = raw.decode("utf-8", errors="replace")
	if raw and not raw.endswith(b"\n"):
		problems.append(Problem(rel, raw.count(b"\n") + 1, 1,
		                        "no newline at end of file"))

	# The line rule cannot see structural depth, and a continuation line at
	# depth 0 -- a signature wrapped under its own open paren at module level
	# -- correctly carries NO tab, only alignment spaces. Flagging those is
	# wrong, and inherited from the checker this tool merges: apt-emerge alone
	# has 219 such lines. Where a fixer exists it knows the real depth, so the
	# fixpoint check below is both authoritative and depth-aware, and the
	# heuristic is redundant. Keep the heuristic only for the languages that
	# have no fixer, where something is better than nothing.
	skip = python_literal_lines(text) if is_python(path) else frozenset()
	problems.extend(check_text(text, rel, wants_indent(path, cfg), skip,
	                           heuristic=not has_fixer(path)))

	# Where a fixer exists, "tabs-then-spaces" is the weaker of two possible
	# questions. The C fixer also knows what LEVEL each line belongs at, so a
	# file can satisfy the line rule and still be indented to the wrong depth
	# -- which the old tabify.py --check caught and a pure line check does
	# not. Migrating to this tool without asking the stronger question would
	# have quietly weakened two projects' gates, which is the exact failure
	# the floor above exists to prevent, arriving by a different door.
	if wants_indent(path, cfg) and has_fixer(path):
		fixed, error = fixed_text(path, text, cfg)
		if error:
			problems.append(Problem(rel, 1, 1, error))
		else:
			# The rule, stated without reference to any tab width: the number
			# of leading TABS must equal the structural depth. How many
			# spaces follow is alignment and is nobody's business -- it is
			# measured from where the content starts, so it holds at every
			# width. That is the whole point of tabs-for-structure, and it is
			# why this check compares tab counts rather than whole lines:
			# comparing lines asks "is this what the converter would emit",
			# which needs a width to answer and so contradicts the rule it is
			# trying to enforce.
			for n, (was, now) in enumerate(zip(text.splitlines(),
			                                   fixed.splitlines()), start=1):
				if n in skip or is_comment_continuation(was):
					continue
				want = len(now) - len(now.lstrip("\t"))
				have = len(was) - len(was.lstrip("\t"))
				if have != want:
					problems.append(Problem(rel, n, 1,
						f"indented {have} tab(s), structure says {want}"))
	return problems


# --------------------------------------------------------------- fixers

def convert_c(text: str, width: int) -> str:
	"""Rewrite leading whitespace in C/C++ so indent is tabs, alignment spaces.

	Structural indent = level * width columns -> level tabs; columns beyond
	that are alignment -> spaces. `level` is brace-nesting depth plus one for
	a switch's case/default body, since C labels open no brace but their
	bodies sit a level deeper. Braces inside strings, char literals, comments
	and preprocessor lines are not counted.
	"""
	lines = text.split("\n")
	out = []
	# one [is_switch, in_case, paren_depth] per open brace
	stack: list[list[int]] = []
	state = "normal"		# normal | block_comment | string | char | raw
	pp_cont = False			# inside a backslash-continued directive
	pending_switch = False		# saw `switch`, awaiting its `{`
	ident = ""
	raw_end = ""			# the `)delim"` that closes an open raw string
	paren = 0			# ( ) depth, to find where a control head ends
	head_paren = None		# paren depth a control head is unwinding to
	virtual = 0			# open braceless bodies: real levels, no braces
	linkage_extern = False		# saw `extern`, watching for its linkage string
	linkage_spec = False		# saw `extern "C"`, awaiting the `{`
	namespace_spec = False		# saw `namespace`, awaiting the `{`
	await_body = False		# an `else`/`do` whose body shape is not yet known
	stmt_level = 0			# level of the line the current statement began on

	def case_extra(frames: list[list[int]]) -> int:
		return sum(1 for f in frames if f[0] and f[1])

	def depth(frames: list[list[int]]) -> int:
		"""Open braces that actually indent.

		`extern "C" { ... }` is a brace and not a level: every C++ project
		writes the declarations inside it at the same column as the ones
		outside, because the block says how to link them and not where they
		sit. Counting it put a spurious tab on any line carrying alignment
		-- a wrapped parameter list, say -- and none on lines starting at
		column 0, so it surfaced as scattered findings in headers rather
		than as a whole block being wrong.

		`namespace N { ... }` is the same brace-without-a-level and was
		missed, for eight months and in every C++ tree here. It failed the
		same way and hid for the same reason: a flush line at column 0 takes
		the `lead_cols < width * level` branch below and is left alone, so
		namespace contents written flush -- which is what all of them are --
		looked accepted, while any line carrying ALIGNMENT had columns
		enough to take the other branch and collected a phantom tab.

		The measurement that settled it: across the fifteen projects, of the
		94 places a gated C or C++ file opens a namespace, 94 write the
		contents flush and none indents them. (A first count said one tree
		indented 576 times and another once; the 576 were vendored files no
		gate reads, and the one was this scanner reading a block comment's
		` *` continuation as indentation. Both were the instrument.)

		What it cost is the reason to record it rather than just fix it.
		`code-style.md`'s own worked example for this rule conformed when
		saved verbatim and reported two violations when a namespace was
		wrapped round it -- so the document and the tool that enforces it
		disagreed, and the trees had been converted to the tool's answer.
		A rule learned from the tool rather than from the document is the
		wrong way round.
		"""
		return sum(1 for f in frames if not f[4])

	for line in lines:
		state_at_start = state
		lead_cols, rest = split_leading_ws(line, width)

		# An `else` or `do` at the end of the previous line leaves the shape
		# of its body unknown until this line starts. Resolve it here, before
		# the level is computed: a `{` means the brace owns the level, and
		# anything else means this line is the body and takes it.
		if state_at_start == "normal" and await_body and rest[:1] not in ("{", ""):
			virtual += 1
			await_body = False

		if rest == "":
			new = line			# blank: no churn
		elif state_at_start in ("string", "raw"):
			new = line			# inside a literal: content
		elif pp_cont:
			# A backslash-continued directive's later lines are aligned
			# under the directive, not indented by the structure around it:
			# a `do { ... } while (0)` macro at file scope is written with
			# tabs for readability and belongs at depth 0 by this model,
			# so rewriting them to the structural level reports every line
			# of the macro. check_text() already stands down on exactly
			# these lines for the same reason; this is the fixer agreeing.
			new = line
		elif state_at_start == "normal" and not pp_cont and rest[0] == "#":
			new = line			# preprocessor directive
		else:
			top_is_switch = bool(stack) and stack[-1][0]
			is_close = state_at_start == "normal" and rest[0] == "}"
			is_open = state_at_start == "normal" and rest[0] == "{"
			is_label = (state_at_start == "normal" and top_is_switch
			            and _CASE_LABEL.match(rest) is not None)
			if is_close:
				frames = stack[:-1]
				level = depth(frames) + case_extra(frames)
			elif is_label:
				frames = stack[:-1]
				level = depth(stack) + case_extra(frames)
			else:
				frames = stack
				level = depth(stack) + case_extra(frames)
			# A braceless body is one real level per open construct. A brace
			# on its own line belongs to the construct that opened it, not to
			# the body it is about to start, so it does not take that level.
			level += virtual - (1 if is_open and virtual else 0)
			level = max(level, 0)

			# A line that opens inside unclosed parens continues a statement
			# begun earlier, and its alignment is measured from where THAT
			# line's content starts -- so it takes that line's tab count, not
			# its own abstract depth. The two differ for a braceless body
			# written on the same line as its head: `if (x) f(a,` puts the
			# statement at the head's indentation while its depth is one
			# deeper, and using the depth would break the alignment at every
			# tab width except the one it was computed for.
			base_paren = stack[-1][2] if stack else 0
			if paren > base_paren:
				level = stmt_level
			else:
				stmt_level = level
			if lead_cols >= width * level:
				new = "\t" * level + " " * (lead_cols - width * level) + rest
			else:
				new = "\t" * (lead_cols // width) + " " * (lead_cols % width) + rest
			if is_label:
				stack[-1][1] = True

		out.append(new)

		counting = not (pp_cont or (state_at_start == "normal" and rest[:1] == "#"))
		i, n = 0, len(line)
		while i < n:
			c = line[i]
			if state == "raw":
				# A raw string ends only at `)delim"`. Nothing inside it is
				# code: hydra embeds whole JavaScript programs this way, and
				# a lexer that walks in reads their braces as C++ nesting and
				# their indentation as ours. That produced 775 findings in
				# four files, none of them real.
				at = line.find(raw_end, i)
				if at < 0:
					break			# rest of the line is raw content
				i = at + len(raw_end)
				state = "normal"
				raw_end = ""
				continue
			if state == "normal":
				if c.isalnum() or c == "_":
					ident += c
					i += 1
					continue
				if counting and ident == "switch":
					pending_switch = True
				was_ident = ident
				ident = ""
				if counting and was_ident:
					if await_body:
						# `else if` -- the `if` owns the body, and must clear
						# the pending state or the next identifier inside its
						# own condition is mistaken for a braceless body.
						await_body = False
						if was_ident != "if":
							# `else`/`do` followed by a statement rather than
							# a block: that statement is the body.
							virtual += 1
					if linkage_spec:
						# `extern "C" JNIEXPORT void f(...) { ... }` is a
						# linkage specifier on one declaration, and that
						# brace opens a function body, which does indent.
						# Only a `{` following the string with nothing but
						# whitespace between opens a linkage BLOCK. hydra's
						# JNI entry points are the case that found this: 47
						# lines reported in one file by the first version
						# of this rule.
						linkage_spec = False
						linkage_extern = False
					if was_ident == "extern":
						linkage_extern = True
					if was_ident == "namespace":
						namespace_spec = True
					if was_ident in CTRL_HEADS:
						head_paren = paren	# body begins when this unwinds
					elif was_ident in ("else", "do"):
						await_body = True
				if c == "/" and i + 1 < n and line[i + 1] == "/":
					break
				if c == "/" and i + 1 < n and line[i + 1] == "*":
					state = "block_comment"
					i += 2
					continue
				if c == '"' and was_ident in RAW_PREFIXES:
					# R"delim( ... )delim" -- delim is up to 16 chars and may
					# not contain a paren, backslash or space.
					open_paren = line.find("(", i + 1)
					if open_paren >= 0:
						delim = line[i + 1:open_paren]
						if len(delim) <= 16 and not any(
								ch in delim for ch in "()\\ \t"):
							raw_end = ")" + delim + '"'
							state = "raw"
							i = open_paren + 1
							continue
					state = "string"	# not actually a raw string
				elif c == '"':
					# `extern` then a string is a linkage specifier, and
					# the block it may open is transparent.
					if linkage_extern:
						linkage_spec = True
					state = "string"
				elif c == "'":
					state = "char"
				elif counting and c == "(":
					paren += 1
				elif counting and c == ")":
					paren -= 1
					if head_paren is not None and paren <= head_paren:
						# the head is complete; whatever follows is its body
						virtual += 1
						head_paren = None
				elif counting and c == "{":
					# The brace takes the level the braceless body would have
					# had, rather than adding a second one on top of it.
					if virtual:
						virtual -= 1
					await_body = False
					# Remember the paren depth this block opened at. A C++
					# lambda passed as an argument -- `connect(x, [this] {`
					# -- runs its whole body at paren depth 1, so a statement
					# inside it ends at a `;` seen at THAT depth, not at zero.
					# Testing against zero leaves every braceless body opened
					# inside a lambda unclosed for the rest of the file.
					# The fourth field is the braceless-body count this block
					# opened INSIDE of -- its floor. A `;` in here closes the
					# bodies opened in here and must not reach past it: in
					#
					#     for (i = 0; i < 3; i++)
					#             if (i) {
					#                     g();
					#                     g();
					#             }
					#
					# the brace consumes the `if`'s body and the `for`'s is
					# still open around the whole block. Resetting to zero at
					# the first `;` dropped it, so the first statement was
					# right and every later one and the closing brace were
					# reported a tab too deep -- the level was lost after one
					# statement rather than never taken, which is what made it
					# look like an indentation fault in the file.
					stack.append([pending_switch, False, paren, virtual,
					              linkage_spec or namespace_spec])
					pending_switch = False
					linkage_extern = False
					linkage_spec = False
					namespace_spec = False
				elif counting and c == "}":
					# A closing brace ends a statement exactly as `;` does,
					# so it closes the braceless bodies opened inside this
					# block and restores the enclosing frame's floor -- the
					# count still open AROUND the block. Zeroing it here
					# dropped that floor, and the fault needed a braceless
					# loop whose body is itself a block containing one:
					#
					#     for (int y = 0; y < rows; ++y)
					#             for (int x = 0; x < cols; ++x) {
					#                     for (int i = 0; i < n; ++i) {
					#                             ...
					#                     }
					#                     if (ok) return {x, y};
					#             }
					#
					# The innermost `}` lost the outer `for`'s body, so every
					# following line was reported a tab too deep. It cost
					# more than a false finding: qtty's findText had been
					# indented two tabs and four spaces to silence it, which
					# is the mixed indent code-style.md rule 2 forbids and
					# which this gate accepts, counting leading tabs and
					# reading the spaces as alignment. The tool rejected
					# correct code, the code was bent to satisfy the tool,
					# and the tool went quiet.
					if stack:
						stack.pop()
					virtual = stack[-1][3] if stack else 0
					await_body = False
					linkage_extern = False
					linkage_spec = False
					namespace_spec = False
				elif counting and c == ";" and paren == (stack[-1][2] if stack else 0):
					# End of a statement closes every braceless body that was
					# waiting on it -- `if (a) if (b) x;` opened two -- but
					# only those opened inside the current block. Anything
					# still open around the block is this frame's floor.
					pending_switch = False
					virtual = stack[-1][3] if stack else 0
					await_body = False
					# `extern "C" int f(void);` declares rather than opens.
					linkage_extern = False
					linkage_spec = False
					# `using namespace std;` and `namespace a = b::c;` both
					# name a namespace and open no block. Without this the
					# flag stays armed and the NEXT brace in the file -- a
					# struct, a function -- is made transparent, which is the
					# expensive direction to be wrong in: a whole body then
					# reads one level too shallow.
					namespace_spec = False
				i += 1
			elif state == "block_comment":
				if c == "*" and i + 1 < n and line[i + 1] == "/":
					state = "normal"
					i += 2
					continue
				i += 1
			else:
				if c == "\\":
					i += 2
					continue
				if (state == "string" and c == '"') or (state == "char" and c == "'"):
					state = "normal"
				i += 1

		# An identifier ending the line is never resolved by the scanner
		# above, which only closes one when it meets a non-identifier
		# character. `else` and `do` on a line of their own are exactly that
		# shape, and so is a `switch` whose `(` is on the next line.
		if state == "normal" and counting:
			if ident == "switch":
				pending_switch = True
			elif ident in CTRL_HEADS:
				head_paren = paren
			elif ident in ("else", "do"):
				await_body = True
		ident = ""
		if state in ("string", "char") and not line.endswith("\\"):
			state = "normal"
		if pp_cont or (state_at_start == "normal" and rest[:1] == "#"):
			pp_cont = line.endswith("\\")
		else:
			pp_cont = False

	return "\n".join(out)


def convert_python(text: str, width: int) -> str:
	"""Rewrite leading whitespace in Python, structurally rather than by division.

	A line's depth comes from tokenize's INDENT/DEDENT stack, not from its
	column. That distinction is the whole job: a continuation line aligned
	under an open paren sits at a column that is not a multiple of `width`,
	and dividing its leading whitespace would turn alignment into indentation
	and destroy it. Rows inside multi-line strings are content and are never
	touched; a comment-only line has no structural meaning, so its own column
	decides.
	"""
	# One definition of "this row is literal content", shared with the
	# checker. It used to be computed twice, and when f-strings stopped
	# being a single token only one copy learned -- so the checker knew a row
	# was untouchable while the converter rewrote it.
	protected = python_literal_lines(text)

	row_depth: dict[int, int] = {}
	depth = 0
	for tok in tokenize.generate_tokens(io.StringIO(text).readline):
		if tok.type == tokenize.INDENT:
			depth += 1
		elif tok.type == tokenize.DEDENT:
			depth -= 1
		elif tok.type in (tokenize.NL, tokenize.NEWLINE,
		                  tokenize.COMMENT, tokenize.ENDMARKER):
			continue
		else:
			row_depth.setdefault(tok.start[0], depth)
			if tok.start[0] not in protected:
				for r in range(tok.start[0], tok.end[0] + 1):
					row_depth.setdefault(r, depth)

	out = []
	for row, line in enumerate(text.splitlines(keepends=True), 1):
		body = line.lstrip(" ")
		col = len(line) - len(body)
		if row in protected or not body.strip() or col == 0:
			out.append(line)
			continue
		if row in row_depth:
			d = row_depth[row]
			pad = " " * max(0, col - width * d)
		else:
			d, pad = col // width, " " * (col % width)
		out.append("\t" * d + pad + body)
	return "".join(out)


def expand(text: str, width: int) -> str:
	"""Leading tabs back to spaces, for content comparison."""
	out = []
	for line in text.split("\n"):
		cols, rest = split_leading_ws(line, width)
		out.append(" " * cols + rest if rest != "" else line)
	return "\n".join(out)


def fixed_text(path: Path, src: str, cfg: Config) -> tuple[str, str | None]:
	"""What the fixer would produce, with its proof checked. -> (text, error)."""
	width = int(cfg["indent_width"])
	if is_python(path):
		try:
			dst = convert_python(src, width)
		except (tokenize.TokenError, SyntaxError, IndentationError) as exc:
			return src, f"does not tokenise ({exc.__class__.__name__})"
		try:
			if ast.dump(ast.parse(src)) != ast.dump(ast.parse(dst)):
				return src, "AST would change (tool bug)"
		except SyntaxError as exc:
			return src, f"does not parse ({exc})"
		return dst, None
	if path.suffix in C_SUFFIXES:
		dst = convert_c(src, width)
		if expand(dst, width) != expand(src, width):
			return src, "conversion would change content (tool bug)"
		return dst, None
	return src, None


def fix_file(path: Path, cfg: Config, write: bool) -> tuple[bool, str | None]:
	"""-> (changed, error). Refuses to write an edit it cannot prove."""
	src = path.read_text(encoding="utf-8", errors="surrogateescape")
	if not has_fixer(path):
		return False, "no fixer for this file type; check only"

	dst, error = fixed_text(path, src, cfg)
	if error:
		return False, f"{error} -- not written"

	if dst == src:
		return False, None
	if write:
		path.write_text(dst, encoding="utf-8", errors="surrogateescape")
	return True, None


# ------------------------------------------------------------ doc gate

# A backticked token worth testing as a path: no globs, no placeholders, no
# URLs, no shell. Anything with a directory separator, or a bare filename
# carrying a suffix we recognise.
_DOC_TOKEN = re.compile(r"`([A-Za-z0-9._/-]+)`")
_DOC_SUFFIX = (".c", ".h", ".cpp", ".hpp", ".cc", ".hh", ".py", ".rs", ".situ",
               ".ebnf", ".lua", ".md", ".toml", ".json", ".sh", ".pro", ".txt")


def doc_paths(text: str) -> list[tuple[int, str]]:
	"""Backticked paths in table rows: the document's declared inventory."""
	found = []
	for number, line in enumerate(text.splitlines(), start=1):
		if not line.lstrip().startswith("|"):
			continue
		for token in _DOC_TOKEN.findall(line):
			if token.startswith(("http", "-", "/", ".")) or token.endswith("/"):
				continue
			if "/" in token:
				found.append((number, token))
	return found


def check_docs(root: Path, cfg: Config) -> list[Problem]:
	"""Hold the design document to the tree it describes.

	A map with a module missing from it is worse than no map: a reader looking
	for where something happens concludes there is nowhere, and writes a
	second copy. The same goes for a heading that appears twice -- whichever
	one you find, the other is the one with the answer.
	"""
	doc = root / cfg["doc_file"]
	problems: list[Problem] = []
	if not doc.is_file():
		return problems
	rel = Path(cfg["doc_file"])
	text = doc.read_text(encoding="utf-8", errors="replace")

	seen: dict[str, int] = {}
	for number, line in enumerate(text.splitlines(), start=1):
		if line.startswith("#"):
			if line in seen:
				problems.append(Problem(rel, number, 1,
					f"heading repeats line {seen[line]}: {line.strip()}"))
			else:
				seen[line] = number

	if not cfg["doc_check_paths"]:
		return problems

	ignore = set(cfg["doc_ignore"])
	for number, token in doc_paths(text):
		if token in ignore or (root / token).exists():
			continue
		# Only complain when the directory it names is real. A path under a
		# directory that does not exist is describing a layout rather than
		# pointing at a file, and flagging those buries the real findings.
		parent = (root / token).parent
		if parent != root and not parent.is_dir():
			continue
		problems.append(Problem(rel, number, 1, f"names a missing file: {token}"))
	return problems


# ----------------------------------------------------------------- main

def resolve(argv: list[str]) -> tuple[str, Path, list[Path]]:
	mode = argv[0] if argv else "check"
	if mode not in ("check", "fix", "list", "docs"):
		print(__doc__, file=sys.stderr)
		raise SystemExit(2)
	rest = argv[1:]
	root = Path.cwd()
	paths = []
	i = 0
	while i < len(rest):
		if rest[i] == "--root":
			root = Path(rest[i + 1]).resolve()
			i += 2
			continue
		if rest[i] in ("-h", "--help"):
			print(__doc__)
			raise SystemExit(0)
		paths.append(Path(rest[i]).resolve())
		i += 1
	return mode, root, paths


def main(argv: list[str]) -> int:
	mode, root, explicit = resolve(argv)
	cfg = load_config(root)
	if explicit:
		files, raw = explicit, 0
	else:
		files, raw = discover(root, cfg)

	if mode == "docs":
		problems = check_docs(root, cfg)
		for problem in problems:
			print(problem, file=sys.stderr)
		if problems:
			print(f"\n{len(problems)} documentation inconsistency(ies)", file=sys.stderr)
			return 1
		print(f"style-gate: {cfg['doc_file']} says nothing twice and names no "
		      f"missing file")
		return 0

	if mode == "list":
		for f in files:
			kind = "indent+text" if wants_indent(f, cfg) else "text"
			print(f"{f.relative_to(root)}\t{kind}")
		floor = cfg["floor"]
		if isinstance(floor, float):
			print(f"\n{len(files)} file(s) of {raw} raw; floor is "
			      f"{floor:g} of raw = {floor_count(raw, cfg)}", file=sys.stderr)
		else:
			print(f"\n{len(files)} file(s); floor is {floor}", file=sys.stderr)
		return 0

	if not explicit and collapse(len(files), raw, cfg):
		if raw == 0:
			print("style-gate: discovery found no files at all --",
			      file=sys.stderr)
			print("style-gate:   this is not an empty tree; it is a "
			      "population nothing can be measured against.",
			      file=sys.stderr)
			print("style-gate:   check that --root names the project, and "
			      "run `list`.", file=sys.stderr)
			return 2
		print(f"style-gate: found {len(files)} files, expected at least "
		      f"{floor_count(raw, cfg)} --", file=sys.stderr)
		print("style-gate:   this reads as a clean tree but is a collapsed "
		      "file list.", file=sys.stderr)
		print("style-gate:   check include/exclude in .style-gate.toml, or "
		      "run `list`.", file=sys.stderr)
		return 2

	if mode == "fix":
		rc = 0
		for path in files:
			if not wants_indent(path, cfg):
				continue
			changed, error = fix_file(path, cfg, write=True)
			if error and "no fixer" not in error:
				print(f"style-gate: {path}: {error}", file=sys.stderr)
				rc = 2
			elif changed:
				print(f"fixed {path.relative_to(root)}")
		return rc

	problems = []
	for path in files:
		problems.extend(check_file(path, root, cfg))
	for problem in problems:
		print(problem, file=sys.stderr)
	if problems:
		print(f"\n{len(problems)} convention violation(s) in {len(files)} file(s)",
		      file=sys.stderr)
		return 1
	# "conform" asserted more than was checked, and this repository's own
	# rules say to report what was actually verified. Measured 2026-08-27:
	# the structural half compares each line's tab count against what the
	# converter would emit, and the converter never ADDS indentation -- it
	# only re-expresses excess tabs as alignment. So a line with too few
	# tabs and no alignment spaces is invisible, and a file with no tabs
	# at all passed while printing that it conformed. Over-indentation is
	# caught; under-indentation is not. Saying so costs one line and
	# stops a green run being quoted for a guarantee it never made.
	print(f"style-gate: {len(files)} file(s) pass: whitespace, and "
	      f"indentation except under-indentation, which is not checked")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
