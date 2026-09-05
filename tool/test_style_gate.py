#!/usr/bin/env python3
# Copied from ~/.claude/tool/test_style_gate.py -- the source. Keep in sync;
# fix drift the moment you notice it.
"""Regression tests for the style gate and the commit-msg hook beside it,
each one a fault that shipped.

The gate is the most-copied tool in the workspace -- thirteen projects
carry it and every commit in fourteen runs it -- and until 2026-08-28 it
had no tests at all. Both lexer faults fuzznet reported in August reached
every copy before anything caught them, and the floor redesign shipped on
fixture runs done by hand in a scratch directory. A tool this shared
cannot keep being verified by whoever happens to be editing it.

Every test here names the incident that produced it, because a fixture
whose reason is lost gets deleted the next time it is inconvenient. Run
with `make test`, which is wired to fail the build; the suite needs
nothing beyond the standard library and the gate itself.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import style_gate as sg


def tabs(source: str, width: int = 8) -> list[int]:
	"""Leading-tab count per line after conversion, the model's answer."""
	out = sg.convert_c(source, width)
	return [len(l) - len(l.lstrip("\t")) for l in out.splitlines()]


class LexerModel(unittest.TestCase):
	"""convert_c is the model; the checker compares tab counts against it."""

	def test_plain_nesting(self):
		self.assertEqual(tabs("int f(void) {\n\tif (x) {\n\t\tg();\n\t}\n}\n"),
		                 [0, 1, 2, 1, 0])

	def test_switch_case_bodies_sit_one_deeper(self):
		src = "void f(void) {\n\tswitch (x) {\n\tcase 1:\n\t\tg();\n\t}\n}\n"
		self.assertEqual(tabs(src), [0, 1, 1, 2, 1, 0])

	def test_braceless_body_is_a_level(self):
		self.assertEqual(tabs("void f(void) {\n\tif (x)\n\t\tg();\n}\n"),
		                 [0, 1, 2, 0])

	def test_braceless_loop_keeps_its_body_past_an_inner_block(self):
		"""qtty, 2026-08-27: a braceless loop whose body is a block
		containing another block lost the outer body at the inner closing
		brace, and every following line was reported a tab too deep.

		It cost more than false findings. Twenty-two lines across five
		trees had been indented with tabs THEN SPACES to silence it --
		the mixed indent code-style.md rule 2 forbids outright, which
		this gate accepts because it counts leading tabs and reads the
		spaces as alignment. The tool rejected correct code, the code
		was bent to satisfy the tool, and the tool went quiet.
		"""
		src = ("int f(int rows, int cols, int n) {\n"
		       "\tfor (int y = 0; y < rows; ++y)\n"
		       "\t\tfor (int x = 0; x < cols; ++x) {\n"
		       "\t\t\tfor (int i = 0; i < n; ++i) {\n"
		       "\t\t\t\tg(i);\n"
		       "\t\t\t}\n"
		       "\t\t\tif (ok) return x;\n"
		       "\t\t}\n"
		       "\treturn -1;\n"
		       "}\n")
		self.assertEqual(tabs(src), [0, 1, 2, 3, 4, 3, 3, 2, 1, 0])

	def test_a_brace_that_serves_a_braceless_body_ends_it(self):
		"""The other side of the same restore, and the reason it is the
		ENCLOSING frame's floor rather than the popped frame's: once the
		block that was the braceless body closes, that body is over.
		Restoring the popped frame's own count leaves it open and pushes
		everything after the block one level too deep -- the original
		fault with its sign flipped.

		The shape is hydra's `site_extractor.cpp`, reduced, and reaching
		it took three tries -- which is the point worth recording. Two
		braceless constructs and a plain statement after the block: same
		under both. Three: same. A nested block: same. What separates
		them is a block closing while braceless bodies are open, followed
		by a line whose indent the lexer must not inflate -- an aligned
		continuation. Under the popped-floor restore the continuation
		goes to 4 instead of 2.

		The first two versions of this test passed under BOTH restores
		and defended nothing, while the variant was measured to differ on
		real trees: 19 findings in hydra against 1, and the extra ones
		were exactly these continuations, which are legitimate alignment.
		Sabotage said the test was empty; only diffing the two lexers
		over a real file said where.
		"""
		src = ("void f(void) {\n"
		       "\tif (a)\n"
		       "\t\tfor (int i = 0; i < n; ++i)\n"
		       "\t\t\tif (b) { c = i; break; }\n"
		       "\tif (c) {\n"
		       '\t\tmsg = fmt("one "\n'
		       '\t\t          "two")\n'
		       "\t\t      .arg(c);\n"
		       "\t}\n"
		       "}\n")
		self.assertEqual(tabs(src), [0, 1, 2, 3, 1, 2, 2, 2, 1, 0])

	def test_extern_c_block_opens_no_level(self):
		"""fuzznet, 2026-08-20: a linkage block inflated the level for the
		whole header, surfacing as scattered findings on any line carrying
		alignment -- 79 residual lines across seven headers once fixed."""
		src = ('extern "C" {\n'
		       "int fzn_send(int fd, const void *buf, size_t len,\n"
		       "             int flags);\n"
		       "}\n")
		self.assertEqual(tabs(src), [0, 0, 0, 0])

	def test_extern_c_on_a_definition_still_indents(self):
		"""hydra, 2026-08-23: the first fix marked ANY brace after the
		linkage string transparent, and 47 JNI entry points -- extern "C"
		JNIEXPORT void f(...) { ... } -- were reported at the wrong depth.
		Only a brace directly after the string opens a linkage block."""
		src = ('extern "C" JNIEXPORT void JNICALL\n'
		       "Java_x(JNIEnv *e,\n"
		       "       jlong id) {\n"
		       "\tint y = 1;\n"
		       "}\n")
		self.assertEqual(tabs(src)[3:], [1, 0])

	def test_namespace_block_opens_no_level(self):
		"""qtty, 2026-08-27: code-style.md's own worked example for this
		rule conformed when saved verbatim and reported two violations when
		a namespace was wrapped round it, nothing else changed. A namespace
		is a brace and not a level, exactly as a linkage block is, and it
		hid the same way: a flush line at column 0 is left alone, so
		namespace contents -- which every gated file writes flush, measured
		94 of 94 -- looked accepted, while any line carrying alignment
		collected a phantom tab. The trees had been converted to the tool's
		answer rather than the document's."""
		src = ("namespace N {\n"
		       "int thing_do(thing_t *t, const char *name,\n"
		       "              uint8_t *out) {\n"
		       "\tif (!t) return 1;\n"
		       "\treturn write(t, name, out,\n"
		       "\t              FLAGS);\n"
		       "}\n"
		       "}\n")
		self.assertEqual(tabs(src), [0, 0, 0, 1, 1, 1, 0, 0])

	def test_namespace_variants_all_open_no_level(self):
		"""Anonymous, nested-name and inline namespaces are the same brace.
		The name sits between the keyword and the brace and is an
		identifier, so -- unlike extern "C" -- an identifier must NOT clear
		the pending state."""
		for head in ("namespace {", "namespace a::b {", "inline namespace v1 {"):
			src = (head + "\n"
			       "void f() {\n"
			       "\tg(1,\n"
			       "\t  2);\n"
			       "}\n"
			       "}\n")
			self.assertEqual(tabs(src), [0, 0, 1, 1, 0, 0], head)

	def test_namespace_without_a_block_leaves_the_next_brace_alone(self):
		"""`using namespace std;` and `namespace x = a::b;` both name a
		namespace and open nothing. If the pending state survived the
		semicolon the NEXT brace in the file would be made transparent,
		and a whole struct body would read one level too shallow -- the
		expensive direction to be wrong in."""
		for head in ("using namespace std;", "namespace x = a::b;"):
			src = (head + "\n"
			       "struct S {\n"
			       "\tvoid f() {\n"
			       "\t\tg(1,\n"
			       "\t\t  2);\n"
			       "\t}\n"
			       "};\n")
			self.assertEqual(tabs(src), [0, 0, 1, 2, 2, 1, 0], head)

	def test_define_continuation_is_alignment_not_structure(self):
		"""fuzznet, 2026-08-14: a multi-line CHECK macro was reported as
		mis-indented because the lexer rewrote a backslash-continued
		directive's lines to the structural level around it."""
		src = ("#define CHECK(cond, msg) \\\n"
		       "\tdo { \\\n"
		       "\t\tif (!(cond)) \\\n"
		       "\t\t\tfail(msg); \\\n"
		       "\t} while (0)\n"
		       "\n"
		       "int f(void) {\n"
		       "\treturn 0;\n"
		       "}\n")
		self.assertEqual(tabs(src), [0, 1, 2, 3, 1, 0, 0, 1, 0])

	def test_raw_string_contents_are_not_code(self):
		"""hydra embeds whole JavaScript programs in raw strings; walking
		into one once produced 775 findings in four files, none real."""
		src = ('const char *js = R"( { if (x) { } } )";\n'
		       "int f(void) {\n\tg();\n}\n")
		self.assertEqual(tabs(src), [0, 0, 1, 0])

	def test_conversion_is_whitespace_only(self):
		"""The reindent proof used for every spread of the lexer fix:
		content must be identical once leading whitespace is stripped."""
		src = ('extern "C" {\n'
		       "int f(int a,\n"
		       "      int b);\n"
		       "}\n")
		out = sg.convert_c(src, 8)
		for was, now in zip(src.splitlines(), out.splitlines()):
			self.assertEqual(was.lstrip(), now.lstrip())


class Floor(unittest.TestCase):
	"""The collapse floor, redesigned 2026-08-26 after decaying to between
	22% and 80% of the real count across fourteen projects."""

	def test_fraction_passes_a_healthy_tree(self):
		self.assertFalse(sg.collapse(8, 10, {"floor": 0.5}))

	def test_fraction_fires_on_a_collapse(self):
		self.assertTrue(sg.collapse(2, 10, {"floor": 0.5}))

	def test_absolute_form_still_works(self):
		self.assertTrue(sg.collapse(1, 10, {"floor": 2}))
		self.assertFalse(sg.collapse(3, 10, {"floor": 2}))

	def test_floor_of_one_point_zero_is_refused(self):
		"""1.0 reads as the old default and would demand every raw path be
		gated; the validator refuses it rather than reinterpreting it."""
		problems = sg.type_problems({"floor": 1.0})
		self.assertTrue(any("floor" in p for p in problems))

	def test_valid_shapes_are_accepted(self):
		self.assertEqual(sg.type_problems({"floor": 0.4}), [])
		self.assertEqual(sg.type_problems({"floor": 30}), [])
		self.assertTrue(sg.type_problems({"floor": True}))

	def test_raw_of_zero_fires_before_either_shape(self):
		"""raidcfgd, 2026-08-26: `count < floor * 0` is `0 < 0`, which is
		False, so the fractional floor passed total collapse -- strictly
		weaker there than the absolute form it replaced. Zero raw is judged
		first, and both shapes must refuse it."""
		self.assertTrue(sg.collapse(0, 0, {"floor": 0.4}))
		self.assertTrue(sg.collapse(0, 0, {"floor": 1}))

	def test_floor_count_computes_files_for_both_shapes(self):
		"""The collapse message used to print the raw fraction -- "expected
		at least 0.35" -- the right number in the wrong unit. floor_count
		is the one place the threshold is computed in files."""
		self.assertEqual(sg.floor_count(10, {"floor": 0.5}), 5)
		self.assertEqual(sg.floor_count(9, {"floor": 0.35}), 3)
		self.assertEqual(sg.floor_count(10, {"floor": 4}), 4)
		self.assertEqual(sg.floor_count(0, {"floor": 0.5}), 0)


class LineRules(unittest.TestCase):
	def test_trailing_whitespace_and_space_before_tab(self):
		problems = sg.check_text("int x; \n \tint y;\n", Path("t.c"))
		kinds = {p.message for p in problems}
		self.assertTrue(any("trailing" in k for k in kinds))
		self.assertTrue(any("space before tab" in k for k in kinds))

	def test_clean_text_reports_nothing(self):
		self.assertEqual(sg.check_text("int x;\n\tint y;\n", Path("t.c"),
		                               heuristic=False), [])


class EndToEnd(unittest.TestCase):
	"""The gate as a subprocess, the way fourteen Makefiles run it."""

	def run_gate_err(self, files: dict[str, str], config: str):
		with tempfile.TemporaryDirectory() as d:
			root = Path(d)
			(root / ".style-gate.toml").write_text(config)
			for name, text in files.items():
				path = root / name
				path.parent.mkdir(parents=True, exist_ok=True)
				path.write_text(text, encoding="utf-8")
			gate = Path(__file__).resolve().parent / "style_gate.py"
			r = subprocess.run([sys.executable, str(gate), "check"],
			                   cwd=root, capture_output=True, text=True)
			return r.returncode, r.stderr

	def run_gate(self, files: dict[str, str], config: str) -> int:
		with tempfile.TemporaryDirectory() as d:
			root = Path(d)
			(root / ".style-gate.toml").write_text(config)
			for name, text in files.items():
				path = root / name
				path.parent.mkdir(parents=True, exist_ok=True)
				path.write_text(text)
			gate = Path(__file__).resolve().parent / "style_gate.py"
			return subprocess.run(
				[sys.executable, str(gate), "check"],
				cwd=root, capture_output=True).returncode

	def test_conformant_tree_passes(self):
		rc = self.run_gate({"a.c": "int f(void) {\n\treturn 0;\n}\n"},
		                   "floor = 0.1\n")
		self.assertEqual(rc, 0)

	def test_violation_fails(self):
		rc = self.run_gate({"a.c": "int f(void) {\n        return 0;\n}\n"},
		                   "floor = 0.1\n")
		self.assertNotEqual(rc, 0)

	def test_unlexable_file_reports_its_byte_finding_alone(self):
		"""situ's suite pinned this when the shadow fix overshot: a file
		the tokeniser refuses is checked as bytes, and that one finding
		must stand alone -- the later checks lean on literal exemptions
		the refused parse cannot supply. `X = (\u2014,` will not lex."""
		rc, err = self.run_gate_err(
			{"a.py": "X = (\u2014,\n"}, "floor = 0.1\nascii_only = true\n")
		self.assertNotEqual(rc, 0)
		findings = [l for l in err.splitlines() if l.startswith("a.py:")]
		self.assertEqual(len(findings), 1, findings)

	def test_ascii_finding_does_not_shadow_indent_findings(self):
		"""hembygd, 2026-08-26: check_file returned at the ASCII block,
		so one em dash suppressed every indentation finding in the file --
		371 findings across 7 files became 3347 across 48 once the dashes
		were spelled out, and the first number was quotable as measured
		fact. Both kinds must be reported together."""
		src = ("int f(void) {\n"
		       "        return 0; /* \u2014 an em dash */\n"
		       "}\n")
		rc, err = self.run_gate_err(
			{"a.c": src}, "floor = 0.1\nascii_only = true\n")
		self.assertNotEqual(rc, 0)
		# Both kinds must appear in one run's output.
		self.assertRegex(err, r"structure says|space-indented")
		self.assertRegex(err, r"ASCII|ascii|U\+2014|0xe2")

	def test_exclude_glob_matches_per_component(self):
		"""bbq-predictor, 2026-08-28: an ABI-suffixed build directory
		needed one literal exclude per ABI, and hydra carried a stale
		unsuffixed literal for weeks. A glob entry covers every ABI and
		survives the rename that strands a literal."""
		rc = self.run_gate(
			{"a.c": "int f(void) {\n\treturn 0;\n}\n",
			 "build-android-arm64-v8a/junk.c": "int    bad;\n",
			 "build-android-x86_64/junk.c": "int    bad;\n"},
			'floor = 0.1\nexclude = ["build-android-*"]\n')
		self.assertEqual(rc, 0)

	def test_exclude_literal_still_exact(self):
		"""A literal must not become a prefix match: excluding "build"
		may not swallow build-android. Proven by a violation planted
		inside build-android that must still be REPORTED -- a conformant
		fixture here would pass either way and prove nothing."""
		rc = self.run_gate(
			{"build-android/a.c": "int f(void) {\n        return 0;\n}\n",
			 "b.c": "int g(void) {\n\treturn 0;\n}\n"},
			'floor = 0.1\nexclude = ["build"]\n')
		self.assertNotEqual(rc, 0)

	def test_exclude_collapse_fails_not_passes(self):
		"""The floor's whole purpose: an exclude that swallows the sources
		must be a red run, not a clean one."""
		files = {f"src/f{i}.c": "int f%d(void) {\n\treturn %d;\n}\n" % (i, i)
		         for i in range(8)}
		rc = self.run_gate(files, 'floor = 0.5\nexclude = ["src"]\n')
		self.assertNotEqual(rc, 0)


class GitDiscovery(unittest.TestCase):
	"""discover()'s git path, against a real repository and a broken one.

	raidcfgd, 2026-08-26: a truncated .git/index -- what a full filesystem
	leaves behind, and that machine has had one -- made ls-files exit 128
	with empty stdout. Read as an empty list it handed the collapse floor
	a raw population of zero, which no floor could fire against, so the
	gate printed "0 files conform" and exited 0 and make propagated the
	pass. Both directions are held here: the healthy repository must still
	answer 0, or the refusal proves nothing about the instrument.
	"""

	def make_repo(self, root: Path) -> None:
		env = dict(os.environ,
		           GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
		run = lambda *args: subprocess.run(
			["git", "-C", str(root)] + list(args),
			env=env, capture_output=True, check=True)
		run("init", "-q")
		(root / ".style-gate.toml").write_text("floor = 0.1\n")
		(root / "a.c").write_text("int f(void) {\n\treturn 0;\n}\n")
		run("add", ".")
		run("-c", "user.name=t", "-c", "user.email=t@t.invalid",
		    "commit", "-q", "-m", "t")

	def run_gate(self, root: Path) -> subprocess.CompletedProcess:
		gate = Path(__file__).resolve().parent / "style_gate.py"
		return subprocess.run([sys.executable, str(gate), "check"],
		                      cwd=root, capture_output=True, text=True)

	def test_healthy_repository_still_passes(self):
		with tempfile.TemporaryDirectory() as d:
			root = Path(d)
			self.make_repo(root)
			out = self.run_gate(root)
			self.assertEqual(out.returncode, 0, out.stderr)

	def test_truncated_index_is_a_broken_instrument_not_a_pass(self):
		with tempfile.TemporaryDirectory() as d:
			root = Path(d)
			self.make_repo(root)
			(root / ".git" / "index").write_bytes(b"")
			out = self.run_gate(root)
			# 2, not 0 and not 1: a broken instrument is neither a clean
			# tree nor a style violation.
			self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
			self.assertIn("cannot list the files", out.stderr)
			# git's own message must survive into the report; turning it
			# into a count is what threw it away.
			self.assertIn("index file smaller than expected", out.stderr)

	# 2026-08-31, this repository. A session running as a different uid from
	# the tree's owner tripped git's dubious-ownership guard. rev-parse
	# exited 128, in_git_repo read that as "not a repository", and discover()
	# fell through to the filesystem walk -- which counts `.git` itself. Raw
	# population 1084 instead of 18, and the gate failed with "found 15
	# files, expected at least 444 -- check include/exclude in
	# .style-gate.toml". The excludes were fine; an hour was available to
	# spend on them.
	#
	# The fixture makes .git/HEAD unreadable instead of reproducing the
	# ownership case, which would need a second uid. Both leave a `.git` in
	# place and both make rev-parse exit 128 with "not a git repository",
	# which is the whole of what the caller can see.
	@unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
	def test_unreadable_repository_is_not_a_tree_without_one(self):
		with tempfile.TemporaryDirectory() as d:
			root = Path(d)
			self.make_repo(root)
			(root / ".git" / "HEAD").chmod(0o000)
			try:
				out = self.run_gate(root)
			finally:
				(root / ".git" / "HEAD").chmod(0o644)
		# 2, like the truncated index above: a broken instrument is neither
		# a clean tree nor a style violation. A 0 here is the whole fault.
		self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
		self.assertIn("will not read it", out.stderr)

	# The control, and the reason the check is `.git` rather than the exit
	# code: a tree that is genuinely not a repository exits 128 from
	# rev-parse too, with the same message, and it must still walk. That is
	# the case the fallback was built for and refusing it would break every
	# tree that has not been initialised yet.
	def test_a_tree_with_no_git_still_walks(self):
		with tempfile.TemporaryDirectory() as d:
			root = Path(d)
			(root / ".style-gate.toml").write_text("floor = 0.1\n")
			(root / "a.c").write_text("int f(void) {\n\treturn 0;\n}\n")
			out = self.run_gate(root)
		self.assertEqual(out.returncode, 0, out.stdout + out.stderr)



class BracedInitialiser(unittest.TestCase):
	"""Two indentations are legal under a brace, and the gate accepted one.

	bbq-predictor 2026-08-27, hembygd the same day in C++: an aligned
	continuation inside `= {` was rejected while the identical thing inside
	`(` was accepted. Both projects reshaped the source rather than the
	tool -- bbq-predictor rewrote a test to `QStringList() << ...` purely
	to pass -- which is the deform-the-source-to-satisfy-the-checker shape.

	The first attempt made the brace transparent so the aligned form was
	the expected one. It passed every fixture and produced 764 findings
	across eleven trees, because the OTHER form is equally legal and
	equally present: raidcfgd indents its brace continuations by a tab.
	Nothing structural distinguishes them; the choice is the author's.

	So the gate accepts both, and this class pins both plus the cases the
	change must not touch.
	"""

	def gate(self, body):
		return self.run_gate({"a.c": body}, "floor = 0.1\n")

	run_gate = None		# bound below, to reuse EndToEnd's helper

	def test_an_aligned_brace_continuation_is_accepted(self):
		self.assertEqual(self.gate(
			"void f(void)\n{\n\tconst int a[] = {1,\n\t                 2};\n}\n"), 0)

	def test_a_designated_initialiser_aligns_the_same_way(self):
		self.assertEqual(self.gate(
			"void f(void)\n{\n\tstruct s v = {.x = 1,\n\t              .y = 2};\n}\n"), 0)

	# raidcfgd's form. The first attempt broke exactly this, in 764 places.
	def test_a_tab_indented_brace_continuation_is_still_accepted(self):
		self.assertEqual(self.gate(
			"void f(void)\n{\n\tconst int a[] = {1,\n\t\t2};\n}\n"), 0)

	# The control the first attempt chose, and it was the wrong one: it is
	# drawn from the construct being IMITATED rather than the one being
	# changed, so it could not catch a regression in brace handling. Kept
	# because it must still hold, not because it discriminates.
	def test_a_paren_continuation_is_unaffected(self):
		self.assertEqual(self.gate(
			"void f(void)\n{\n\tg(1,\n\t  2);\n}\n"), 0)

	# The one that stops this being a general loosening. Accepting "either
	# of two levels" must not become "any level": a continuation one level
	# deeper than the indented form is still wrong and still reported.
	def test_a_continuation_deeper_than_either_form_is_still_reported(self):
		self.assertNotEqual(self.gate(
			"void f(void)\n{\n\tconst int a[] = {1,\n\t\t\t2};\n}\n"), 0)

	# A brace with nothing after it opens an ordinary block and is not
	# dual: its body has one right answer, and marking every brace would
	# switch a level of depth checking off inside every function.
	#
	# The fixture has to be built so that the WRONG version would differ,
	# which is the lesson the first attempt paid for. Dual acceptance is
	# "have == want - 1", so a body three tabs deep never exercises it --
	# an earlier version of this test used one and passed against a gate
	# that marked every brace, proving nothing. This body is one tab plus
	# alignment: shallow by exactly one, and carrying columns enough to be
	# reported at all rather than falling into the flush-line branch.
	def test_a_brace_with_no_content_after_it_is_not_dual(self):
		src = ("void f(void)\n{\n\tconst int a[] = {\n"
		       "\t                 1,\n\t};\n}\n")
		self.assertNotEqual(self.gate(src), 0)

	# The construct that produced the original report, rather than one
	# built from its description -- reduced in hembygd from
	# src/qt/gamewidget.cpp's facing_tile() and playscript.cpp's V2i,
	# both of which were rewritten as two scalars to get past the old
	# gate. `V2i` is a real type there, so this is the shape a C++ author
	# writes rather than the shape a fault description implies.
	#
	# **It carries its own control and that is why it is kept whole.**
	# The bare `{ }` scope block underneath is the other half of the
	# brace-handling fault -- the one that LOSES a level -- which neither
	# tree has ever managed to reproduce. It passed the old gate and
	# passes this one, in the same file and the same invocation as the
	# initialiser that did not. So one run says both things: the aligned
	# continuation is accepted now, and a bare block was not disturbed
	# getting there. The synthetic test above pins the second property
	# from the other direction, by sabotage; this pins it by construction.
	def test_the_construct_that_produced_the_report(self):
		self.assertEqual(self.gate(
			"void f(void)\n"
			"{\n"
			"\tV2i v = { a + b,\n"
			"\t          c + d };\n"
			"\t{\n"
			"\t\tint x = 1;\n"
			"\t\t(void)x;\n"
			"\t}\n"
			"}\n"), 0)


BracedInitialiser.run_gate = EndToEnd.run_gate


class LambdaInBracelessBody(unittest.TestCase):
	"""A lambda took a level belonging to a loop it was nested inside.

	qtty 2026-08-27, immediately after the closing-brace fix. Correctly
	tabbed code was rejected, and the discriminating control is that the
	same lambda inside a BRACED loop conformed -- so the trigger was the
	braceless level, not the lambda.

	`{` consumed a pending braceless body on the reasoning that the brace
	takes the level that body would have had. That is right for a brace
	that IS the body and wrong for one opening an expression inside it: by
	the time the lambda opens, the inner block has already taken the level,
	and what is left pending belongs to the statement the whole block is
	part of.

	The first attempt conditioned the decrement on `await_body`, which
	fixed this and broke aligned continuations -- 179 findings across
	twelve trees, because it also moved the case where the lambda IS the
	braceless body's statement, which every tree writes the other way. The
	frame's own floor separates the two: consume a body opened inside this
	block, never one inherited from around it.
	"""

	def gate(self, src: str) -> int:
		return self.run_gate({"a.cpp": src}, "floor = 0.1\n")

	def test_the_fault_correct_code_is_accepted(self):
		src = ("void f(int n)\n{\n"
		       "\tfor (int y = 0; y < n; ++y)\n"
		       "\t\tfor (int x = 0; x < n; ++x) {\n"
		       "\t\t\tauto g = [&] {\n"
		       "\t\t\t\th();\n"
		       "\t\t\t};\n"
		       "\t\t\tk();\n"
		       "\t\t}\n}\n")
		self.assertEqual(self.gate(src), 0)

	def test_the_shape_the_bug_demanded_is_now_rejected(self):
		"""qtty's real construct, as the bug deformed it.

		Reduced from src/graphics/graphics.cpp, which is where this was
		found. The lambda's body sits a level below its own statement and
		the closing `};` a level below that -- dedented past the lines
		either side of it, which is the fault's fingerprint and not
		something anyone writes on purpose.

		It has to be the real shape. An invented one written in pure tabs
		is accepted whatever the lexer thinks, because a line inside an
		unterminated statement is left where it stands; only the spaces
		here make the gate re-level it and so make this a test at all.
		"""
		src = ("void f(int n)\n{\n"
		       "\tfor (int cy = 0; cy < n; ++cy)\n"
		       "\t\tfor (int cx = 0; cx < n; ++cx) {\n"
		       "\t\t\tconst int X = cx;\n"
		       "\t\t\tauto sample = [&](double fy) -> int {\n"
		       "\t\t\t    int sx = 1;\n"
		       "\t\t\t    return sx;\n"
		       "\t\t    };\n"
		       "\t\t\tconst int top = sample(0.25);\n"
		       "\t\t}\n}\n")
		self.assertNotEqual(self.gate(src), 0)

	def test_the_braced_control_still_conforms(self):
		"""qtty's control: the identical lambda under a BRACED loop.

		It conformed before the fix and must still, or the fix has moved
		something other than the braceless case.
		"""
		src = ("void f(int n)\n{\n"
		       "\tfor (int y = 0; y < n; ++y) {\n"
		       "\t\tauto g = [&] {\n"
		       "\t\t\th();\n"
		       "\t\t};\n"
		       "\t\tk();\n"
		       "\t}\n}\n")
		self.assertEqual(self.gate(src), 0)

	def test_a_lambda_that_is_the_braceless_body_is_unmoved(self):
		"""The case the first attempt broke, in the shape twelve trees write.

		The lambda's call IS the braceless `if`'s body, so its brace does
		take that level, and the outer close sits at the `if`'s own depth.
		This is what produced 179 findings when it moved; it must not.
		"""
		src = ("void f(void)\n{\n"
		       "\tif (!e())\n"
		       "\t\tsingle(13000, [&] {\n"
		       "\t\t  const int v = 1;\n"
		       "\t\t  use(v);\n"
		       "\t});\n}\n")
		self.assertEqual(self.gate(src), 0)

	def test_a_brace_that_is_the_braceless_body_still_takes_its_level(self):
		"""The rule the fix must not undo, from the shipped fix's own case."""
		src = ("void f(int n)\n{\n"
		       "\tfor (int i = 0; i < n; i++)\n"
		       "\t\tif (i) {\n"
		       "\t\t\tg();\n"
		       "\t\t\tg();\n"
		       "\t\t}\n}\n")
		self.assertEqual(self.gate(src), 0)

	def test_an_aligned_continuation_under_a_braceless_body(self):
		"""What the await_body attempt broke: a continued argument."""
		src = ("void f(void)\n{\n\tif (a)\n"
		       "\t\tg(\"x\"\n\t\t  \"y\");\n}\n")
		self.assertEqual(self.gate(src), 0)

	def test_a_lambda_argument_with_no_braceless_level_anywhere(self):
		"""No pending body at all: the decrement was never in play."""
		src = ("void f(void)\n{\n\tsingle(1, [&] {\n"
		       "\t\tg();\n\t});\n}\n")
		self.assertEqual(self.gate(src), 0)


LambdaInBracelessBody.run_gate = EndToEnd.run_gate


class UnderIndentation(unittest.TestCase):
	"""The gate never reported a line with too FEW tabs.

	Found 2026-08-27, closed 2026-09-01. The converter re-expresses excess
	tabs as alignment and never ADDS indentation, so a line short of the
	structural depth came back unchanged and compared equal to itself. A
	file with no tabs at all reported that it conformed.

	Closing it needed the switch model fixed first, because the blindness
	was hiding three faults in it: a braced `case` counted its brace AND
	its label level, this workspace's majority label style was the one the
	model did not implement, and a comment introducing a label was held to
	the body's level. Naively reporting short lines gave 6332 findings
	across seventeen trees; with the model corrected, 396.
	"""

	def gate(self, src: str, cfg: str = "floor = 0.1\n") -> int:
		return self.run_gate({"a.cpp": src}, cfg)

	# --- the blindness itself, which is what this closes -------------
	def test_a_short_line_is_reported(self):
		self.assertNotEqual(self.gate(
			"void f(void)\n{\n\tif (a) {\n\tg();\n\t}\n}\n"), 0)

	def test_a_file_with_no_tabs_at_all_is_reported(self):
		"""It reported that it conformed. Nothing else in the suite asks."""
		self.assertNotEqual(self.gate(
			"void f(void)\n{\nif (a) {\ng();\n}\n}\n"), 0)

	def test_a_whole_block_short_by_one_is_reported(self):
		self.assertNotEqual(self.gate(
			"void f(void)\n{\n\tif (a) {\n\t\tif (b) {\n"
			"\t\tg();\n\t\t}\n\t}\n}\n"), 0)

	def test_correct_code_stays_clean(self):
		self.assertEqual(self.gate(
			"void f(void)\n{\n\tif (a) {\n\t\tg();\n\t}\n}\n"), 0)

	# --- the switch model the blindness was hiding -------------------
	def test_a_braced_case_body_is_one_level_below_its_label(self):
		"""Not two. The brace and `case_extra` were both counted.

		Invisible before, because counting twice can only ask for MORE
		indentation than the file has.
		"""
		self.assertEqual(self.gate(
			"void f(int a)\n{\n\tswitch (a) {\n\t\tcase 1: {\n"
			"\t\t\tg();\n\t\t}\n\t}\n}\n"), 0)

	def test_labels_at_the_switch_level_conform(self):
		"""2815 switches in this workspace, against 108 the other way."""
		self.assertEqual(self.gate(
			"void f(int a)\n{\n\tswitch (a) {\n\tcase 1:\n"
			"\t\tg();\n\t\tbreak;\n\t}\n}\n"), 0)

	def test_labels_one_deeper_conform_too(self):
		"""Both styles are legal; the model learns, it does not rule."""
		self.assertEqual(self.gate(
			"void f(int a)\n{\n\tswitch (a) {\n\t\tcase 1:\n"
			"\t\t\tg();\n\t\t\tbreak;\n\t}\n}\n"), 0)

	def test_a_switch_indented_two_ways_is_reported(self):
		"""Learning a style is not standing down: the switch must keep it."""
		self.assertNotEqual(self.gate(
			"void f(int a)\n{\n\tswitch (a) {\n\tcase 1:\n\t\tg();\n"
			"\t\tbreak;\n\t\tcase 2:\n\t\tg();\n\t\tbreak;\n"
			"\t}\n}\n"), 0)

	def test_a_comment_introducing_a_label_sits_with_the_label(self):
		"""157 lines in one qtty file were reported for this alone."""
		self.assertEqual(self.gate(
			"int f(int m)\n{\n\tswitch (m) {\n"
			"\t// why the next one is what it is\n"
			"\tcase 1:\n\t\treturn 1;\n\t}\n}\n"), 0)

	def test_a_comment_before_the_first_label_does_not_crash(self):
		"""It did. The learning pass had nothing to add yet and added None.

		The sweep that should have caught it counted findings by grepping,
		and a traceback prints none -- so two trees reported zero and read
		as clean. The liveness check is a file count, not an empty result.
		"""
		self.assertEqual(self.gate(
			"int f(int m)\n{\n\tswitch (m) {\n\t// a leading comment\n"
			"\tcase 1:\n\t\treturn 1;\n\t}\n}\n"), 0)

	# --- labels on a block rather than a switch ----------------------
	def test_access_specifiers_conform_either_way(self):
		"""732 level with the members, 642 one out."""
		self.assertEqual(self.gate(
			"class X {\npublic:\n\tX();\nprivate:\n\tint m_a;\n};\n"), 0)
		self.assertEqual(self.gate(
			"class Y {\n\tpublic:\n\tY();\n};\n"), 0)

	def test_goto_labels_conform_either_way(self):
		"""3689 level with the statement, 48 one out."""
		self.assertEqual(self.gate(
			"int f(void)\n{\n\tint r = 0;\n\tgoto out;\nout:\n"
			"\treturn r;\n}\n"), 0)
		self.assertEqual(self.gate(
			"int g(void)\n{\n\tint r = 0;\n\tgoto out;\n\tout:\n"
			"\treturn r;\n}\n"), 0)

	def test_a_member_short_of_the_class_level_is_still_reported(self):
		"""The label may move. What follows it may not."""
		self.assertNotEqual(self.gate(
			"class X {\npublic:\n\tX();\nvoid f();\n};\n"), 0)


UnderIndentation.run_gate = EndToEnd.run_gate


class PythonStructuralDepth(unittest.TestCase):
	"""Tab-indented Python got no structural check at all.

	`convert_python` measured a line's indent with `line.lstrip(" ")`,
	which counts spaces and ignores tabs. Every tab-indented line therefore
	had a column count of zero and was passed through untouched -- so the
	converter re-expressed a file still written in spaces and inspected
	nothing in a converted one. Every Python file in this workspace is
	converted, so the structural half was inert wherever it ran.

	What made it look alive is that a sabotaged file WAS caught: an
	inconsistent indent stops the file parsing, and the syntax check
	reports that. A block moved uniformly stays valid Python and passed --
	26 real lines of tool/sync.py, moved a tab, reported nothing.

	The check is held to STATEMENT rows. Python fixes a statement's
	indentation and a continuation's is free, which is not a limitation
	worked around but the language: see the limit pinned at the bottom.
	"""

	def gate(self, src: str) -> int:
		return self.run_gate({"a.py": src}, "floor = 0.1\nindent_width = 4\n")

	def test_a_block_over_indented_as_a_whole_is_reported(self):
		"""Valid Python, and the case the sabotage control was built on."""
		self.assertNotEqual(self.gate(
			"def f(a):\n\tif a:\n\t\t\tx = 1\n\t\t\treturn x\n"
			"\treturn 0\n"), 0)

	def test_a_statement_under_indented_is_reported(self):
		self.assertNotEqual(self.gate("def f(a):\n\tif a:\n\treturn 1\n"), 0)

	def test_correct_code_stays_clean(self):
		self.assertEqual(self.gate(
			"def f(a):\n\tif a:\n\t\treturn 1\n\treturn 0\n"), 0)

	def test_space_before_tab_is_still_caught(self):
		self.assertNotEqual(self.gate(
			"def f(a, b):\n\treturn g(a,\n \t       b)\n"), 0)

	# --- continuations, which this must NOT hold to a depth -----------
	def test_an_aligned_continuation_conforms(self):
		self.assertEqual(self.gate(
			"def f(a, b):\n\treturn g(a,\n\t         b)\n"), 0)

	def test_a_hanging_indent_conforms(self):
		"""20998 continuation rows in this workspace are hung one tab."""
		self.assertEqual(self.gate(
			"def f(a, b):\n\treturn g(a,\n\t\tb)\n"), 0)

	def test_a_deeper_hanging_indent_conforms(self):
		"""2847 are hung two, 424 three, 64 four. None of them is wrong."""
		self.assertEqual(self.gate(
			"def f(a, b):\n\treturn g(a,\n\t\t\tb)\n"), 0)

	def test_a_nested_literal_conforms(self):
		"""Nesting varies the tab count WITHIN one logical line, which is
		why per-logical-line consistency cannot be the rule either."""
		self.assertEqual(self.gate(
			'X = {\n\t"k": {\n\t\t"a": 1,\n\t},\n}\n'), 0)

	def test_a_comment_inside_a_continuation_is_left_alone(self):
		"""It has no structural depth, so its own column decides -- and
		deciding means leaving it, not dividing its column by the width.
		Dividing reported 43 lines across four trees, all of them right."""
		self.assertEqual(self.gate(
			"def f(s):\n\treturn [e for e in s\n\t        if e\n"
			"\t        # why this one is excluded\n\t        and e.ok]\n"), 0)

	def test_alignment_carried_in_tabs_is_NOT_caught(self):
		"""The limit, pinned, because the entry that asked for this
		expected it to be the whole job.

		A continuation whose alignment was converted to tabs -- what
		`unexpand --first-only` does -- renders correctly at the width it
		was made at and moves at every other. It cannot be told apart from
		a hanging indent by structure, because the shapes are the same
		ones: measured over 288 files, +1/+2/+3/+4 tabs occur thousands of
		times each, with and without trailing spaces, all legitimate. If
		this ever starts failing, something has found a discriminator and
		the entry in project.md should be re-read before it is celebrated.
		"""
		self.assertEqual(self.gate(
			"def f(a, b):\n\treturn g(a,\n\t\t\t     b)\n"), 0)


PythonStructuralDepth.run_gate = EndToEnd.run_gate


class RustIsGated(unittest.TestCase):
	"""Rust was in no suffix list, so nothing looked at it.

	Raised by situ 2026-08-27, closed 2026-09-01. `.rs` was left out
	because the tool has no Rust parser: the column rule cannot tell a
	string literal from code and reported a `--help` text inside one as
	space-indented -- 118 findings in netcfgd when the entry was written,
	120 today, 106 of them in a single literal.

	That was right about the column rule and wrong to drop the file. The
	note it replaced said Rust was covered anyway by `rustfmt` with
	`hard_tabs = true`, which is true in netcfgd and false in situ -- one
	`runtime/rust/situ_rt.rs`, no rustfmt.toml, no `cargo fmt` in its
	build. A claim about coverage had been generalised from the tree that
	measured it.

	So Rust gets every check that is exact without a parser and not the one
	that needs one. It adopted with no backlog: zero findings on netcfgd's
	145 files and situ's one, and the inspected count rose 260 -> 405.
	"""

	def gate(self, src: str, name: str = "a.rs") -> int:
		return self.run_gate({name: src}, "floor = 0.1\nascii_only = true\n")

	def test_clean_rust_passes(self):
		self.assertEqual(self.gate("fn main() {\n\tlet x = 1;\n}\n"), 0)

	def test_rust_is_inspected_at_all(self):
		"""The whole finding: it was in no list, so nothing read it."""
		self.assertNotEqual(self.gate("fn main() {\n\tlet x = 1;   \n}\n"), 0)

	def test_space_before_tab_is_caught(self):
		self.assertNotEqual(self.gate("fn main() {\n \tlet x = 1;\n}\n"), 0)

	def test_missing_final_newline_is_caught(self):
		self.assertNotEqual(self.gate("fn main() {\n\tlet x = 1;\n}"), 0)

	def test_non_ascii_is_caught(self):
		self.assertNotEqual(self.gate(
			"fn main() {\n\t// an em dash \u2014 here\n}\n"), 0)

	def test_the_column_rule_is_stood_down(self):
		"""The deliberate miss, pinned.

		A space-indented Rust line is NOT reported, because the rule that
		would report it cannot tell this from the inside of a string
		literal -- which is where 106 of netcfgd's 120 findings were. If
		this starts failing, someone has taught the tool to lex Rust and
		should say so here.
		"""
		self.assertEqual(self.gate("fn main() {\n    let x = 1;\n}\n"), 0)

	def test_usage_text_in_a_literal_is_not_a_finding(self):
		self.assertEqual(self.gate(
			'fn main() {\n\tlet h = "usage:\\n    -v  verbose\\n";\n}\n'), 0)


RustIsGated.run_gate = EndToEnd.run_gate


class DocsModeReportsWhatItRead(unittest.TestCase):
	"""`docs` passed on a document it had never opened, and named it.

	`check_docs` returned an empty problem list when doc_file was absent,
	and main() reads empty as success -- so the mode printed "project.md
	says nothing twice and names no missing file" about a project.md that
	did not exist. Not a bare "no findings": a positive sentence about a
	named artifact, which is the reassuring costume rather than the quiet
	one.

	Signalled from fuzzypickles 2026-09-01, reproduced against a directory
	holding only a .style-gate.toml, and swept here: all seventeen trees
	have their doc_file present, so it was latent everywhere and lying
	nowhere.

	The second half is the population. `check` prints its file count and
	refuses a collapsed list; `docs` printed a verdict with no count at
	all, so if doc_paths() ever stopped matching, the mode would inspect
	nothing and print the same sentence unchanged.
	"""

	def docs(self, files: dict[str, str]) -> tuple[int, str]:
		with tempfile.TemporaryDirectory() as d:
			root = Path(d)
			for name, text in files.items():
				(root / name).parent.mkdir(parents=True, exist_ok=True)
				(root / name).write_text(text, encoding="utf-8")
			gate = Path(__file__).resolve().parent / "style_gate.py"
			r = subprocess.run([sys.executable, str(gate), "docs"], cwd=root,
			                   capture_output=True, text=True, timeout=120)
			return r.returncode, r.stdout + r.stderr

	def test_a_missing_document_is_refused(self):
		"""The whole finding: this used to pass, and name the file."""
		rc, out = self.docs({".style-gate.toml": "floor = 0.1\n"})
		self.assertNotEqual(rc, 0, out)
		self.assertIn("no such file", out)

	def test_a_missing_document_is_not_called_clean(self):
		"""The words matter here more than the exit code, because the
		sentence is what a reader takes away."""
		_, out = self.docs({".style-gate.toml": "floor = 0.1\n"})
		self.assertNotIn("says nothing twice", out)

	def test_a_present_document_still_passes(self):
		rc, out = self.docs({".style-gate.toml": "floor = 0.1\n",
		                     "project.md": "# One\n\nsome prose\n"})
		self.assertEqual(rc, 0, out)
		self.assertIn("says nothing twice", out)

	def test_the_verdict_carries_a_population(self):
		"""A verdict with no count cannot tell a clean document from one
		nothing looked at -- which is the argument `check` already makes
		one mode over, with its file count and its floor."""
		_, out = self.docs({".style-gate.toml": "floor = 0.1\n",
		                    "project.md": "# One\n## Two\n### Three\n"})
		self.assertIn("3 heading(s)", out)

	def test_the_population_moves_with_the_document(self):
		"""Pinning the half that would otherwise rot silently: if the count
		were a constant, or the extractor stopped matching, this is the
		test that notices."""
		_, few = self.docs({".style-gate.toml": "floor = 0.1\n",
		                    "project.md": "# One\n"})
		_, many = self.docs({".style-gate.toml": "floor = 0.1\n",
		                     "project.md": "# One\n## Two\n### Three\n#### Four\n"})
		self.assertIn("1 heading(s)", few)
		self.assertIn("4 heading(s)", many)

	def test_a_repeated_heading_is_still_reported(self):
		"""The rule the mode exists for, unmoved by the fix."""
		rc, out = self.docs({".style-gate.toml": "floor = 0.1\n",
		                     "project.md": "# One\n\n# One\n"})
		self.assertNotEqual(rc, 0, out)
		self.assertIn("heading repeats", out)

	# The missing-file rule had no test at all until 2026-09-05, found by
	# respec bringing the gate under a sabotage harness and reported here:
	# blinding the report left this suite green. Their measurement did not
	# transfer unaltered -- of the seven blinding mutations tried at the
	# source, five were already caught -- but this one and the interior
	# carriage return below were real, and are theirs.

	def test_a_document_naming_a_missing_file_is_refused(self):
		"""Reaching this rule takes three things at once, and a fixture
		missing any of them passes while proving nothing: the path must
		sit in a TABLE ROW, it must contain a slash, and its directory
		must exist -- a token whose parent does not is read as a layout.
		The first fixture written here satisfied none of them and went
		green; the path count in the verdict is what said so, which is
		the argument for printing a population rather than a verdict."""
		rc, out = self.docs({
			".style-gate.toml": "floor = 0.1\n",
			"sub/present.md": "here\n",
			"project.md": "# One\n\n| file | note |\n|---|---|\n"
			              "| `sub/gone.md` | not there |\n",
		})
		self.assertNotEqual(rc, 0, out)
		# The finding NAMES the token, which is the proof it reached the
		# extractor. The path count cannot serve here: it is printed with
		# the verdict, and a run that finds something prints findings
		# instead -- so the count is the tell for the passing case below
		# and the named token is the tell for this one.
		self.assertIn("names a missing file: sub/gone.md", out)

	def test_a_path_under_a_missing_directory_is_read_as_a_layout(self):
		"""The guard's other half, pinned so it is a decision rather than
		a surprise. The count proves the token was extracted and then
		deliberately not reported, which is what separates this from a
		fixture the extractor simply never saw."""
		rc, out = self.docs({
			".style-gate.toml": "floor = 0.1\n",
			"project.md": "# One\n\n| file | note |\n|---|---|\n"
			              "| `nowhere/thing.md` | a sketch |\n",
		})
		self.assertIn("1 path(s)", out)
		self.assertEqual(rc, 0, out)


class CarriageReturnIsActuallyChecked(unittest.TestCase):
	"""The carriage-return rule could never fire, in any language.

	`check_text` iterated `text.splitlines()`, which consumes the "\r" of a
	"\r\n" as part of the line ending, so `if "\r" in line` was testing a
	string the carriage return had already been removed from. A CRLF file
	passed clean and the check read as live for as long as it has existed.

	Found 2026-09-01 while adding Rust, by sabotaging each check in turn to
	watch it fail -- and this one did not. Nothing in this workspace has a
	CRLF file, so no tree could have caught it by being wrong.
	"""

	def gate(self, data: bytes, name: str = "a.c") -> int:
		with tempfile.TemporaryDirectory() as d:
			root = Path(d)
			(root / ".style-gate.toml").write_text("floor = 0.1\n")
			(root / name).write_bytes(data)
			gate = Path(__file__).resolve().parent / "style_gate.py"
			return subprocess.run([sys.executable, str(gate), "check"],
			                      cwd=root, capture_output=True).returncode

	def test_crlf_in_c_is_reported(self):
		self.assertNotEqual(self.gate(b"int main(void) {\r\n\treturn 0;\n}\n"), 0)

	def test_crlf_in_python_is_reported(self):
		self.assertNotEqual(self.gate(b"def f():\r\n\treturn 1\n", "a.py"), 0)

	def test_crlf_in_rust_is_reported(self):
		self.assertNotEqual(self.gate(b"fn main() {\r\n\tlet x = 1;\n}\n", "a.rs"), 0)

	def test_an_interior_carriage_return_is_reported(self):
		"""The two carriage-return rules are not one rule twice. The
		line-ending check REMOVES the byte it reports, so that trailing
		whitespace cannot report the same character under a name that
		hides what it is -- which leaves a return in the MIDDLE of a line
		visible only to the second rule. Blinding that second rule left
		the suite green until this was written."""
		self.assertNotEqual(
			self.gate(b"int main(void) {\n\treturn\r0;\n}\n"), 0)

	def test_unix_line_endings_pass(self):
		self.assertEqual(self.gate(b"int main(void) {\n\treturn 0;\n}\n"), 0)

	def test_a_crlf_line_is_not_also_called_trailing_whitespace(self):
		"""One fault, one name. The carriage return is consumed before the
		trailing-whitespace rule sees the line, or every CRLF line would be
		reported twice, once under a name that hides what it is."""
		with tempfile.TemporaryDirectory() as d:
			root = Path(d)
			(root / ".style-gate.toml").write_text("floor = 0.1\n")
			(root / "a.c").write_bytes(b"int main(void) {\r\n\treturn 0;\n}\n")
			gate = Path(__file__).resolve().parent / "style_gate.py"
			r = subprocess.run([sys.executable, str(gate), "check"], cwd=root,
			                   capture_output=True, text=True)
		self.assertIn("carriage return", r.stderr)
		self.assertNotIn("trailing whitespace", r.stderr)

class CommitMsgHook(unittest.TestCase):
	"""The commit-msg hook as git runs it, via sh, on synthetic messages.

	raidcfgd, 2026-08-26: the hook read line 1 of the file as the subject,
	but git's subject is the first line left after cleanup strips comments
	and leading blank lines -- so a commit.template opening with either
	switched every column check off, silently and for every commit made
	under it. A 96-column subject was accepted.
	"""

	# The hook sits in two places, and this suite now runs in both. At the
	# source it is `tool/commit-msg`, beside the gate; in every project it
	# is synced to `tool/hooks/commit-msg`, because that is where a tree
	# installs from. Resolved rather than assumed: pointing at one spelling
	# made all seven cases below fail in a copy, which is how this was
	# found -- the suite was run from a tree shaped like a synced project
	# before it was spread to sixteen of them.
	#
	# Falling back to the source spelling rather than skipping is
	# deliberate. A suite that quietly skips when it cannot find the thing
	# it tests reports the same silence as one that found nothing wrong,
	# and the whole reason this file travels is to refuse that.
	HOOK = next((c for c in (Path(__file__).resolve().parent / "commit-msg",
	                         Path(__file__).resolve().parent / "hooks" / "commit-msg")
	             if c.is_file()), Path(__file__).resolve().parent / "commit-msg")

	def run_hook(self, message: str) -> subprocess.CompletedProcess:
		with tempfile.NamedTemporaryFile("w", suffix=".txt",
		                                 delete=False) as handle:
			handle.write(message)
			name = handle.name
		try:
			return subprocess.run(["sh", str(self.HOOK), name],
			                      capture_output=True, text=True)
		finally:
			os.unlink(name)

	def test_leading_blank_lines_do_not_hide_the_subject(self):
		"""Proven at the boundary rather than by acceptance alone: the
		real subject at exactly 75 columns passes and at 76 is refused,
		which only a hook reading the right line can do -- the old one
		measured the blank on line 1 and accepted both."""
		subject = "core: " + "x" * 69		# exactly 75 columns
		ok = self.run_hook("\n\n" + subject + "\n\nsome body prose.\n")
		self.assertEqual(ok.returncode, 0, ok.stderr)
		refused = self.run_hook("\n\n" + subject + "y\n\nsome body prose.\n")
		self.assertEqual(refused.returncode, 1, refused.stderr)
		self.assertIn("subject is 76 columns", refused.stderr)

	def test_leading_comment_does_not_switch_the_hook_off(self):
		"""The `#` on line 1 used to be a quiet exit 0 -- the whole
		incident. A comment above a valid message must be skipped, not
		obeyed."""
		out = self.run_hook("# a template comment\ncore: fix the check\n"
		                    "\nsome body prose.\n")
		self.assertEqual(out.returncode, 0, out.stderr)
		refused = self.run_hook("# a template comment\ncore: " + "x" * 70
		                        + "\n\nsome body prose.\n")
		self.assertEqual(refused.returncode, 1, refused.stderr)
		self.assertIn("subject is 76 columns", refused.stderr)

	def test_wrapped_subject_still_refused(self):
		"""fuzznet's finding must survive the fix: a subject wrapped onto
		a second line before the blank is still joined and refused."""
		out = self.run_hook("core: fix the\nlength check\n\nsome body.\n")
		self.assertEqual(out.returncode, 1, out.stderr)
		self.assertIn("wrapped", out.stderr)

	def test_subject_running_into_body_still_refused(self):
		"""No blank line after the subject reads as a wrapped subject,
		because to git it is one."""
		out = self.run_hook("core: fix the check\nthe body follows.\n")
		self.assertEqual(out.returncode, 1, out.stderr)
		self.assertIn("wrapped", out.stderr)

	# The vendor check's spared names had no test at all until 2026-09-05,
	# when a fourth was added: three exemptions had been argued into the
	# hook one incident at a time and nothing held any of them. These cover
	# the four together with the refusals they must not have widened,
	# because an exemption is only safe in company -- each case below
	# passes against a hook that spares everything, and only the refusals
	# say the scrub is still narrow.

	def test_the_spared_names_pass(self):
		"""All four, in one message. `claude-<digits>` is the per-uid
		scratch directory under /tmp: a commit saying which directory
		held eleven gigabytes could not name it before this."""
		for name in (".claude/settings.json", "CLAUDE.md",
		             "claude-guidelines", "/tmp/claude-1001",
		             "claude-1000 and claude-1001 both"):
			out = self.run_hook("core: a change\n\nit names %s here.\n"
			                    % name)
			self.assertEqual(out.returncode, 0,
			                 "%s was refused: %s" % (name, out.stderr))

	def test_the_bare_vendor_word_is_still_refused(self):
		"""The control. Every case above passes against a hook whose
		scrub forgives everything, so without this the suite would go on
		passing after the check had been widened into uselessness."""
		out = self.run_hook("core: a change\n\nclaude wrote this bit.\n")
		self.assertEqual(out.returncode, 1, out.stderr)
		self.assertIn("tooling reference", out.stderr)

	def test_a_persons_trailer_is_accepted(self):
		"""The boundary the vendor cases cannot show, reported by beerssh
		2026-09-05 after their own control confused them for a minute.

		Every attribution case here names the vendor, so together they
		establish that a VENDOR trailer is refused and say nothing about
		trailers as such -- and a reader who takes one as "sign-offs are
		refused" is wrong in the direction that matters, because
		`CLAUDE.md` says a person's trailer is theirs to write and the
		hook never claimed otherwise. Without this case the controls
		cannot fail the way the thing they control for fails."""
		for trailer in ("Co-Authored-By: Jane Roe <jane@example.invalid>",
		                "Signed-off-by: Jane Roe <jane@example.invalid>"):
			out = self.run_hook("core: a change\n\nbody.\n\n%s\n" % trailer)
			self.assertEqual(out.returncode, 0,
			                 "%s was refused: %s" % (trailer, out.stderr))

	def test_a_spared_name_does_not_carry_a_sign_off_past_the_check(self):
		"""The case that would show the fourth exemption had opened a
		bypass: one message holding both the newly spared path and a
		vendor sign-off. beerssh's, and stronger than testing either
		alone, which is all this suite did before."""
		out = self.run_hook("core: a change\n\nit names /tmp/claude-1001 "
		                    "here.\n\nCo-Authored-By: Claude "
		                    "<noreply@example.invalid>\n")
		self.assertEqual(out.returncode, 1, out.stderr)

	def test_an_attribution_trailer_is_still_refused(self):
		"""And it is refused for a reason no scrub can reach: the
		attribution check reads the raw message rather than the scrubbed
		prose, so adding a name above cannot let a sign-off through."""
		out = self.run_hook("core: a change\n\nbody.\n\n"
		                    "Co-Authored-By: Claude <noreply@example.invalid>\n")
		self.assertEqual(out.returncode, 1, out.stderr)


class ReportsItsScope(unittest.TestCase):
	"""The success line must not claim more or less than the gate checks.

	It used to end "except under-indentation, which is not checked", and
	that was honest: the converter never ADDS indentation, so a line short
	of its depth came back unchanged and a file with no tabs at all passed
	while the gate printed that its files "conform". Rule 1 says report
	what was actually verified.

	Closed 2026-09-01. The caveat goes with the gap -- a limit that has
	been lifted and is still advertised misleads in the other direction,
	and a reader who believes it will not trust a finding the gate makes.
	"""

	def test_the_fixer_still_never_adds_indentation(self):
		"""Unchanged, and deliberate: `fix` must not reindent a tree.

		Its proof is that expanding leading tabs reproduces the original
		file, which adding a level would break by design. So the gap was
		never closed by making the converter write the missing tabs -- it
		records the level it declined to write, and the check reads that.
		"""
		src = "void f(void) {\n\tif (a) {\n\tg();\n\t}\n}\n"
		self.assertEqual(tabs(src), [0, 1, 1, 1, 0])

	def test_over_indentation_is_caught(self):
		src = "void f(void) {\n\tif (a) {\n\t\t\t\tg();\n\t}\n}\n"
		self.assertNotEqual(tabs(src)[2], 4)

	def test_the_success_line_claims_both_directions_now(self):
		"""Asserted on the gate's OUTPUT, not on its source.

		The first version grepped the source for `files conform"` and
		failed whether or not the message had been fixed, because two
		comments quote the old wording while recording an incident. A
		probe matching the wrong thing -- and it was only caught because
		the sabotage that was supposed to prove it discriminates showed
		the same failure the healthy tree already had. Establish the
		control passes BEFORE breaking it.
		"""
		gate = Path(__file__).resolve().parent / "style_gate.py"
		with tempfile.TemporaryDirectory() as tmp:
			root = Path(tmp)
			(root / "a.c").write_text("int main(void) {\n\treturn 0;\n}\n",
			                          encoding="utf-8")
			env = {**os.environ, "GIT_AUTHOR_NAME": "t",
			       "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
			       "GIT_COMMITTER_EMAIL": "t@t"}
			for args in (["init", "-q"], ["add", "a.c"],
			             ["commit", "-q", "-m", "f"]):
				subprocess.run(["git", "-C", str(root), *args], check=True,
				               capture_output=True, env=env)
			r = subprocess.run([sys.executable, str(gate), "check"],
			                   cwd=root, capture_output=True, text=True,
			                   timeout=120)
		self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
		self.assertNotIn("conform", r.stdout)
		self.assertNotIn("not checked", r.stdout)
		self.assertIn("whitespace and indentation", r.stdout)


if __name__ == "__main__":
	unittest.main(verbosity=1)
