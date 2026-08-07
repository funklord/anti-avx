# anti-avx -- ahead-of-time AVX to SSE binary translation.
#
# The only compiled code in the tree is src/f16c.c, the software
# half-precision conversion that stands in for the F16C instructions
# Westmere does not have. Everything else is analysis tooling in Python.
#
# So this file covers the style gate, the git hooks, the F16C tests, and
# `scan` -- the target that reproduces every figure in project.md from the
# binary itself.
#
# `scan` is the only target here that does real work, and it is deliberately
# not part of `all` or `check`: it needs a 102 MB game binary that is not in
# the repository, and it writes about 0.9 GB. Both are reasons to ask for it
# by name rather than have it happen to somebody.

PROJECT    = anti-avx
PYTHON    ?= python3
OBJDUMP   ?= objdump
CC        ?= cc

# -Os because size is what these projects optimise for. The ISA flags are
# load-bearing rather than decoration: the whole point of this code is to
# run where AVX and F16C do not exist, so the compiler is forbidden from
# emitting either. -mno-f16c in particular stops it from "helpfully"
# recognising the conversion idiom and emitting the very instruction the
# code exists to replace.
CFLAGS    ?= -Os -std=c11 -Wall -Wextra -msse4.1 -mno-avx -mno-f16c
CPPFLAGS  += -Isrc -MMD -MP

# Where build products land. Settable so an isolated run can be kept from
# clobbering a plain one. BUILD_DIR is the canonical name across these
# projects; do not introduce a synonym.
BUILD_DIR ?= build

# The translation target. Not in the repository -- see .gitignore. This is
# the Steamless-unpacked form, which is what every measurement in project.md
# was taken from; the shipped binary has a .bind DRM section that disassembles
# as ~85,000 phantom instructions.
TARGET    ?= Starfield-unpacked.exe

# The full .text listing and the report derived from it. Named here because
# `clean` removes files it names rather than sweeping a directory.
LISTING    = $(BUILD_DIR)/text.asm
REPORT     = $(BUILD_DIR)/report.txt

# The software F16C conversions. This is the only compiled code in the tree.
OBJS       = $(BUILD_DIR)/f16c.o $(BUILD_DIR)/fmaddsub.o \
             $(BUILD_DIR)/permil.o $(BUILD_DIR)/permd.o
TEST_OBJS  = $(BUILD_DIR)/f16c_test.o $(BUILD_DIR)/fmaddsub_test.o \
             $(BUILD_DIR)/permil_test.o $(BUILD_DIR)/permd_test.o
TEST_BINS  = $(BUILD_DIR)/f16c_test $(BUILD_DIR)/fmaddsub_test \
             $(BUILD_DIR)/permil_test $(BUILD_DIR)/permd_test
TEST_BIN   = $(BUILD_DIR)/f16c_test
DEPS       = $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)

.PHONY: all check style style-source style-docs verify check-f16c \
        check-f16c-exhaustive check-f16c-oracle check-fmaddsub check-permil \
        check-isa \
        scan report \
        coverage hooks clean distclean help

all: check

# `check` is what must pass before committing. There is no test suite yet,
# so it is the gate alone -- and it deliberately does not depend on `scan`,
# which needs a binary a fresh clone does not have.
check: style verify check-isa check-f16c check-f16c-oracle check-fmaddsub \
       check-permil check-permd

style: style-source style-docs

# Assemble every lowering rule and prove no VEX prefix survives. Needs no
# game binary, so it belongs in `check` where `scan` and `coverage` do not.
verify:
	$(PYTHON) tools/lower.py verify

# -- the software F16C conversions -------------------------------------------

# Tests are built by the test target and by nothing else, so a plain build
# stays fast. The cost of that choice is paid by the dependency rules below
# being correct: -MMD -MP writes a .d beside every object, and every one of
# them is read back, TEST OBJECTS INCLUDED. A test object whose .d is never
# included does not rebuild when f16c.h changes, and the result is a test
# binary built against one layout linking against another.
check-f16c: $(TEST_BIN)
	$(TEST_BIN)

# All 2^32 singles rather than the default spread. A couple of minutes, and
# a counted loop, so it terminates on its own; it is a separate target
# because `make check` should not take minutes.
check-f16c-exhaustive: $(TEST_BIN)
	$(TEST_BIN) exhaustive

# The reference checked against CPython's own binary16 support, which is the
# only implementation on this machine that nobody here wrote. Exhaustive
# over all 65,536 halves.
check-f16c-oracle: $(TEST_BIN)
	$(PYTHON) tools/f16c_oracle.py $(TEST_BIN)

# The alternating-lane FMA lowerings. Separate from check-f16c because they
# are a different rule with a different failure mode: F16C is an algorithm
# that can be subtly inexact, while these are exact and can be subtly
# BACKWARDS -- wrong on half the lanes, right on the other half.
check-fmaddsub: $(BUILD_DIR)/fmaddsub_test
	$(BUILD_DIR)/fmaddsub_test

# The vpermilps variable-control helper. Its permutation space is small
# enough to cover completely, so this is exhaustive rather than sampled.
check-permil: $(BUILD_DIR)/permil_test
	$(BUILD_DIR)/permil_test

# The vpermd cross-lane helper. Exhaustive over all 8^8 index combinations,
# which takes a few seconds -- worth it, since sampling a permutation space
# is how the awkward cases get missed.
check-permd: $(BUILD_DIR)/permd_test
	$(BUILD_DIR)/permd_test

# The proof that matters for the translator: the code that replaces F16C
# must not itself contain AVX or F16C. Checked by disassembling what was
# actually built rather than by trusting the compiler flags -- a flag that
# silently stopped applying would otherwise look exactly like a clean pass.
check-isa: $(OBJS)
	@$(OBJDUMP) -d $(OBJS) | awk -F'\t' 'NF>=3 { \
		n = split($$2, b, " "); \
		if (b[1] == "c4" || b[1] == "c5" || b[1] == "62") bad++ } \
		/vcvtph2ps|vcvtps2ph/ { f16++ } \
		END { \
		  if (bad) { printf "check-isa: FAILED -- %d VEX/EVEX encodings\n", bad > "/dev/stderr"; exit 1 } \
		  if (f16) { printf "check-isa: FAILED -- %d F16C instructions\n", f16 > "/dev/stderr"; exit 1 } \
		  print "check-isa: no VEX, no EVEX, no F16C in the built object" }'

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: tests/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/f16c_test: $(BUILD_DIR)/f16c_test.o $(BUILD_DIR)/f16c.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/fmaddsub_test: $(BUILD_DIR)/fmaddsub_test.o $(BUILD_DIR)/fmaddsub.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/permil_test: $(BUILD_DIR)/permil_test.o $(BUILD_DIR)/permil.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/permd_test: $(BUILD_DIR)/permd_test.o $(BUILD_DIR)/permd.o
	$(CC) $(CFLAGS) -o $@ $^

# Named explicitly, never bare. A bare `.SECONDARY:` applies to every target
# any pattern rule matches -- including the object pattern above -- and Make
# then declines to rebuild a *missing* secondary whose dependant already
# exists, which is how adding a source file leaves a stale binary and a
# `make` that reports nothing to do.
.SECONDARY: $(TEST_OBJS)

style-source:
	$(PYTHON) tools/style_gate.py

# Holds project.md to the tree: no statement made twice, no backticked path
# naming a file that does not exist.
style-docs:
	$(PYTHON) tools/style_gate.py docs

# -- measurement -------------------------------------------------------------

# Reproduce the figures in project.md. Two steps, kept separate because the
# listing takes ~30 s and the analysis ~75 s, and iterating on the analysis
# should not re-disassemble 61 MB of .text every time.
scan: $(REPORT)
	@echo "scan: $(REPORT)"

report: scan

$(LISTING): $(TARGET) | $(BUILD_DIR)
	@echo "  objdump  $< -> $@  (~0.9 GB, ~30 s)"
	$(OBJDUMP) -d -j .text $< > $@

# Without `-j .text` objdump also disassembles the 234 KB .bind DRM section,
# which is flagged CODE and decodes as ~85,000 phantom instructions from
# encrypted data. That contamination is what produced the one-off `vfmaddcsh`
# and `vpmaskmovq` in the first scan, and chasing them is how the DRM wrapper
# was found. Keep the flag.

$(REPORT): $(LISTING) tools/vex_scan.py | $(BUILD_DIR)
	@echo "  vex_scan $< -> $@  (~75 s, ~1.1 GB RSS)"
	$(PYTHON) tools/vex_scan.py $< > $@

# Which VEX sites in the binary have a lowering rule, and which do not. The
# gap list is the point: it is the set of instructions a translator would
# have to refuse.
#
# This EXITS NON-ZERO while any gap remains, and that is deliberate -- it is
# a gate, not a report. Twelve F16C sites are uncovered today (Finding 10),
# so it fails today. Do not silence it with a `-` or a `|| true`: the whole
# value of the target is that it goes quiet only when the binary can
# actually be translated.
coverage: $(LISTING)
	$(PYTHON) tools/lower.py coverage $<

$(BUILD_DIR):
	mkdir -p $@

$(TARGET):
	@echo "$(TARGET): not present." >&2
	@echo "  It is a copyrighted game binary and is not in the repository." >&2
	@echo "  Unpack it with Steamless first -- see project.md, hard part 4." >&2
	@exit 1

# -- git hooks ---------------------------------------------------------------

# The hook lives in tools/hooks/ rather than only in .git/hooks so that it
# survives a clone and can be diffed against its siblings. An untracked hook
# enforces a rule nobody can see.
hooks:
	@test -d .git || { echo "hooks: not a git repository" >&2; exit 1; }
	@install -m 0755 tools/hooks/commit-msg .git/hooks/commit-msg
	@echo "hooks: commit-msg installed from tools/hooks/"

# -- cleaning ----------------------------------------------------------------

# Named targets only. No `rm -rf` of a directory and no wildcard sweep: a
# clean target is the one thing everybody runs without reading.
clean:
	rm -f $(LISTING) $(REPORT) $(OBJS) $(TEST_OBJS) $(TEST_BINS) $(DEPS)
	@echo "clean: removed $(LISTING) $(REPORT) $(OBJS) $(TEST_OBJS) $(TEST_BINS) $(DEPS)"
	@rmdir $(BUILD_DIR) 2>/dev/null || true

# Adds only what this project's own tooling wrote. It does not sweep for
# editor droppings: a .swp belongs to an editor that may still have the file
# open, and `find .` from here would walk .git as well. `git clean -xdn`
# lists that class, and removing it is the person's call.
distclean: clean
	@find . -name .git -prune -o \( -name __pycache__ -type d \) -print \
	        -exec rm -rf {} + 2>/dev/null || true
	@echo "distclean: done"

help:
	@echo 'Targets:'
	@echo '  check       the style gate -- what must pass before committing'
	@echo '  style       indentation, whitespace and document checks'
	@echo '  verify      assemble every lowering rule; prove no VEX survives'
	@echo '  check-f16c  software half-precision conversions, exhaustive h->f'
	@echo '  check-f16c-exhaustive'
	@echo '              also all 2^32 singles; a couple of minutes'
	@echo '  check-f16c-oracle'
	@echo '              reference vs CPython binary16, an outside opinion'
	@echo '  check-fmaddsub'
	@echo '              the alternating-lane FMA lowerings'
	@echo '  check-permil'
	@echo '              the vpermilps variable-control helper, exhaustive'
	@echo '  check-permd'
	@echo '              the vpermd cross-lane helper, all 8^8 permutations'
	@echo '  check-isa   prove the built object has no AVX, EVEX or F16C'
	@echo '  scan        reproduce project.md from $$(TARGET) into $$(BUILD_DIR)'
	@echo '  coverage    which VEX sites have a lowering rule, and the gaps'
	@echo '  hooks       install the commit-msg hook into .git/hooks'
	@echo '  clean       remove the listing and the report'
	@echo '  distclean   clean, plus __pycache__'
	@echo
	@echo 'Variables:'
	@echo '  BUILD_DIR   where products land (default: build)'
	@echo '  TARGET      the binary to scan (default: Starfield-unpacked.exe)'

# Every .d written by -MMD -MP above is read back here. Test objects are in
# this list deliberately: leaving them out is the failure that produces a
# test binary compiled against a stale header, which shows up as nonsense
# assertion failures rather than as a build error.
-include $(DEPS)
