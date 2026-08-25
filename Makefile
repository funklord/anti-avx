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

# Bounds for the ddisasm run. The address-space cap is deliberately below
# total RAM so that a run which does not fit is reported as a failed run
# rather than absorbed by the machine.
DDISASM_LIMIT_GB ?= 28
DDISASM_TIMEOUT  ?= 3600

# Iterations per timed run in `make bench`.
BENCH_ITERATIONS ?= 100000

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
             $(BUILD_DIR)/permil_test.o $(BUILD_DIR)/permd_test.o \
             $(BUILD_DIR)/lowering_test.o
TEST_BINS  = $(BUILD_DIR)/f16c_test $(BUILD_DIR)/fmaddsub_test \
             $(BUILD_DIR)/permil_test $(BUILD_DIR)/permd_test \
             $(BUILD_DIR)/lowering_test
# Generated from the lowering rules themselves, so the cases cannot drift
# away from what the rewriter actually emits.
GENERATED  = $(BUILD_DIR)/lowering_cases.s $(BUILD_DIR)/lowering_cases.inc
TEST_BIN   = $(BUILD_DIR)/f16c_test
DEPS       = $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)

.PHONY: all check style style-source style-docs verify check-f16c \
        check-f16c-exhaustive check-f16c-oracle check-fmaddsub check-permil \
        check-isa \
        scan report \
        coverage disassemble patch patch-plan patch-verify detour bench outside \
        placement check-aliasing check-lowering scratch-check check-pe \
        census check-spill check-unwind \
        detour-plan detour-verify hooks clean \
        distclean help

all: check

# `check` is what must pass before committing. There is no test suite yet,
# so it is the gate alone -- and it deliberately does not depend on `scan`,
# which needs a binary a fresh clone does not have.
check: style verify check-aliasing check-lowering check-isa check-f16c \
       check-f16c-oracle check-fmaddsub check-permil check-permd

style: style-source style-docs

# Assemble every lowering rule and prove no VEX prefix survives. Needs no
# game binary, so it belongs in `check` where `scan` and `coverage` do not.
verify:
	$(PYTHON) tools/lower.py verify

# Prove no lowering reads a register it has already overwritten. Needs no
# game binary either: it assembles its own operand shapes, lowers them, and
# disassembles the result back to simulate the register moves.
check-aliasing:
	$(PYTHON) tools/detour.py selftest

# Execute the lowerings and check what they computed, against GCC compiling
# the equivalent SSE intrinsic. The one test that runs translated code: this
# machine has no AVX, so it can execute the output but never the input.
check-lowering: $(BUILD_DIR)/lowering_test
	$(BUILD_DIR)/lowering_test

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

$(BUILD_DIR)/%.o: test/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/f16c_test: $(BUILD_DIR)/f16c_test.o $(BUILD_DIR)/f16c.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/fmaddsub_test: $(BUILD_DIR)/fmaddsub_test.o $(BUILD_DIR)/fmaddsub.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/permil_test: $(BUILD_DIR)/permil_test.o $(BUILD_DIR)/permil.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/permd_test: $(BUILD_DIR)/permd_test.o $(BUILD_DIR)/permd.o
	$(CC) $(CFLAGS) -o $@ $^

# Both halves come out of one generator run, so one recipe produces both and
# the .inc names the .s as its sibling rather than repeating the command.
$(BUILD_DIR)/lowering_cases.s: tools/lowering_cases.py tools/detour.py \
                               tools/lower.py tools/patch.py | $(BUILD_DIR)
	$(PYTHON) tools/lowering_cases.py emit $(BUILD_DIR)/lowering_cases.s \
	          $(BUILD_DIR)/lowering_cases.inc

$(BUILD_DIR)/lowering_cases.inc: $(BUILD_DIR)/lowering_cases.s
	@test -f $@

# -I$(BUILD_DIR) so the generated table is found; the .inc is an order-only
# prerequisite of nothing, so it is named here to force generation first.
$(BUILD_DIR)/lowering_test.o: test/lowering_test.c \
                              $(BUILD_DIR)/lowering_cases.inc | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -I$(BUILD_DIR) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/lowering_test: $(BUILD_DIR)/lowering_test.o \
                            $(BUILD_DIR)/lowering_cases.s
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

# -- disassembly (milestone 3) -----------------------------------------------

# Ddisasm is not packaged for Debian and is not in this tree. Unpack
# GrammaTech's focal builds into a scratch prefix and point DDISASM_PREFIX at
# it; tools/run_ddisasm.sh does the rest. See project.md, Finding 12, for
# what it needs and what happened.
#
# This target is NOT part of `check`, and not only because it needs the game
# binary: on the real target it consumes tens of gigabytes and fails. The
# bounds in run_ddisasm.sh are what keep that from taking the machine with
# it, so do not invoke ddisasm directly to "save time".
disassemble: | $(BUILD_DIR)
	@test -n "$$DDISASM_PREFIX" || { \
		echo "disassemble: set DDISASM_PREFIX to an unpacked ddisasm tree" >&2; \
		exit 1; }
	tools/run_ddisasm.sh $(TARGET) $(BUILD_DIR)/$(basename $(notdir $(TARGET))).gtirb \
		$(DDISASM_LIMIT_GB) $(DDISASM_TIMEOUT)

# -- in-place rewriting (milestone 4) ----------------------------------------

PATCHED  = $(BUILD_DIR)/$(basename $(notdir $(TARGET)))-sse.exe
DETOURED = $(BUILD_DIR)/$(basename $(notdir $(TARGET)))-detour.exe

# What can be rewritten without moving anything, and what cannot.
patch-plan: $(LISTING)
	$(PYTHON) tools/patch.py plan $(TARGET) $<

# Rewrite classes A, B and Z in place. No relocation, no reassembly: the
# output is the same size as the input and byte-identical outside the
# instructions it rewrote.
$(PATCHED): $(TARGET) $(LISTING) tools/patch.py | $(BUILD_DIR)
	$(PYTHON) tools/patch.py apply $(TARGET) $(LISTING) $@

patch: $(PATCHED)

# The invariants. `verify` disassembles both binaries and checks that every
# address which began an instruction still does -- the check that caught
# both bugs this tool has had, and the one worth running after any change
# to it.
patch-verify: $(PATCHED)
	$(PYTHON) tools/patch.py verify $(TARGET) $(PATCHED)

# Class C, which cannot be rewritten in place: a stub section is appended and
# each site becomes a jump into it. Only sites already five bytes or longer
# are touched -- see project.md, Finding 15, for why the shorter ones are
# left alone rather than made to fit.
detour-plan: $(LISTING)
	$(PYTHON) tools/detour.py plan $(TARGET) $<

$(DETOURED): $(TARGET) $(LISTING) tools/detour.py tools/patch.py | $(BUILD_DIR)
	$(PYTHON) tools/detour.py apply $(TARGET) $(LISTING) $@

detour: $(DETOURED)

detour-verify: $(DETOURED) $(LISTING)
	$(PYTHON) tools/detour.py verify $(TARGET) $(DETOURED) $(LISTING)

# -- measuring the cost ------------------------------------------------------

# What a detour actually costs on this CPU, which is the translation target.
# NOT part of `check`: it is a timing measurement, so it is slow and its
# result depends on what else the machine is doing.
$(BUILD_DIR)/icache_bench: tools/icache_bench.c | $(BUILD_DIR)
	$(CC) -O2 -std=c11 -Wall -Wextra -o $@ $<

bench: $(BUILD_DIR)/icache_bench
	$(BUILD_DIR)/icache_bench $(BENCH_ITERATIONS)

# Where the detours land: per-function density and, more to the point, how
# many loop bodies contain one. Static structure only -- it cannot say which
# loops execute.
placement: $(LISTING)
	$(PYTHON) tools/placement.py report $(TARGET) $<

# Reconcile what survives against what the rewriter declined, by comparing
# address sets rather than totals.
census: $(LISTING) $(DETOURED)
	objdump -d -j .text $(DETOURED) > $(BUILD_DIR)/after.asm
	$(PYTHON) tools/detour.py census $(TARGET) $(LISTING) $(BUILD_DIR)/after.asm

# Which of the sites .pdata refuses to vouch for are real leaf functions.
outside: $(LISTING)
	$(PYTHON) tools/outside.py report $(TARGET) $<

# -- the end-to-end test, on PEs this project builds itself ------------------

PE_NAMES   = aliasing memory branch ymm zerofill unrolled crossblock riprel \
             fallthrough pastread swallowed gapped interleaved permilps \
             twostore loopcopy lowwrite zerorun loophead zerochain \
             swallowjmp condbefore rspcopy
PE_SOURCES = $(PE_NAMES:%=$(BUILD_DIR)/pe-%.exe)
PE_LISTINGS= $(PE_NAMES:%=$(BUILD_DIR)/pe-%.asm)
PE_FIXED   = $(PE_NAMES:%=$(BUILD_DIR)/sse-%.exe)
# Wine wants an absolute prefix, and it is kept under BUILD_DIR so that it is
# this build's to remove rather than something in the user's home.
PE_PREFIX  = $(abspath $(BUILD_DIR))/wineprefix
# winedbg is disabled deliberately. The originals are MEANT to die of an
# illegal instruction, and with the debugger enabled that crash starts
# winedbg and waits -- two minutes of timeout for a result already known.
# Measured: with the override the same crash returns 29 immediately, and 29
# is the low byte of STATUS_ILLEGAL_INSTRUCTION.
WINE_ENV   = WINEPREFIX=$(PE_PREFIX) WINEDEBUG=-all WINEDLLOVERRIDES=winedbg.exe=d

# Named, and named HERE rather than beside the other one, because .SECONDARY
# expands its prerequisites where it is read -- listed before PE_LISTINGS is
# defined it silently protects nothing. Without it make deletes the listings
# as intermediates, and a missing secondary is not rebuilt when the thing
# depending on it already exists, which is how a stale rewrite would go
# unnoticed.
# The two extra harnesses build PEs that PE_NAMES does not list, so make
# would treat them as intermediates and delete them after every run.
# Named, never bare: a bare .SECONDARY protects every pattern target,
# object files included, and then declines to rebuild a missing one.
EXTRA_PES  = $(BUILD_DIR)/pe-spill.exe $(BUILD_DIR)/pe-spill.asm \
             $(BUILD_DIR)/pe-homespill.exe $(BUILD_DIR)/pe-homespill.asm \
             $(BUILD_DIR)/pe-unwind.exe $(BUILD_DIR)/pe-unwind.asm \
             $(BUILD_DIR)/pe-unwindstub.exe $(BUILD_DIR)/pe-unwindstub.asm \
             $(BUILD_DIR)/pe-unwindspill.exe $(BUILD_DIR)/pe-unwindspill.asm
.SECONDARY: $(PE_LISTINGS) $(EXTRA_PES)

$(BUILD_DIR)/pe-%.exe: tools/pe_build.py | $(BUILD_DIR)
	$(PYTHON) tools/pe_build.py sample $* $@

$(BUILD_DIR)/pe-%.asm: $(BUILD_DIR)/pe-%.exe
	objdump -d -j .text $< > $@

$(BUILD_DIR)/sse-%.exe: $(BUILD_DIR)/pe-%.exe $(BUILD_DIR)/pe-%.asm \
                           tools/detour.py tools/patch.py tools/outside.py \
                           tools/scratch.py tools/targets.py tools/lower.py
	$(PYTHON) tools/detour.py apply $(BUILD_DIR)/pe-$*.exe \
	          $(BUILD_DIR)/pe-$*.asm $@

# Build AVX PEs, rewrite them, and run both halves under wine. The originals
# must fail -- this CPU has no AVX -- and each rewritten one must return its
# own expected answer.
#
# **Both halves are assertions.** If an original succeeded, the machine would
# have AVX and the test would be proving nothing; that is the vacuous pass
# this shape exists to prevent, so it fails with its own message.
#
# Termination: every wine invocation is wrapped in a timeout, and the trap
# reaps the wineserver even when an assertion fails part way through.
check-pe: $(PE_FIXED) $(PE_SOURCES)
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-pe: wine is not installed"; exit 1; }
	@mkdir -p $(PE_PREFIX)
	@$(WINE_ENV) timeout 300 wine wineboot -i >/dev/null 2>&1 || true
	@set -e; \
	trap 'pkill -x wineserver >/dev/null 2>&1 || true' EXIT; \
	for name in $(PE_NAMES); do \
		want=`$(PYTHON) tools/pe_build.py names | \
		      awk -v n=$$name '$$1 == n { print $$2 }'`; \
		$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-$$name.exe \
			>/dev/null 2>&1 && new=0 || new=$$?; \
		$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/pe-$$name.exe \
			>/dev/null 2>&1 && old=0 || old=$$?; \
		echo "check-pe: $$name -- original $$old, rewritten $$new, want $$want"; \
		if [ "$$old" = "$$want" ]; then \
			echo "check-pe: the ORIGINAL $$name returned $$want -- this CPU"; \
			echo "          has AVX, so the test proves nothing here"; \
			exit 1; \
		fi; \
		if [ "$$new" != "$$want" ]; then \
			echo "check-pe: rewritten $$name returned $$new, want $$want"; \
			exit 1; \
		fi; \
	done; \
	echo "check-pe: AVX in, SSE out, and the answers survived the trip"

# The three ways a stub can get a scratch register when none is dead, all
# built and all run. `none` is the default and must REFUSE the site, so the
# rewritten binary still dies of an illegal instruction -- that assertion is
# what stops the other two passing for the wrong reason, since a site that
# was never the hard case would run under all three.
#
# What this proves is that each mechanism round-trips the borrowed register.
# What it cannot prove is what happens when a thread is inside the stub:
# see check-unwind for the stack case, and Finding 46 for the pool's race,
# which no single-threaded test can reach.
#
# Termination: one wine invocation per mode, each under a timeout.
check-spill: $(BUILD_DIR)/pe-spill.exe $(BUILD_DIR)/pe-spill.asm \
             $(BUILD_DIR)/pe-homespill.exe $(BUILD_DIR)/pe-homespill.asm
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-spill: wine is not installed"; exit 1; }
	@mkdir -p $(PE_PREFIX)
	@$(WINE_ENV) timeout 300 wine wineboot -i >/dev/null 2>&1 || true
	@set -e; \
	trap 'pkill -x wineserver >/dev/null 2>&1 || true' EXIT; \
	want=`$(PYTHON) tools/pe_build.py names | \
	      awk '$$1 == "spill" { print $$2 }'`; \
	for mode in none stack pool; do \
		$(PYTHON) tools/detour.py --spill=$$mode apply \
			$(BUILD_DIR)/pe-spill.exe $(BUILD_DIR)/pe-spill.asm \
			$(BUILD_DIR)/sse-spill-$$mode.exe >/dev/null; \
		$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-spill-$$mode.exe \
			>/dev/null 2>&1 && got=0 || got=$$?; \
		echo "check-spill: --spill=$$mode returned $$got, want $$want"; \
		if [ "$$mode" = "none" ]; then \
			if [ "$$got" = "$$want" ]; then \
				echo "check-spill: --spill=none answered $$want, so the"; \
				echo "             site was never the hard case and the"; \
				echo "             other two prove nothing"; \
				exit 1; \
			fi; \
		elif [ "$$got" != "$$want" ]; then \
			echo "check-spill: --spill=$$mode did not round-trip"; \
			exit 1; \
		fi; \
	done; \
	echo "check-spill: none refuses; stack and pool both give the register back"; \
	want=`$(PYTHON) tools/pe_build.py names | \
	      awk '$$1 == "homespill" { print $$2 }'`; \
	for mode in none home; do \
		$(PYTHON) tools/detour.py --spill=$$mode apply \
			$(BUILD_DIR)/pe-homespill.exe $(BUILD_DIR)/pe-homespill.asm \
			$(BUILD_DIR)/sse-homespill-$$mode.exe >/dev/null; \
		$(WINE_ENV) timeout 120 wine \
			$(BUILD_DIR)/sse-homespill-$$mode.exe \
			>/dev/null 2>&1 && got=0 || got=$$?; \
		echo "check-spill: homespill --spill=$$mode returned $$got, want $$want"; \
		if [ "$$mode" = "none" ]; then \
			if [ "$$got" = "$$want" ]; then \
				echo "check-spill: --spill=none answered $$want, so the"; \
				echo "             site was never the hard case"; exit 1; \
			fi; \
		elif [ "$$got" != "$$want" ]; then \
			echo "check-spill: the home space did not round-trip"; exit 1; \
		fi; \
	done; \
	echo "check-spill: and the callee home space lends a register with no rsp"

# Can an exception be dispatched from inside a stub? Two programs that fault
# on purpose, both registering a handler through .pdata -- which is how a PE
# with no imports gets SEH at all.
#
# The control faults on a plain `mov`. The other faults on a lowered
# instruction inside a stub, which answered 5 -- an unhandled 0xC0000005 --
# until the stubs were given unwind data, because a stub is entered by a jump
# and the dispatcher was reading a return address that was never one.
#
# **Both answer 42 now, and the second one is the whole point of Finding 48.**
# It is the only check here that exercises the exception path at all, so if it
# ever goes back to 5 something has stopped emitting `.avxpdat`.
#
# Termination: one wine invocation per program, each under a timeout.
check-unwind: $(BUILD_DIR)/sse-unwind.exe $(BUILD_DIR)/sse-unwindstub.exe \
              $(BUILD_DIR)/pe-unwindspill.exe $(BUILD_DIR)/pe-unwindspill.asm
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-unwind: wine is not installed"; exit 1; }
	@mkdir -p $(PE_PREFIX)
	@$(WINE_ENV) timeout 300 wine wineboot -i >/dev/null 2>&1 || true
	@set -e; \
	trap 'pkill -x wineserver >/dev/null 2>&1 || true' EXIT; \
	for name in unwind unwindstub; do \
		want=`$(PYTHON) tools/pe_build.py names | \
		      awk -v n=$$name '$$1 == n { print $$2 }'`; \
		$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-$$name.exe \
			>/dev/null 2>&1 && got=0 || got=$$?; \
		echo "check-unwind: $$name returned $$got, want $$want"; \
		if [ "$$got" != "$$want" ]; then \
			echo "check-unwind: $$name changed behaviour"; exit 1; \
		fi; \
	done; \
	$(PYTHON) tools/detour.py --spill=stack apply \
		$(BUILD_DIR)/pe-unwindspill.exe $(BUILD_DIR)/pe-unwindspill.asm \
		$(BUILD_DIR)/sse-unwindspill.exe >/dev/null; \
	want=`$(PYTHON) tools/pe_build.py names | \
	      awk '$$1 == "unwindspill" { print $$2 }'`; \
	$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-unwindspill.exe \
		>/dev/null 2>&1 && got=0 || got=$$?; \
	echo "check-unwind: unwindspill returned $$got, want $$want"; \
	if [ "$$got" != "$$want" ]; then \
		echo "check-unwind: unwindspill changed behaviour"; exit 1; \
	fi; \
	echo "check-unwind: a handler is reached from inside a stub, and a stub"; \
	echo "              that moved rsp still hands it the wrong frame"

# Prove every register the liveness scan claims as scratch is really dead,
# by enumerating paths rather than intersecting sets. Needs the listing, so
# it cannot live in `check`.
scratch-check: $(LISTING)
	$(PYTHON) tools/scratch.py check $< $(TARGET)

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
	rm -f $(LISTING) $(REPORT) $(PATCHED) $(DETOURED) $(GENERATED) \
	      $(PE_SOURCES) $(PE_LISTINGS) $(PE_FIXED) $(EXTRA_PES) \
	      $(BUILD_DIR)/sse-unwind.exe $(BUILD_DIR)/sse-unwindstub.exe \
	      $(BUILD_DIR)/sse-unwindspill.exe \
	      $(BUILD_DIR)/sse-spill-none.exe $(BUILD_DIR)/sse-spill-stack.exe \
	      $(BUILD_DIR)/sse-spill-pool.exe \
	      $(BUILD_DIR)/icache_bench \
	      $(BUILD_DIR)/after.asm $(BUILD_DIR)/patched.asm $(BUILD_DIR)/stubs.asm $(OBJS) $(TEST_OBJS) $(TEST_BINS) $(DEPS)
	@echo "clean: removed $(LISTING) $(REPORT) $(PATCHED) $(DETOURED) $(BUILD_DIR)/icache_bench $(OBJS) $(TEST_OBJS) $(TEST_BINS) $(DEPS)"
	@# The wine prefix is a directory this build created, so it goes
	@# wholesale -- but only after checking the variable is non-empty and
	@# not something that could resolve outside the build tree.
	@case "$(PE_PREFIX)" in \
	  */wineprefix) test -d "$(PE_PREFIX)" && rm -rf "$(PE_PREFIX)" && \
	                echo "clean: removed $(PE_PREFIX)" || true ;; \
	  *) echo "clean: refusing to remove '$(PE_PREFIX)'" ;; \
	esac
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
	@echo '  disassemble ddisasm over $$(TARGET), under prlimit bounds'
	@echo '  patch-plan  what can be rewritten in place, and what cannot'
	@echo '  patch       rewrite classes A/B/Z in place into $$(BUILD_DIR)'
	@echo '  patch-verify'
	@echo '              size, headers, and instruction boundaries preserved'
	@echo '  detour-plan what Class C would be detoured'
	@echo '  detour      in-place patches plus Class C detours'
	@echo '  detour-verify'
	@echo '              sections, boundaries and the stub section'
	@echo '  check-lowering  execute every lowering and check the result'
	@echo '  check-pe    build an AVX PE, rewrite it, run both under wine'
	@echo '  bench       what a detour costs on this CPU (a timing run)'
	@echo '  placement   where the detours land: functions and loop bodies'
	@echo '  outside     the code .pdata does not describe'
	@echo '  census      what survives the rewrite, and why'
	@echo '  scratch-check  prove every claimed scratch register is dead'
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
