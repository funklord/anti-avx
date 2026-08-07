# anti-avx -- ahead-of-time AVX to SSE binary translation.
#
# Nothing is compiled yet. The project is at the measurement stage, so this
# file exists for the style gate, the git hooks, and `scan` -- the target
# that reproduces every figure in project.md from the binary itself.
#
# `scan` is the only target here that does real work, and it is deliberately
# not part of `all` or `check`: it needs a 102 MB game binary that is not in
# the repository, and it writes about 0.9 GB. Both are reasons to ask for it
# by name rather than have it happen to somebody.

PROJECT    = anti-avx
PYTHON    ?= python3
OBJDUMP   ?= objdump

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

.PHONY: all check style style-source style-docs scan report hooks \
        clean distclean help

all: check

# `check` is what must pass before committing. There is no test suite yet,
# so it is the gate alone -- and it deliberately does not depend on `scan`,
# which needs a binary a fresh clone does not have.
check: style

style: style-source style-docs

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
	rm -f $(LISTING) $(REPORT)
	@echo "clean: removed $(LISTING) $(REPORT)"
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
	@echo '  scan        reproduce project.md from $$(TARGET) into $$(BUILD_DIR)'
	@echo '  hooks       install the commit-msg hook into .git/hooks'
	@echo '  clean       remove the listing and the report'
	@echo '  distclean   clean, plus __pycache__'
	@echo
	@echo 'Variables:'
	@echo '  BUILD_DIR   where products land (default: build)'
	@echo '  TARGET      the binary to scan (default: Starfield-unpacked.exe)'
