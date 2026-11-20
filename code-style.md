<!-- Copied from ~/.claude/guidelines/code-style.md by tool/sync.py.
     Edit the source, not this part: this project's own rules follow
     the end-of-copy line below. -->

# code-style.md

Code style for private projects. This file is the **source**. Every private
project except the one holding it carries a copy at its repo root, written
by `tool/sync.py` -- see *Keeping the copies in sync* at the end.

Vendored submodules, generated sources and attic/historical material are
exempt: they keep whatever their upstream or generator produces. Each
project names its own exempt paths in its part of the file.

## The three rules

1. **`snake_case`, not `camelCase`,** for identifiers this project defines.
2. **Tabs for indentation, spaces for alignment.**
3. **Lowercase filenames,** unless a tool demands otherwise.

Everything below is these three rules in detail, plus the exceptions that
are already settled. An exception not listed here is not yet settled: raise
it rather than deciding in passing.

## 1. Naming

`snake_case` for functions, variables, type names and fields.

This holds **even inside a toolkit whose own API is `camelCase`**. Call the
foreign API exactly as it is spelled (`setParent`, `addWidget`) -- that is
the API's name, not a violation. But names *you* introduce stay
`snake_case`; do not let the surrounding convention pull them across.

- **Name the thing, not its category**: `plan`, not `plan_struct` or
  `plan_result`.
- **No abbreviations that are not already vocabulary.** `observed`, not
  `obs`; `interface`, not `iff`. This matters most where an internal name
  escapes into something you cannot rename later -- a wire format, a config
  key, a CLI output, an on-disk path.
- **One word per concept, everywhere** -- the same word in the type name,
  the file path, the subcommand and the documentation. A synonym introduced
  for variety reads as a second concept.

### Prefixes, and visibility

Prefixes keep this project's symbols from colliding with a library's, so
they follow **visibility**, and the choice is judgement rather than a
mechanical rule:

- **Anything with more than small visibility carries the project prefix**
  -- the public API, and anything a linker or importer outside its own
  module can reach.
- **Module-private symbols are left unprefixed**, so that the absence of a
  prefix reads as "this does not leave the module."

The middle case decides itself on link safety, not taste. A symbol internal
by intent but still reaching the linker -- cross-file within a library, not
`static`, not part of the API -- is *not* private for this purpose: prefix
it. A deliberate parallel copy of a function in two libraries needs a
**distinct** name; the assumption that nothing will ever link both sides
fails later, at a call site that changed nothing, and names files you did
not touch.

Where a language enforces its own scheme, accept it, and say in the
project's part of this file that the toolchain is doing it:

- **Rust** -- `non_snake_case` and `non_camel_case_types` are on by
  default, so types are `PascalCase` and constants `SCREAMING_SNAKE_CASE`
  -- the toolchain's, not a choice. Package systems that demand kebab-case
  (Cargo crates, Debian packages) read back with their own spelling; do not
  invent a third by naming the directory differently from the package.
- **Python** -- a leading underscore (`_name`) is the language's private
  marker and stands in for "unprefixed" above.

## 2. Indentation and alignment

Indent structural nesting with **tab** characters, one tab per level. When
lining up tokens *within* a line -- continuation parameters under an open
paren, a block comment's `*` column, an aligned trailing comment -- use
**spaces**, after the indent tabs. Alignment is then relative to the shared
leading tabs, so it survives at any tab width. No tab width is prescribed;
the viewer decides.

```c
int thing_do(thing_t *thing, const char *name, size_t name_len,
              uint8_t *out, size_t out_cap) {
>---if (!thing) return ERR_MALFORMED;
>---return thing_write(thing, name, name_len, out, out_cap,
>---                    THING_DEFAULT_FLAGS);
}
```

(`>---` marks a tab; everything lining up under `(` is spaces.)

Never mix tabs and spaces *within* the indent itself. Tabs come first and
spaces after; the reverse, or an alternation, breaks at a different tab
width -- and in Python it is a syntax error.

### Settled exceptions

Divergence needs a technical reason. These are accepted:

- **Makefile recipe lines** -- `make` requires a literal tab. Compliant by
  construction.
- **YAML** -- the spec forbids tabs for indentation. Use spaces.
- **Markdown** -- list continuation and code fences are space-indented by
  specification. Exempt.
- **Debian packaging files** -- exempt, for two reasons measured against
  dpkg. `debian/changelog` has a fixed layout with no tab in it:
  `dpkg-parsechangelog` calls a tab-indented change line "unrecognized"
  and loses the trailer if a tab precedes `--`. A deb822 continuation in
  `control` or `copyright` may lead with a space *or* a tab, but that
  whitespace is field syntax rather than indentation, and everything past
  it is alignment.
- **Go** -- `gofmt` emits tabs natively. Compliant already.
- **Vendored, generated and attic sources** -- exempt, per the header.

**Python**: PEP 8 prefers spaces, but the language's only hard rule is that
indentation must not be *ambiguous*, and tabs-then-spaces is unambiguous at
every tab width. Continuation lines inside brackets are not
indentation-significant at all. Never a space *before* a tab in leading
whitespace -- that is what raises `TabError`.

Anything else that seems to need spaces: signal it to the list in
`claude-guidelines`' `project.md`, follow the rule meanwhile, and it is
settled here in a pass rather than in whichever project met it first.

## 3. Filenames

**Lowercase, always**, for everything the project names itself:
`main_window.cpp`, not `MainWindow.cpp`.

**The separator follows what the name binds to**, which is a technical
difference rather than taste:

- **`snake_case` where the filename becomes an identifier** -- a source
  file, a header, a module. `desired_state.rs` *is* the module
  `desired_state`, and `desired-state.rs` cannot be a module at all, a
  hyphen not being legal in a Rust path; Python imports are the same. That
  is the language's requirement, and not negotiable where it applies.
- **`kebab-case` for prose** -- documentation, design notes, decision
  records. Nothing imports `code-style.md`, so no identifier is at stake,
  and kebab-case is what markdown and URLs settled on. (When this rule said
  `snake_case` for documentation too, 174 of 197 markdown names across the
  workspace were already kebab-case.)

Settled exceptions:

- **Names a tool will not accept lowercased** -- `Makefile`,
  `CMakeLists.txt`, `AndroidManifest.xml`, `Dockerfile`, `Cargo.toml`.
- **Root files with an established convention** -- `README.md`, `LICENSE`,
  `CHANGELOG.md`, `AUTHORS`, `VERSION`. The last is this workspace's own: a
  project that packages or ships a version tracks one, and the build reads
  it for the package version and for what the program prints, so the
  number lives in one place. `claude-guidelines` packages nothing and has
  none.
- **Package-system spellings** -- kebab-case where Cargo or Debian require
  it, which is the spelling prose uses, so a crate directory and the design
  note beside it agree by construction.

### Singular, unless somebody else standardised the plural

**Prefer the singular for a directory this project names itself**:
`helper/`, `doc/`, `fixture/`. The name says what kind of thing lives
there, not how many, and should not have to change when the count does.

Two exceptions, and they are not equal -- the same shape as the lowercase
rule, which yields first to `Makefile` because make will read nothing else,
and only then to `README.md` because the world settled it.

**First: a name a tool requires is not a name we choose.** It outranks the
singular as it outranks lowercase, needs no measurement, and the test is
whether something breaks when the name changes. It is open-ended: a tool
met tomorrow that demands a name gets the same answer, whether the name is
plural, singular, capitalised or none of those. Present here: **Cargo**
looks for `tests/`, `examples/` and `benches/`, and `cargo-fuzz` for
`fuzz_targets/`; **GitHub** requires `.github/workflows/`; **git** keeps
`hooks/`, hence `tool/hooks/`. **A foreign package's directory names are
the same exception one layer out**: the Android SDK's `platform-tools/` and
`build-tools/` are the SDK's spelling. A word-boundary rewrite of `tools/`
once reached into `platform-tools/`, the hyphen being a boundary, and every
adb target in four projects pointed at a binary that was not there -- so a
sweep skips compound names it does not own. Package-system spellings (Cargo
crates, Debian packages) under *Filenames* above are this same carve-out.

**Second: a plural an ecosystem has settled** -- a convention rather than a
requirement: nothing breaks, but a reader would be surprised. Cargo
workspaces keep members in `crates/`. **These need measuring**, and the
project's part of this file names what it measured against, so the next
reader does not reopen it.

Say which kind is being claimed: confusing them lands on whoever renames a
directory that looked like a convention and finds the build broken. And an
inventory name in `harmonization.md` moves only when its owner says so, in
a deliberate pass with each project's gates run against the result -- as
`tools/`, `docs/` and `docs/decisions/` became `tool/`, `doc/` and
`doc/decision/` -- never as a side effect of a style rule.

## ASCII in source

Source and comments are ASCII. Write `--` where prose would use an em dash,
and "section" for a section sign.

This governs **the text the repository writes about itself**, not the data
the software handles. Three exceptions, which are the rule's shape rather
than holes in it:

- **Documentation.** Markdown may use typographic punctuation.
- **User-facing text in UI software.** A tick a program prints is output,
  not prose -- `GREEN('gpg ')` is correct as it stands.
- **Anything that genuinely requires Unicode**: a fixture for a UTF-8
  parser, a terminal emulator's character tables, a font tool.

Where a project needs the rule enforced, `ascii_only` in `.style-gate.toml`
turns it on. In Python and in C/C++ it enforces exactly that shape -- ASCII
outside string literals, Unicode allowed inside -- reading Python with
`tokenize` and C and C++ with a scanner written for the purpose. Every
other language gets a whole-file byte check, and so does a file in those
two that will not lex: a file nobody can parse is not a file that has been
cleared.

**An exception wider than its reason is how a rule stops being enforced.**
The check was once whole-file for everyone, so a project printing two
status ticks switched it off, and an em dash arrived in a comment; in a Qt
tree that kept it off for its toolbar glyphs, 854 of 1114 non-ASCII
characters turned out to be prose in comments.

## Formatters

A formatter is allowed **only if it can be configured to honour the three
rules completely**. Configuration gaps are disqualifying: a formatter that
gets indentation right and alignment wrong rewrites the tree on somebody's
next save. So the decision is per tool, per project, and a real evaluation:

- If it can be made to comply, use it, and commit the config with a comment
  saying which setting is load-bearing and what happens without it.
- If it cannot, do not run it -- **not even ad hoc on a single file**. The
  failure is a silent conversion of files that were already correct,
  found later as a reverted commit rather than an error.
- If no existing tool fits and the rule is worth mechanising, write our
  own. A checker that only gates indentation is worth more than a formatter
  that reflows everything.

**Record the decision and the finding that produced it** in the project's
part of this file -- which tool, what failed, what would change the answer.
A verdict without its evidence gets re-litigated, and a tool that improves
later is never reconsidered because nobody remembers what was wrong with
it.

Naming and filename rules are review items, not automated ones.

## Precedence

Three layers, and they are not equals:

1. **The global guidelines** (`~/.claude/CLAUDE.md` and the files it
   imports) -- the source, and they win.
2. **The project's `project.md`** -- project-specific design and
   conventions.
3. **The project's `code-style.md`** -- this file, copied, and the
   project's own part after it.

A project file that disagrees with the source is **drift, not an
override**: fix it. A project that genuinely needs to diverge needs a
technical reason, and that is not a decision to make while working on
something else -- signal it to the list in `claude-guidelines`'
`project.md` and keep following the source meanwhile.

**When a conflict between layers actually comes up, stop and ask.** Do not
silently pick a winner, even the global one.

This precedence rule lives here and in the global guidelines only. It does
not belong in a `project.md`.

## Keeping the copies in sync

Each private project keeps `code-style.md` at its root, in two parts: this
source, verbatim, under a header naming it; then, after a line marking the
end of the copy, **the project's own part**, holding only what is genuinely
its own -- its exempt paths, formatter verdicts, language-specific notes
and tooling commands, under its own headings. `claude-guidelines` is the
exception: it holds the source at `guidelines/code-style.md`, and its root
file points here.

**`tool/sync.py` writes the copied part and never touches the project's
part**, the same way it spreads the gate. So a copy cannot drift, and a
project that wants a rule to read differently changes the source, through
the signal list, rather than its copy. Until 2026-11-20 copies were adapted
by hand and audited only for their headings, and most had drifted in prose
no audit could see.

**Keep a census out of this document.** A count written here is copied
into every tree and goes stale in all of them at once; state the rule and
the criterion that decides it, and keep the count where it can be
recounted once.

**This source is plain ASCII**, so that it is valid in a tree whose own
rules restrict the characters its files may contain. Keep it so.

**Re-read this source before writing a project's own part, or anything
about the rules**, rather than working from what was loaded at the start of
the session: text written against a stale source is drift being written.
**A copied part that differs from the source** -- a tree the spread has not
reached, a hand edit -- is put right with `sync.py --commit <tree>`, never
by editing the copy; `sync.py --check` lists any that differ. A project's
`project.md` may state the three rules in brief and point here; it does not
restate the precedence rule.

<!-- End of the copied part. What follows is this project's own. -->

## This project

Code style for this project -- `tool/vex_scan.py`, whatever tooling follows
it, the `Makefile` and the documents.

Nothing is vendored.

### Exempt paths

None yet. There is no vendored code, no generated source and no attic. The
one file the tree deliberately does not govern is the translation target
itself -- a 102 MB copyrighted game binary, which is an input rather than a
part of the project and is excluded in `.gitignore`.

Disassembly listings under `$(BUILD_DIR)` are generated and exempt. They
are also excluded from the gate by the shipped `build` entry in its default
`exclude` list, so nothing here has to name them.

### Formatters: no formatter is run here

**No formatter is run on this tree, and none has been evaluated.** There is
one Python file. `black` is the obvious candidate and is **disqualified as
it stands**: it emits spaces for indentation with no option to emit tabs,
which is rule 2, and the choice is not configurable. That is the
disqualifying kind of gap rather than the tolerable kind -- it would
silently convert a conforming file on somebody's next save.

What would change the answer: a formatter that can be configured to emit
tab indentation and leave intra-line alignment alone. Until then the gate
checks and nothing rewrites.

### Indentation: Python is tab-indented here

**Python is tab-indented here**, which is the global rule and not a local
choice. Continuation lines inside brackets are not indentation-significant,
so the alignment half of rule 2 applies to them normally: tabs to reach the
nesting level, spaces to line up under an open paren.

### Naming, and the one place it will get hard

`snake_case` for everything this project names. The project is small
enough today that no prefix is needed, and a leading underscore is Python's
private marker.

The pressure will come from the subject matter rather than from a toolkit.
x86 mnemonics, register names and encoding fields are **foreign API names**
and keep their own spelling: `vfmadd231ps`, `%ymm0`, `VEX.vvvv`, `xgetbv`.
The rule is the same one that governs calling a `camelCase` toolkit -- use
the name the thing actually has, and keep `snake_case` for names this
project introduces. So a variable holding a decoded `vpermilps` is
`permute_control`, not `vpermilpsImm` and not `perm_ctl`.

**No abbreviations that are not already vocabulary** matters more here than
usual, because this domain is dense with them. `instruction`, not `insn`;
`immediate`, not `imm`; `destination`, not `dst` -- except where the latter
is the established spelling *of the thing itself*, as in an operand named
`dst` in the SDM. Where an internal name would escape into a report, a
filename or a CLI flag, spell it out.

### Tooling

```
make check      the gate -- what must pass before committing
make style      indentation, whitespace and document checks
python3 tool/style_gate.py list     what the gate actually looks at
python3 tool/style_gate.py fix      rewrite indentation, with a proof
```

`fix` verifies its own edit before writing: for Python the AST must be
identical before and after, so a rewrite that moved a block or a string
literal is refused rather than saved.
