<!-- The three rules and their detail are copied from
     ~/.claude/guidelines/code-style.md -- the source. Keep in sync; fix
     drift the moment you notice it. -->

# code-style.md

Code style for this project -- `tools/vex_scan.py`, whatever tooling follows
it, the `Makefile` and the documents.

**The global source**, `~/.claude/guidelines/code-style.md`, applies to every
private project and sits above both this file and `project.md`. Where
either disagrees with it, that is **drift to fix, not a local override**.
A genuine divergence needs a technical reason and is signalled to the list
in `claude-guidelines`' `project.md` rather than decided in passing -- and
when a conflict actually comes up, stop and ask instead of picking a
winner.

Nothing is vendored.

## The three rules

1. **`snake_case`, not `camelCase`,** for identifiers this project defines.
2. **Tabs for indentation, spaces for alignment.**
3. **Lowercase filenames,** unless a tool demands otherwise.

Everything below is these three rules in detail, plus the exceptions that
are already settled. An exception not listed here is not yet settled:
signal it to the list in
`claude-guidelines`' `project.md` rather than deciding in passing.

## 1. Naming

`snake_case` for functions, variables, type names and fields.

This holds **even inside a toolkit whose own API is `camelCase`**. Call the
foreign API exactly as it is spelled (`setParent`, `addWidget`) -- that is
not a violation, it is the API's name. But names *you* introduce stay
`snake_case`. Do not let the surrounding convention pull your own names
across.

- Prefer the plain descriptive name over the redundant one. Name the thing,
  not its category: `plan`, not `plan_struct` or `plan_result`.
- **No abbreviations that are not already vocabulary.** `observed`, not
  `obs`; `interface`, not `iff`. This matters most wherever an internal
  name escapes into something you cannot rename later -- a wire format, a
  config key, a CLI output, an on-disk path.
- **One word per concept, everywhere.** The same word in the type name, the
  file path, the subcommand and the documentation. A synonym introduced for
  variety reads as a second concept.

### Prefixes, and visibility

Prefixes exist to keep this project's symbols from colliding with a
library's. So they follow **visibility**, and the choice is a matter of
judgement rather than a mechanical rule:

- **Anything with more than small visibility carries the project prefix** --
  the public API, and anything a linker or importer outside its own module
  can reach.
- **Module-private symbols are left unprefixed**, precisely so that the
  absence of a prefix reads as "this does not leave the module."

The middle case decides itself on link safety, not on taste. A symbol that
is internal by intent but still reaches the linker -- cross-file within a
library, not `static`, not part of the API -- is *not* private for this
purpose. Prefix it. A deliberate parallel copy of a function in two
libraries needs a **distinct** name, not the same name in both on the
assumption that nothing will ever link both sides; that assumption fails
later, at a call site that changed nothing, and names files you did not
touch.

Where a language enforces its own scheme, accept it rather than fight it,
and say in the project's copy that the toolchain is doing it:

- **Rust** -- `non_snake_case` and `non_camel_case_types` are on by default,
  so types are `PascalCase` and constants `SCREAMING_SNAKE_CASE`. That is
  the toolchain's, not a choice. Package systems that demand kebab-case
  (Cargo crate names, Debian package names) likewise read back with their
  own spelling; do not invent a third by naming the directory differently
  from the package.
- **Python** -- a leading underscore (`_name`) is the language's private
  marker and stands in for "unprefixed" above.

## 2. Indentation and alignment

Indent structural nesting with **tab** characters, one tab per level. When
lining up tokens *within* a line -- continuation parameters under an open
paren, a block comment's `*` column, an aligned trailing comment -- use
**spaces**, after the indent tabs.

The point of the split: alignment is expressed relative to the shared
leading tabs, so it survives at any tab width. No tab width is prescribed
anywhere; the viewer decides.

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
spaces come after; the reverse, or an alternation, is what breaks at a
different tab width -- and in Python it is a syntax error.

### Settled exceptions

Divergence needs a technical reason. These reasons are already accepted and
need no discussion:

- **Makefile recipe lines** -- `make` requires a literal tab. Compliant by
  construction.
- **YAML** -- the spec forbids tabs for indentation outright. Use spaces.
- **Markdown** -- list continuation and code fences are space-indented by
  specification. Exempt.
- **Debian packaging files** -- exempt, and the two halves are exempt for
  different reasons. `debian/changelog` has a fixed layout that a tab is
  not part of: `dpkg-parsechangelog` calls a tab-indented change line
  "unrecognized" and loses the trailer outright if a tab precedes `--`. A
  deb822 continuation in `control` or `copyright` is the opposite case --
  `deb822(5)` allows a leading SPACE *or* TAB and dpkg round-trips either,
  but that leading whitespace is field syntax rather than indentation, so
  the rule has nothing to say about it and everything past it is
  alignment. Both measured against dpkg rather than read off the manual.
- **Go** -- `gofmt` emits tabs natively. Compliant already.
- **Vendored, generated and attic sources** -- exempt, per the header.

Python deserves a note, because PEP 8 prefers spaces and the tension looks
worse than it is: the language's only hard rule is that indentation must not
be *ambiguous*, and tabs-then-spaces is unambiguous at every tab width.
Continuation lines inside brackets are not indentation-significant at all.
Never a space *before* a tab in leading whitespace -- that is the case that
raises `TabError`.

Anything else that seems to need spaces: signal it to the list in
`claude-guidelines`' `project.md`, follow the rule meanwhile, and it gets
settled and added here in a pass rather than in whichever project met it
first.

## 3. Filenames

**Lowercase, always**, for everything the project names itself. So
`main_window.cpp`, not `MainWindow.cpp`.

**The separator follows what the name binds to**, and the two cases are a
technical difference rather than a matter of taste:

- **`snake_case` where the filename becomes an identifier** -- a source
  file, a header, a module. `desired_state.rs` *is* the module
  `desired_state`, and `desired-state.rs` cannot be a module at all,
  because a hyphen is not legal in a Rust path; Python imports are the
  same. That is the language's requirement wearing a convention's
  clothes, and it is not negotiable where it applies.
- **`kebab-case` for prose** -- documentation, design notes, decision
  records. Nothing imports `code-style.md`, so no identifier is at stake,
  and kebab-case is what markdown and URLs settled on long ago.

The rule used to say `snake_case` for prose too, and every private project
was quietly ignoring it. It was rewritten after measuring all fourteen
trees: of 197 tracked markdown basenames, 174 were already kebab-case.

Settled exceptions:

- **Names a tool will not accept lowercased** -- `Makefile`,
  `CMakeLists.txt`, `AndroidManifest.xml`, `Dockerfile`, `Cargo.toml`.
- **Root files with an established convention** -- `README.md`, `LICENSE`,
  `CHANGELOG.md`, `AUTHORS`, `VERSION`. The last is this workspace's own
  rather than the wider world's, and is settled by use: thirteen of the
  fourteen private projects track one, and a build reads it for the
  package version and for whatever the program prints, so the number
  lives in exactly one place. `claude-guidelines` is the one without it,
  and it packages nothing.
- **Package-system spellings** -- kebab-case where Cargo or Debian require
  it.

## ASCII in source

Source and comments are ASCII. Write `--` where prose would use an em dash,
and "section" for a section sign.

This governs **the text the repository writes about itself**, not the data
the software handles. Three exceptions, and they are the rule's shape
rather than holes in it:

- **Documentation.** Markdown may use typographic punctuation.
- **User-facing text in UI software.** A tick a program prints is output,
  not prose -- `GREEN('gpg ')` is correct as it stands.
- **Anything that genuinely requires Unicode**: a fixture for a UTF-8
  parser, a terminal emulator's character tables, a font tool.

Where a project needs the rule enforced, `ascii_only` in `.style-gate.toml`
turns it on.

## Formatters

A formatter is allowed **only if it can be configured to honour the three
rules completely**. Configuration gaps are disqualifying, not something to
work around: a formatter that gets indentation right and alignment wrong
will rewrite the tree on somebody's next save.

So the decision is per tool, per project, and it is a real evaluation:

- If it can be made to comply, use it, and commit the config with a comment
  saying which setting is load-bearing and what happens without it.
- If it cannot, do not run it -- **not even ad hoc on a single file**. The
  failure mode is a silent conversion of files that were already correct,
  discovered later as a reverted commit rather than an error.
- If no existing tool fits and the rule is worth mechanising, write our
  own. A checker that only gates indentation is worth more than a formatter
  that reflows everything.

**Record the decision and the finding that produced it** in the project's
copy of this file -- which tool, what specifically failed, what would change
the answer. A verdict without its evidence gets re-litigated, and a tool
that improves later never gets reconsidered because nobody remembers what
was actually wrong with it.

Naming and filename rules are review items, not automated ones.

## Precedence

Three layers, and they are not equals:

1. **The global guidelines** (`~/.claude/CLAUDE.md` and the files it
   imports) -- the source, and they win.
2. **The project's `project.md`** -- project-specific design and conventions.
3. **The project's `code-style.md`** -- this file, copied.

A project copy that disagrees with the source is **drift, not an
override**: fix it. A project that genuinely needs to diverge needs a
technical reason, and that is not a decision to make while working
on something else -- signal it to the list in `claude-guidelines`'
`project.md` and keep following the source meanwhile.

**When a conflict between layers actually comes up, stop and ask.** Do not
silently pick a winner, even the global one.

This precedence rule lives here and in the global guidelines only. It does
not belong in a `project.md`.

## What is specific to this project

### Exempt paths

None yet. There is no vendored code, no generated source and no attic. The
one file the tree deliberately does not govern is the translation target
itself -- a 102 MB copyrighted game binary, which is an input rather than a
part of the project and is excluded in `.gitignore`.

Disassembly listings under `$(BUILD_DIR)` are generated and exempt. They are
also excluded from the gate by the shipped `build` entry in its default
`exclude` list, so nothing here has to name them.

### Formatter verdicts

**No formatter is run on this tree, and none has been evaluated.** There is
one Python file. `black` is the obvious candidate and is **disqualified as it
stands**: it emits spaces for indentation with no option to emit tabs, which
is rule 2, and the choice is not configurable. That is the disqualifying kind
of gap rather than the tolerable kind -- it would silently convert a
conforming file on somebody's next save.

What would change the answer: a formatter that can be configured to emit tab
indentation and leave intra-line alignment alone. Until then the gate checks
and nothing rewrites.

### Language notes

**Python is tab-indented here**, which is the global rule and not a local
choice. PEP 8 prefers spaces; the language's only hard requirement is that
indentation be unambiguous, and tabs-then-spaces is unambiguous at every tab
width. Never a space *before* a tab in leading whitespace -- that is the case
that raises `TabError`.

Continuation lines inside brackets are not indentation-significant, so the
alignment half of rule 2 applies to them normally: tabs to reach the nesting
level, spaces to line up under an open paren.

### Naming, and the one place it will get hard

`snake_case` for everything this project names. The project is small enough
today that no prefix is needed, and a leading underscore is Python's private
marker.

The pressure will come from the subject matter rather than from a toolkit.
x86 mnemonics, register names and encoding fields are **foreign API names**
and keep their own spelling: `vfmadd231ps`, `%ymm0`, `VEX.vvvv`, `xgetbv`.
The rule is the same one that governs calling a `camelCase` toolkit -- use
the name the thing actually has, and keep `snake_case` for names this project
introduces. So a variable holding a decoded `vpermilps` is `permute_control`,
not `vpermilpsImm` and not `perm_ctl`.

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
python3 tools/style_gate.py list     what the gate actually looks at
python3 tools/style_gate.py fix      rewrite indentation, with a proof
```

`fix` verifies its own edit before writing: for Python the AST must be
identical before and after, so a rewrite that moved a block or a string
literal is refused rather than saved.

## Keeping this copy in sync

This file is a copy. The source is `~/.claude/guidelines/code-style.md`, and
the span from *The three rules* through *Precedence* is copied from it
verbatim -- byte-for-byte, which is checkable:

```sh
python3 - <<'EOF'
from pathlib import Path
src = (Path.home() / ".claude/guidelines/code-style.md").read_text()
mine = Path("code-style.md").read_text()
span = src[src.index("## The three rules"):src.index("## Keeping the copies")]
print("in sync" if span.rstrip() in mine else "DRIFT")
EOF
```

Everything above that span and everything below it is this project's own.
**Re-read the source before reconciling**, rather than working from memory:
a copy reconciled against a stale source is drift being written rather than
fixed.
