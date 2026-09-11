---
tags:
  - re
---

# Optional instruction alignments

`crimson match explain` exports an inspectable diagnostic bundle for a scratch.
Use it when the canonical diff leaves an operand chain unclear or a proposed
instruction pairing looks suspicious. The command does not change scratch
sources, aliases, match scores, experiments, acceptance rules, or native receipts.
A successful exit means the diagnostic ran successfully, even for a WIP function.

## Setup and use

The Levenshtein view uses an optional development group. It pins asm-differ to
commit `0dd09af8f8008f1f880327cf0aca3b26d2562ea2`; its dependencies are in `uv.lock`.
Normal game installations do not need this group.

```sh
uv sync --group match-explain
uv run --group match-explain crimson match explain \
  tools/match/scratches/projectile_render \
  --engine levenshtein --objdump /path/to/GNU/objdump \
  --out /tmp/projectile-explanation
```

Use GNU objdump with `pe-i386` support. On Apple Silicon with Homebrew binutils,
the path is `/opt/homebrew/opt/binutils/bin/objdump`. The wrapper explicitly selects
that format; no ELF conversion or objcopy step is needed.

For objdiff, install the platform's CLI from the
[objdiff v3.8.1 release](https://github.com/encounter/objdiff/releases/tag/v3.8.1)
and pass its path. This is the version tested for this integration. For example,
the release's macOS ARM64 CLI has SHA-256
`98f8275c27900c4fe2248fce3af37617658be49648fa7dbb5b376371f046dfdb`.

```sh
uv run --group match-explain crimson match explain \
  tools/match/scratches/projectile_render \
  --engine both --objdiff /path/to/objdiff-cli \
  --objdump /path/to/GNU/objdump --out /tmp/projectile-both
```

The default engine is `objdiff`, searched on `PATH`. `--engine levenshtein` needs
no objdiff executable. For an existing asm-differ checkout/environment, use
`--asm-differ /path/to/diff.py --asm-python /path/to/venv/bin/python`.
The output directory must be new, so a failed or previous run cannot silently
supply stale output to a later report. Failed runs retain their partial evidence.

## Reading a bundle

Start with `README.md` and `summary.json`. The latter lists every target offset
where the two aligners choose different candidate offsets, including unpaired
instructions. Each engine also produces:

- `*-assembly.txt`: paired original normalized instructions, with target VAs,
  function offsets, and independent reference status.
- `*-rows.json`: the same rows with complete reference identities and evidence.
- `*-raw.json` and `*-self.json`: unmodified tool output and target self-comparison.

Both sides must contain every canonical instruction offset exactly once and in
order. Missing, duplicate, unknown, or reordered offsets fail the diagnostic.
Self-comparison must pair each instruction with itself and report no difference.
Reference status is recomputed with Crimson's existing identity rules, even when
the external tool proposes a pairing. Summary reference counts include unpaired
reference instructions as `unresolved`; they are not directly comparable with
canonical counts of paired instructions.

`crimson.json` preserves the canonical result and reference audit.
`provenance.json` records the scratch configuration, build-input hashes, compiler
object hash, image hash, and diagnostic implementation hashes. Source and config
snapshots, untouched compiler output, and original function bytes are retained.
`tools.json` records actual executable/script paths, versions where available,
and hashes. These diagnostic COFF objects contain exact function extents with
independently identified external reference fields replaced by named relocations.
Every changed field and materialized local relative relocation is recorded in
`target-evidence.json` and `candidate-evidence.json`. They are synthetic diagnostic
containers, not recovered original object files. The entire bundle can be large;
keep it outside the tracked source tree unless specific evidence is worth saving.

## Address hypotheses

The report can group changes such as a missing shift and several scaled memory
operands into one retained-index hypothesis. It starts at reference-matched calls
and tracks affine register expressions modulo 2^32 through direct control flow.
A join retains an expression only when incoming paths agree. Unsupported writes,
partial-register writes, unknown loads, and volatile registers across calls lose
their expressions. Reference-bearing immediates and LEAs are not interpreted as
numeric constants. A return-value lifetime ends before another call with the same
reference operands; indirect jumps end the trace.

For `projectile_render`, the useful example is retaining `152*i` in one register
versus retaining `19*i` and applying scale eight in four field accesses. The report
shows the actual retained values, memory scales, offsets, and shared reference
identities. It predicts that changing where the source retains the scaled index
may change those operands together.

This is conditional on the paired calls returning corresponding indices and on
the intervening calls honoring the x86 callee-saved register ABI. The command does
not prove that the calls have corresponding arguments, that the paths correspond,
or that the entire function is equivalent. Inspect those producers and test the
hypothesis with a controlled compiler experiment and native behavior fixtures.

## Limits and controls

External scores remain in raw output for inspection; they do not become a new
matching objective. Levenshtein avoids two false cross-branch 3.0/4.0 pairings in
the frozen projectile spike, but adds reference mismatches in the high-score
function. No alignment is uniformly preferable. Even agreeing reference identities
can appear in unrelated branches.

Stock asm-differ stack categories are unsuitable for these VC6 functions: its
x86 regex treats ESI displacements as stack differences and excludes ESP.
The integration therefore does not expose those categories as source explanations.
The tested decomp-permuter scorer loses the destination register of a relocated
load; its search engine was not evaluated. The radiff2 spike did not pass its
self-comparison control. Neither is integrated.

The regular tests cover byte preservation, coverage rejection, independent
reference checks, affine grouping, joins, loops, partial writes, call clobbers,
and return-value lifetime boundaries. Run actual external-engine controls with:

```sh
CRIMSON_TEST_OBJDIFF=/path/to/objdiff-cli \
CRIMSON_TEST_ASM_DIFFER=/path/to/asm-differ/diff.py \
CRIMSON_TEST_ASM_PYTHON=/path/to/venv/bin/python \
CRIMSON_TEST_OBJDUMP=/path/to/GNU/objdump \
uv run --group match-explain pytest tests/test_match_explain.py
```

These controls require both tools to distinguish a relocated ECX/EDX load,
wrong reference, ESP and ESI displacement changes, a branch-target change, and
instruction reordering, while accepting a self-control. Without these environment
variables, only the seven external-engine cases are skipped.
