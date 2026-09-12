# Overlay size and target-position ownership

`player_render_overlays` improves from **97.431432% to 99.303136%** under the
unchanged `msvc6.5 /O2 /GB /W3 /GR-` profile. Candidate instructions fall from
1,149 to the native **1,148**, the exact prefix grows from 9 to **784**, and
clean references increase from 333 to **338**. No reference debt is introduced.
The fuzzy gap falls from 117.691772 to **31.930314 bytes**.

**This remains a partial recovery.** Normalized and encoded-body exactness are
both false. [The complete residual diff](native-current.diff) retains the two
remaining instruction-order differences: second-shield radius evaluation versus
rotation argument setup, and target-trail length evaluation versus normalization
argument pushes. No extra exact function is claimed.

## Retained source changes

The dead-player branch now owns its size scalar. The living-player shadow,
body and muzzle passes share `sprite_size`, with body dimensions loaded before
their coordinate calculations. Splitting only the dead owner or only adding the
body captures regresses; the combination restores all four native body-size
stack accesses at offsets 2165, 2175, 2522 and 2532. This is a source lifetime
interaction, not an inserted store or register constraint.

Each muzzle branch now loads its own input size. VC6 hoists the common load to
the native position between the weapon-index shift and subtraction, restoring
that instruction order without adding a load to the emitted function.

The target trail binds the existing `vec2f_t` position member by reference for
its displacement calculations while retaining the indexed distance-guard input.
This restores native's four `[ECX*8 + field-address]` reads and removes the
candidate's extra index shift. It does not introduce a new storage layout,
reference alias or numeric address recipe.

## Source controls

[source-controls.json](source-controls.json) retains two complete matrices,
reconstructible from [before.cpp](before.cpp): all **15 partitions** of the dead,
living-shadow, living-body and muzzle size owners; and all **63 non-default
combinations** of direct access, creature pointer, cached index and position
reference at the guard/X/Y consumers. Each includes checked line edits, source
hashes, instruction/prefix counts and reference results.

[verify_controls.py](verify_controls.py) independently reconstructs and compiles
all **78 controls**, reproducing every recorded metric in
[control-results.json](control-results.json). The four retained source regions
also have a complete **15-case reversion matrix** in
[render-owners-reversions-2026-09-12.json](../../scratches/player_render_overlays/render-owners-reversions-2026-09-12.json).
Every partial or full reversion compiles and lowers alignment; reverting all
four reproduces the preceding 97.431432% result. That sweep is recorded in the
scratch's `experiments.jsonl`. These matrices bound the tested source forms;
they do not establish exhaustion or unique original source spelling.

## Native execution and stack evidence

[verify.py](verify.py) reuses the unchanged native runner and **851 fixtures**
from the preceding size-ownership proof. Native, preceding source and retained
source agree on all checked ordered calls, permitted global writes, player and
creature state, and target-trail distance/segment results. The original 239
pinned call hashes are checked again. The x87 observer checks control word
`0x037f` and an empty stack on all 2,553 runs.

All **202 unambiguous paired stack accesses** now use their native homes.
The four preceding mismatches are restored, with **zero displaced accesses**.
The parent stack mapper's exclusions remain in the saved maps.
[results.json](results.json) binds this result to the native image/body, both
sources and objects, verifier dependencies, fixtures and individual traces.
The retained source SHA-256 is
`322be4d21391ba19a4ad893e033f2d08238e6393acdafaac2e96b64dc8632172`.

This is instruction recovery without an observed runtime defect in the
preceding source. The fixtures use PC=64 and modeled Grim/D3DX callbacks;
they establish neither arbitrary-input/PC=24 equivalence nor rendered pixels.
No matching rules, compiler flags, aliases, waivers, Python gameplay or Zig
code changes are part of this recovery.

## Reproduction

```sh
uv run --no-sync python tools/match/evidence/overlay-render-owners-2026-09-12/verify_controls.py \
  --out /tmp/crimson-overlay-owner-controls
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/overlay-render-owners-2026-09-12/verify.py \
  --out /tmp/crimson-overlay-owner-native
uv run --no-sync crimson match mutate tools/match/scratches/player_render_overlays \
  --spec tools/match/scratches/player_render_overlays/render-owners-reversions-2026-09-12.json \
  --max-changes 4 --max-variants 15 --jobs 6
```

The stock VC6 compiler and native runner's macOS JIT permission are required.
