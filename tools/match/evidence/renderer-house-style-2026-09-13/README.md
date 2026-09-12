# Renderer source-style controls

The exact sibling renderers are useful source evidence, but each transferred
idiom still needs a native check. This package retains two changes to
`projectile_render`:

1. Copy the fading beam's direction as a whole `vec2f_t`, as the live beam
   already does. The exact `player_render_overlays` likewise copies its
   direction before normalization. Native `0x42484f..0x424889` copies the
   two stored components with integer loads/stores before normalization.
2. Compute the chain radius before the Fire Bullets condition. Native
   `0x424b17..0x424b2d` computes and stores the radius before taking the
   branch that skips the creature search.

| Measurement | Before | Retained |
| --- | ---: | ---: |
| Normalized alignment | 60.268007% | 60.726846% |
| Candidate/native instructions | 2,949/3,021 | 2,950/3,021 |
| Clean/unresolved/mismatched positional references | 471/0/13 | 479/0/8 |
| Exact prefix | 0 | 0 |
| Candidate/native local frame | 388/412 bytes | 388/412 bytes |
| Normalized / encoded-body exact | false / false | false / false |

The gain is 57.588974 fuzzy-weighted bytes, not newly exact bytes. No whole
function match is added. Compiler flags, aliases, native extent, and matcher
rules are unchanged. The disappearing reference mismatches are improved
instruction pairings, not five independently fixed incorrect global accesses.

The predecessor is pinned in `before.cpp`, from
`923881a3ce13852a5327391a30ef22ae15646f24`, SHA-256
`29966e39e8f1e9ed67ac197d8cc8c9cb8048a4457e51ec1138d3487b912d23d9`.
The retained source SHA-256 is
`48ff88ff9f9e78427d1e6b28af863bedbc983c6ccf1d4c8fe9c9563b7fce3750`.

## What transferred from the exact code

- `player_render_overlays`: constructed direction, whole-vector copy, then
  normalization. The aggregate-copy change helps here; changing the vector
  type or borrowing a function-level direction-result local is neutral.
- `creature_render_type`: mixed indexed pool accesses and local pointers.
  These motivate bounded Fire Bullets/plasma controls, not a blanket rewrite.
  Some Fire Bullets forms improve alignment and reference pairing but still
  have the unresolved coordinate-store defect described below.
- `ui_render_hud`: disjoint values sometimes share one source local, while
  position objects need distinct scopes. Here borrowing the distance or step
  local raises the reference problem count, so those forms are not retained.
- Vector expressions preserve observable x87 store boundaries. Common
  subexpression extraction, component assignments, and compound operations
  are not interchangeable merely because the algebra is the same.

`source-controls.json` contains 133 checked, reconstructible source forms:
32 beam interactions, 16 arc interactions, eight scalar interactions, 32 pool
access controls, 44 Fire Bullets expression/scope controls, and the isolated
radius-placement control. The copy/radius pair has all four combinations.
All controls compile; none is exact. Failed or neutral forms only bound these
tested spellings and do not establish an exhausted compiler/source search.

## Native execution regressions

The retained source reproduces all **11,854** historical native fixtures:
200 plasma head, 480 beam, 384 ion-chain, 438 laser-owner, 1,194 secondary
body, 4,118 conventional corner, and 5,040 laser-trig cases. Each replay checks
the pinned image/body and historical native trace, complete ordered call
arguments, and the corresponding pool/write state. The historical suite also
rejects a freshly compiled wrong ion-width control.

The existing execution engines and external-call contracts are reused.
Their modeled Grim/D3DX behavior does not establish GPU pixel identity or
all-input equivalence. These changes do not alter either modern port.

## Newly exposed Fire Bullets residual

The native overlay's type gate uses slot 95 even when that record is inactive;
the active/lifetime/position accesses use the current record. The probe sets
only an inactive slot 95 to type 45 and keeps all active records conventional,
so the existing machine executor can exercise this previously missed pass.
Extending its accepted fixture type list changes only input validation.

The 512 deterministic fixtures expose ten one-bit Y-coordinate differences
in both the predecessor and retained source. All ten are at diagnostic PC64;
none of the 256 PC24 cases differs. Native stores the Y camera sum before
subtracting 32 (`0x42540d`, `0x425420..0x42542d`), whereas the scalar source
keeps that sum wide. This is not a claimed game-precision visual bug.

Vector/pair forms recover those ten Y words, but the tested forms disturb
unrelated allocation and alignment. The nearest tested scoped vector form reaches
59.923090%, 2,960/3,021 instructions, and 477/0/8 references. It is preserved
as a diagnostic control. Replaying all 512 cases against it exposes three new
PC64 X-coordinate differences, so fixing the selected Y witnesses is not a
complete rounding correction. The 44 expression/scope controls record only
the ten original witnesses and their ten PC24 counterparts; the full matrix
is recorded separately in `fire-vector-control.json`.
The next investigation can use these witnesses to recover the shared geometry
lifetimes and retain both native behavior and stronger whole-body evidence.

## Reproduce

```sh
uv run --no-sync python tools/match/evidence/renderer-house-style-2026-09-13/verify_controls.py \
  --out /private/tmp/renderer-house-controls

for suite in historic conventional laser; do
  uv run --no-sync --with unicorn==2.1.4 python \
    tools/match/evidence/renderer-house-style-2026-09-13/replay.py \
    --source tools/match/scratches/projectile_render/scratch.cpp \
    --suite "$suite" --out "/private/tmp/renderer-house-$suite"
done

uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/renderer-house-style-2026-09-13/fire_probe.py \
  --source tools/match/scratches/projectile_render/scratch.cpp \
  --out /private/tmp/renderer-house-fire
```

The control verifier preserves each reconstructed source in its output tree.
Pass `fire-scope-shapes/0-loop/scratch.cpp` from that tree to `fire_probe.py`
to reproduce this rejected vector diagnostic. `fire-before.json`,
`fire-current.json`, and `fire-vector-control.json` record the full discovery
matrix for the three sources. `fire-witnesses.json` pins the ten inputs used
to test the 44 expression/scope forms and their PC24 counterparts.
