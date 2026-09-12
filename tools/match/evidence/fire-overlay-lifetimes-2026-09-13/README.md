# Fire Bullets overlay: copy boundaries and rounding

The native screen-position arithmetic is now reproduced by ordinary vector
expressions, including the separate Y temporary. These are diagnostic source
controls: the canonical scratch remains unchanged because the recovered forms
still disturb allocation elsewhere in the function.

The predecessor is `b484ae17ce2f5781aaa89824e0bfce362c4361e3`, with the canonical
source pinned in `before.cpp`, SHA-256
`48ff88ff9f9e78427d1e6b28af863bedbc983c6ccf1d4c8fe9c9563b7fce3750`.

## What the native instructions establish

At `0x4253eb..0x425441`, native adds camera X and projectile X, then camera Y
and projectile Y. It stores the Y sum, subtracts 32 from the still-wide X sum,
stores final X, reloads the Y sum, and subtracts 32 before storing final Y.
Both final components are loaded as integer words for the draw call.

For the bounded finite inputs here, the diagnostic PC64 oracle is:

```text
X = float32(camera_x + projectile_x - 32)
Y = float32(float32(camera_y + projectile_y) - 32)
```

The input sums fit exactly in Python binary64. At PC24, both sums round to
24-bit significands before subtraction. This is not a claimed game-precision
visual bug: the earlier 256 PC24 cases already agreed with the scalar source.

The complete vector expression recovers all 19 native instructions in this
86-byte draw window with two explicit stack-home shifts and a projectile-cursor
bias. All five masked reference pairs independently agree: camera X, camera Y,
the Grim interface, and both 32.0 constants. The checker passes its native
self-control and rejects a substituted 31.0 reference. These substitutions are
diagnostic, never a change to matcher normalization or exact-match credit.

## What this teaches about source style

The previous investigation's nearest vector control assigned a camera sum to
an object declared outside the branch, then applied `-= 32`. Its extra aggregate
copy rounds X too early. That control fixes the original ten Y witnesses but
fails three different X witnesses.

The combined 13 witnesses and their PC24 counterparts distinguish three forms:

```cpp
// Scalar draw arguments: both sums remain wide; ten Y witnesses fail.
grim_draw_quad(camera.x + position.x - 32,
               camera.y + position.y - 32, 64, 64);

// Aggregate copy: both sums are stored; three X witnesses fail.
vec2 screen_result = camera + position;
vec2 draw_pos = screen_result;
draw_pos -= 32;

// Complete vector expression: native X/Y rounding and separate Y temporary.
vec2 draw_pos = camera + position - 32;
grim_draw_quad(draw_pos.x, draw_pos.y, 64, 64);
```

These examples abbreviate the actual source in `source-controls.json`. The
explicit member-copy form also preserves native rounding, as it does in the
already recovered conventional trails. Initializing a vector and immediately
using `-=` gets the arithmetic right but reuses its final Y slot for the sum;
the complete expression retains a distinct compiler temporary as native does.
Subtracting in scalar draw arguments eliminates that store again.

Scope alone therefore does not explain the boundary. It matters whether the
compiler constructs a result, copies an aggregate, or copies individual
components. Several spellings reproduce the same machine behavior; this does
not identify a unique original C++ statement or justify a universal vector rule.

## Bounded evidence

`source-controls.json` preserves **35** freshly compiled forms: 28 new forms
and seven controls carried forward into the expanded witness set. Each is a
checked patch against `before.cpp`. On all 26 combined witnesses, 21 forms
agree, nine retain the ten Y failures, and five retain the three X failures.

The full matrix contains **608** cases: the original 512 deterministic
geometries plus 96 mixed-pool cases covering slots 0/31/94/95, inactive entries,
nonzero active value 2, adjacent float32 lifetime values, the earlier type-zero
deactivation, both glow settings, and three alphas. An independent oracle checks
overlay count, slot order, rotation owner, and both coordinate words. Native
still gates the entire overlay pass on inactive slot 95's type; all other
accesses use the current record.

The complete expression passes all 608 cases and all **11,854** historical
renderer fixtures. The scalar control fails 22 cases and the aggregate-copy
control fails three, all at PC64. Their original ten Y and three X failures
remain reproducible, so this matrix distinguishes the two incorrect boundaries.
`fixtures.jsonl` pins native inputs, overlay words, full ordered call-trace
hashes, and pool/write state. `results.json` records fresh control compilations,
the full-matrix failures, the instruction window, and object-equivalent compiler
listings. `replays.json` retains the historical replay receipts without their
redundant full CFG payloads; the wrong ion-width control is also rejected.

| Source | Alignment | Instructions | Clean/unresolved/mismatched refs |
| --- | ---: | ---: | ---: |
| Canonical scalar | 60.726846% | 2,950/3,021 | 479/0/8 |
| Aggregate-copy control | 59.923090% | 2,960/3,021 | 477/0/8 |
| Complete-expression control | 53.589958% | 2,954/3,021 | 419/0/10 |

All three allocate 388 local bytes against native's 412. The corrected
expression changes stack-home assignment without changing frame size; the
compiler listings have 52 distinct declared slots in each case. The alignment
loss and unchanged frame size do not establish a count of missing locals.
Both exactness flags remain false. No canonical source, modern port, aliases,
compiler flags, native extent, or acceptance rules are changed.

The next unresolved problem is how the original source shared these position
objects with other renderer passes. The arithmetic and copy controls now give
that investigation a stronger acceptance test than alignment alone.

## Reproduce

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/fire-overlay-lifetimes-2026-09-13/verify.py \
  --out /private/tmp/fire-overlay-lifetimes

for suite in historic conventional laser; do
  uv run --no-sync --with unicorn==2.1.4 python \
    tools/match/evidence/renderer-house-style-2026-09-13/replay.py \
    --source /private/tmp/fire-overlay-lifetimes/prior/expression/scratch.cpp \
    --suite "$suite" --out "/private/tmp/fire-overlay-$suite"
done
```

The existing machine executor checks stack balance, saved registers, allowed
instruction addresses, x87 state, and non-stack writes. Type 45 is permitted
only in inactive slot 95; active Fire beam execution is outside this proof.
The external-call contracts remain modeled. These finite caller fixtures do
not establish GPU pixels, arbitrary-input identity, or complete renderer parity.
