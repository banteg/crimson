# Exact player overlays

`player_render_overlays` now matches all **1,148 instructions and 4,582 encoded
body bytes**, with **340 clean references**, no unresolved or mismatched
references, and no padding difference. The preceding source had the same
instruction count and stack homes but two scheduling differences, at 99.303136%.

Two source boundaries recover the remaining instructions:

- Use the VC6 header's `sinf` wrapper for the two shield radii. Its float
  argument and return boundaries replace the direct double `sin` call with a
  cast. The inner-radius change restores the later outer-radius/rotation
  schedule; changing the outer radius alone is neutral.
- Construct the target-trail displacement as a `player_render_vec2_t` value
  before assigning it to `render_delta`. This restores the native ordering of
  the float stores, squared-length calculation, integer copy and normalization
  arguments. The vector copy still precedes the length calculation, preserving
  the native float32 rounding boundary.

The original-era SDK uses `sinf` and value-constructed vectors in
`cl_mod_sdk_v1/cl_crimsonroks/src/cltypes.h` and `r_roks.cpp`. The installed
VC6.5 `math.h` defines `sinf(float)` through `(float)sin((double)_X)`. These
are source/compiler evidence, not a claim that the original source is unique.
No compiler settings, aliases, comparison rules, or gameplay behavior changed.

Source identities:

- `before.cpp`, from `4f4c8be66f44fd49a17992a5dc0bab1a3ca59790`:
  `322be4d21391ba19a4ad893e033f2d08238e6393acdafaac2e96b64dc8632172`.
- Current scratch:
  `8a403a6a4c6c7bf63cc276950e407adb8bf2d1f7cac6d56d228950dde6941181`.

## Controls and execution

`source-controls.json` preserves 281 hash-checked, reconstructible controls:
255 nonempty selections of the eight sine wrappers, 15 grouped math-consumer
forms, and 11 trail value/length forms. The complete set is retained, including
regressions and reference mismatches. Four value-construction trail forms reach
encoded exactness; neither an operator subtraction nor the SDK reciprocal
length routine does. These results distinguish the tested source boundaries;
they do not prove uniqueness or exhaust other source forms.

The adjacent three-site reversion plan records all seven nonempty combinations
in the scratch's `experiments.jsonl`. Reverting only the outer-radius wrapper
is byte neutral. Every other reversion loses exactness; reverting all three
recovers the preceding 99.303136% candidate.

`verify.py` executes 851 native/before/current fixture triples. It compares
complete ordered call argument bits, permitted global writes, stored trail
length, and unchanged player/creature storage. It reproduces the original
239 call hashes, checks all 202 paired stack homes, and requires both normalized
and encoded-body exactness. All 2,553 runs also check the x87 control word and
empty x87 stack through the existing guarded runner.

These execution fixtures cover the modeled CPU calls and PC64 arithmetic,
including the existing rounding-boundary cases. They are not GPU pixel tests.
The encoded-body and reference checks independently cover the entire function.

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/overlay-exact-2026-09-12/verify.py \
  --out /private/tmp/overlay-exact-native
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/overlay-exact-2026-09-12/verify_controls.py \
  --out /private/tmp/overlay-exact-controls
.venv/bin/crimson match mutate tools/match/scratches/player_render_overlays \
  --spec tools/match/scratches/player_render_overlays/float-sine-vector-reversions-2026-09-12.json \
  --max-changes 3 --max-variants 7 --jobs 6
```
