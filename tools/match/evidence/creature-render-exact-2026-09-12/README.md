# Exact creature renderer

`creature_render_type` now matches all **765 instructions and 2,834 encoded body
bytes**, with **145 clean references**, no unresolved or mismatched references,
and no padding difference. The preceding reconstruction had 760 instructions,
79.737705% alignment, and 139 clean plus five mismatched references.

Four related source changes recover the native pool walks:

| Pass | Recovered source access |
| --- | --- |
| Shadow | Read the type guard and flags through `creature_pool[creature_index]`; keep the record pointer for tint and geometry. |
| Energizer | Use a counted entry loop, with an indexed type guard and the record's `max_health` field. |
| Normal | Read the type guard through the indexed pool; keep flags, tint and geometry on the record pointer. |
| Hit flash | Read the timer through the indexed pool in both the guard and alpha calculation. |

The compiler now retains the native lifecycle, max-health, animation-phase and
lifecycle induction cursors, respectively. It also retains the tint pointers
and parameter reloads that were missing from the shadow and normal passes.
The counted Energizer loop replaces the prior standalone max-health cursor and
containing-record cast. Every iteration still advances, including rejected
records. All rendering arithmetic, constants, conditions, pass order and state
writes remain as before.

These are actual field accesses to the same indexed objects. No register hints,
volatile accesses, artificial uses, compiler changes, aliases or matcher-rule
changes are introduced. Exact code generation supports the reconstruction;
it does not establish unique original source spelling.

Source identities:

- `before.cpp`, from `efaeb11c98c1b7265236cddd6a84ba56c3b278cc`:
  `64c270c898ac14e21ab7ad932cc0cf83a5bdc7d97b397461b102ff93276f7086`.
- Current scratch:
  `ccc5b0965304ef83c444bfae3b091e640802411d0f2c65231f907653e9ed0107`.

## Reproducible controls

`source-controls.json` records all 558 compiling controls, with exact source
edits, hashes, instruction counts, prefix lengths, reference results and encoded
exactness. The families contain 160 shadow owner/value forms, 254 normal/flash
owner forms, 128 Energizer loop/owner forms, and 16 combined-pass forms.
Regressions and reference disagreements are retained alongside improvements.
The combined matrix finds one exact candidate; selecting each pass's highest
standalone score would not find that combination.

The scratch's `pass-owner-reversions-2026-09-12.json` plan evaluates all 15
nonempty reversions of the four pass changes. Its complete results are recorded
in the scratch's `experiments.jsonl`. Every reversion loses exactness; reverting
all four reproduces the 79.737705% predecessor. The source controls are bounded evidence
about these access patterns, not a claim that all alternatives are exhausted.

## Native execution

`verify.py` reuses the guarded creature-render execution harness, including its
compiled layout check and four deliberately incorrect source controls. It
requires normalized and encoded exactness and checks every native/current
instruction is executed across 130 scenarios. It then executes the preserved
760-instruction predecessor and compares its complete call and write hashes
with those same native observations.

The cases cover both PC24 and PC64 arithmetic, animation flags, lifecycle and
health boundaries, inactive and other-type records, the last rendered pool
slot, Energizer levels, shadows, Monster Vision and hit flashes. Checks include
ordered argument bits, pointed-to colors, permitted state writes, callee-saved
registers, stack balance and the x87 control word. The four negative controls
change shadow opacity, omit the final slot, omit spawn-slot release and remove
the second flash draw; each must be detected.

This is CPU submission evidence with modeled Grim2D calls, not GPU pixel
validation or an all-input runtime proof. Whole-function encoded identity and
clean references are checked independently of the finite fixtures.

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/creature-render-exact-2026-09-12/verify.py \
  --out /private/tmp/creature-render-exact-native
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/creature-render-exact-2026-09-12/verify_controls.py \
  --out /private/tmp/creature-render-exact-controls --jobs 6
.venv/bin/crimson match mutate tools/match/scratches/creature_render_type \
  --spec tools/match/scratches/creature_render_type/pass-owner-reversions-2026-09-12.json \
  --max-changes 4 --max-variants 15 --jobs 6
```
