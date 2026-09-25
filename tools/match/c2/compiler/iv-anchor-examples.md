# IV anchor examples: accumulation and round-2 champions

This note adds worked examples to [strength-reduction.md](strength-reduction.md) §3. The merge rule there
(rule A) holds unchanged. Two of its consequences need refining:
- "a field with strictly more reads wins" is only true when there are two IVs;
- "a field-address local anchors at the first field accessed" is only true when the round-2 IV has few uses.

Everything below was traced with `scripts/c2/iv_trace.py` and replayed with `scripts/c2/iv_merge_chain.py`:

```sh
uv run python scripts/c2/iv_trace.py <scratch-dir> --out <trace-dir>
uv run python scripts/c2/iv_merge_chain.py <trace-dir> [--loop <address-substring>]
```

`iv_merge_chain.py` reads the IL entering merge #2 (0x10746a2f, mode 4). For each loop it prints the preheader
derived-IV inits, their use counts and the rule-A chain, and then compares the predicted survivor with the one
actually kept. A use is a tuple that reads the derived symbol, other than its preheader init and its tag-4 latch
update. The replay predicted the survivor in 70 of 70 multi-IV loops: 10 loops in each of 7 traces of
`projectile_render` variants.

## 1. The survivor carries its count forward

The champion is the last preheader init, and it adds each loser's uses to its own count. A field that is read
early in the body therefore picks up the counts of every field it beats. By the time a heavily used field
is compared, it may face a much larger total.

Example: the `projectile_render` plasma loop, 0x60 records of size 0x40 (canonical source at d14b31ba3). The
table lists the derived IVs in preheader order, which is the reverse of each field's last occurrence:

| init | +8 pos_x | +12 pos_y | +36 life | +44 speed | +4 angle | +20 origin_y | +16 origin_x | +32 type | +0 active |
|---|---|---|---|---|---|---|---|---|---|
| uses | 21 | 21 | 2 | 15 | 5 | 5 | 5 | 1 | 1 |

The chain runs as follows:
1. +0 (1) is the first champion.
2. +32 beats it on the tie (count 2).
3. +16 (5) beats +32 (count 7).
4. +16 then keeps against +20, +4, +44 and +36, reaching a count of 34.
5. It keeps against +12 (21), then against +8 (21).

The anchor is **+16**, although +8 and +12 are the most-read fields. They cannot win because the fade branch
at the end of the loop reads them last, so they are the last two challengers.

## 2. A round-2 IV with many uses keeps the anchor

A named pointer to a field (`p = &pool[i].f`) makes `p + k` a round-2 IV. Round-2 inits are appended after all
round-1 inits, so the last one is the first champion. strength-reduction.md's g1/g2 controls have one use of
`p + 4`, so the first round-1 challenger beats it on the tie. With many uses it wins instead.

Example: add `const vec2f_t *position = &projectile_pool[projectile_index].position;` (+8) to the plasma loop,
and read every pos_x/pos_y as `position->x` / `position->y`.
- `position + 4` (+12) becomes a round-2 IV with 11 uses and is the first champion.
- It beats the pointer's own round-1 init +8 (7 uses). It keeps against every later challenger (largest is +44
  with 15, faced at a count of 35).
- Anchor **+12**. The result is `mov esi, projectile_pos_y` / `cmp esi, particle_vel_x`, as in native.

`projectile_t::position` (the vec2 at +8) is already in `crimsonland_types.h`.

## 3. The field-address local's own init goes to the end of round 1

The local's initializer is one occurrence of `i*S + &pool.f`. If the local is declared before the other field
reads, that occurrence is the earliest last occurrence, so its IV is created last in round 1. Without round-2
IVs, it is the first champion (this is strength-reduction.md control `g4`).

In the same loop, reading only pos_x through `position` (pos_y direct) gives anchor **+8**: +8 (7) keeps against
every challenger and ends at 41 against +12 (21). The declaration can move anywhere before the first
`position` read: at the top of the body, after the `active` test, after the type filter, or at function scope.
All four placements give byte-identical output.

## Acceptance walkthrough (`projectile_render`, predictions written before compiling)

| variant | prediction | observed anchor | whole function | refs |
|---|---|---|---|---|
| canonical (b0) | +16 (chain §1) | +16 | 69.82% | 521/0/3 |
| v1 `const vec2f_t *position`, x and y through it | +12 | +12 | **71.38%** | **523/0/1** |
| v2 same with `const vec2f_t &position` | +12 | +12, same bytes as v1 | 71.38% | 523/0/1 |
| v5/v11/v9 v1 with the declaration after the type filter / after `active` / at function scope | +12 | +12, same bytes as v1 | 71.38% | 523/0/1 |
| v8 v1 with `projectile_render_vec2_t` as the pointee | +12 | +12, same bytes as v1 | 71.38% | 523/0/1 |
| v3 / v10 y through `position`, x direct | +12 | +12 (round-2 +12 ends at 45 against +8 at 22) | 71.29% | 518/0/1 |
| v4 x through `position`, y direct (negative) | +16 (**miss**) | +8 (§3) | 69.46% | 521/0/3 |
| v6 `vec2f_t position = ...` by value (negative) | not +12 | +16, plus an up-front copy of the vec2 | 68.07% | 510/0/3 |
| codex `projectile_pos_y_block_t *pos` at +12 (negative) | not +12 | +44 | 69.08% | 521/0/3 |
| codex `projectile_t *projectile` at +0 (negative) | not +12 | +16 (the fields fold back into round 1) | 69.41% | 521/0/3 |

The v4 miss is the §3 effect. The pointer's own init at +8 wins as the first champion. strength-reduction.md
§3 already states this for `g4`.

The pointer form also fixes the operand order of the inner-loop `fadd`. Native adds `[pos]` before
`[camera_offset]`, and so do reads through `position`. Direct `pool[i].pos_x` reads add the camera term first,
so v3 still differs on the x coordinate. That order difference is the evidence that native read both
coordinates through one pointer or reference to a vec2.

## Open questions

- In v1, the round-2 `position + 4` has 11 uses while the equivalent round-1 +12 had 21. The pass that CSEs the
  round-2 candidates was not identified.
- Resolved in [iv-cursor-merge.md](iv-cursor-merge.md): two IVs are compared only when step and update block match and their initial values differ by a constant; the replay tool now applies that and handles cursor pseudo-inits.