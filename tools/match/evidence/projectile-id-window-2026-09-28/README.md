# projectile_render: the last residuals are one id shift and one window, 2026-09-28

The canonical scratch stays at **97.75%** raw, 99.40% with labels masked, 3015/3021 instructions and
544/0/0 references. This evidence explains every remaining region (K6, K7, K8 and K9 in
[pr-residual-map.md](../../c2/compiler/pr-residual-map.md)). With two source additions it produces a
byte-exact body:

```text
match=100.00% prefix=3021/3021 target_insns=3021 candidate_insns=3021 refs=544/0/0 body_byte_exact=True
```

[pad-and-parens.diff](pad-and-parens.diff) holds both additions. The first one is a stand-in, not
recovered source (§1), so nothing is landed.

## 1. K6, K7 and K8: the arc's vector parts need ids 288 or 320 higher

`id_delta_profile.py --probe` finds eight tie sites that native orders the other way. All eight are in the ion
arc (`point0 -= direction * scale * 10.0f` and its three siblings). Each one compares a part of an inlined
`operator*` result with a point field or with another result part. The key is the part's id mod 2048.

| Pair (lane) | Our ids | Native needs |
|---|---|---|
| result x `#3820` vs result x `#3775` | 1772, 1727 | `#3820` wraps past 2048 and `#3775` does not: +276..+320 |
| result x `#3874` vs `point` x `#264` | 1826 | +222..+485 |
| result x `#3892` vs `point` x `#267` | 1844 | +204..+470 |
| result y `#4206`/`#4212`/`#4220`/`#4232` vs `point` y | 110..136 | ≥ +130..+156 |

A uniform shift of these twelve ids by **+288 or +320** satisfies all of them. As a phantom re-key
(`--phantom O:3766:4054,O:3767:4055,…`, the same +288 on all twelve ids), the function goes to **99.90%**, 3021/3021.
This fixes K6, K7 and, through the arc's changed node count, K8. Only K9 is left.

**Where the ids come from.** The arc parts are allocated by the inline-expansion pass (profile tag `inline`)
after the reader has finished, x lanes first (ids 3430..3900), then y lanes (4008..4240). So every id the
**reader** consumes, anywhere in the function, moves them. A real compile shows this. The stand-in is N dead stores
`step_x = transition_alpha * k;`, one reader temp each, into a float that every plasma loop writes before it reads:

| Pad | Placed before source line | Raw | Instructions |
|---|---|---|---|
| none | | 97.75% | 3015 |
| N = 256, 272 | 877 (before the arc) | 98.18% | 3019 |
| N = 280 .. 344 | 877 | **99.90%** | 3021 |
| N = 352 .. 384 | 877 | 96.04% | 3016 |
| N = 288 | 211, 307, 344, 627, 630, 637, 650, 722, 877, 955, 1040, 1165 | **99.90%** each | 3021 |
| N = 288 | 158 (before the sharpshooter loop) | 99.64% (the four y lanes stay reversed) | 3021 |

The needed amount is therefore 9 or 10 more 32-id chunks of reader IL somewhere after the sharpshooter loop,
including after the arc. Equivalently, since only id mod 2048 matters, about 1730 fewer ids. For scale, the
50-line plasma-rifle arm costs 160 ids (C0 0x1140 → 0x10a0 without it). Native's source was about
9% more verbose than ours in IL terms, with identical code.

Tried and rejected, because each changes code:

- indexed `projectile_pool[i].field` access instead of `position->`, `primary->` or `projectile->`. The IV anchor
  moves (iv-anchor-examples.md), and each adds at most two chunks;
- vector-operator locals or operator temporaries passed to an inline draw helper in the plasma arms. They spill
  to the frame;
- an unreachable plasma dispatch arm. C2 does not prove the `||` type filter, so the arm stays;
- `grim_draw_quad_points` repeated in each primary arm. It is not cross-jumped back into one call;
- new named locals (block-scoped pads, or per-quad locals in the plague block). They shift other pool-B ids;
  in the plague block they flip five plasma `fadd` ties and two arc lanes.

The dead-store pad is only a measuring device. The natural construct that consumed these chunks is still
unknown.

## 2. K9: the plague block needs more nodes before quad D

`sched_trace.py` on the padded build shows window 206: 81 machine nodes, no FROUND. It runs from the top of the
plague `life_timer == 0.4f` block, which native enters with no branch target inside it, to the **first**
`push 62` of quad D. The next two pushes land in window 207, after `fld st(0); fsin`. Native keeps
`fld st(0)` .. `push ecx` (nodes 77..88) in one window. That needs 4..73 more counted nodes before them.

No-op parentheses supply these nodes: each makes C1 emit a FROUND. On the padded build, 21 of the 127 combinations
of these groups are byte-exact:

| Group | Parentheses |
|---|---|
| cA, cB, cC | both coordinate arguments of quad A, B or C |
| oB | quad B's `(float)cos(heading) * 15.0f` and `sin` terms |
| oC | quad C's two offset terms |
| ang | the `heading`, `phase` and `phase_120` definitions |
| trig | the `phase_cos` and `phase_120_sin` definitions |

No exact combination contains the whole oC group. Examples: cA+cB+cC+ang, cA+cB+cC+trig, cA+cB+oB+cC. The
diff uses the first set found: cA+oB+ang plus quad C's `sin(phase) * 11.0f` term alone.

Single-use float locals per quad do not work: as named locals they shift other ids and bring two arc lanes
back (3019 instructions). Parenthesizing every `grim_draw_quad` argument in the function, as a macro would,
regresses to 95.91%.

## Reproduce

```sh
uv run python scripts/c2/id_delta_profile.py tools/match/scratches/projectile_render --out /tmp/pr-ids --probe --jobs 8
git apply tools/match/evidence/projectile-id-window-2026-09-28/pad-and-parens.diff
uv run crimson match scratch tools/match/scratches/projectile_render   # body_byte_exact=True
git checkout tools/match/scratches/projectile_render/scratch.cpp
uv run python scripts/c2/sched_trace.py tools/match/scratches/projectile_render --out /tmp/pr-sched
```
