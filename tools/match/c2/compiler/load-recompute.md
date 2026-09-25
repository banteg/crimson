# Recomputed loads: splitting value numbers with a propagated FROUND (C2.DLL 8966)

This note explains how to get native's "recompute the same field read twice" x87 shape when no store
sits between the two reads. It uses the `player_update` low-health blood offset (native 0x4137a6) as
the worked case. It also records the prologue ordering question at 0x4136f3, which is still open,
and why the raw match ratio can drop when a region is fixed. Addresses are virtual addresses in the
pinned C2.DLL (image base 0x10700000), `/O2 /GB`.

"Verified" means confirmed with a preserving trace
([`scripts/c2/il_stage_trace.py`](../../../../scripts/c2/il_stage_trace.py),
[`scripts/c2/alias_trace.py`](../../../../scripts/c2/alias_trace.py),
[`scripts/c2/sched_trace.py`](../../../../scripts/c2/sched_trace.py)) or by compiles. "Read" means
static reading only. "Inferred" means the rule fits every compile below but the C2 code for it was
not traced.

Short version:

1. Two identical subtrees that read the same field are merged by the phase-3 CSE sweep. This happens
   unless a kill lies between them, meaning an aliasing store or a call, or unless their value
   numbers differ. [Verified]
2. A **single-use float local that only holds a load** (`float heading = player->aim_heading;`) is
   forward-propagated into its use with a `0x162` round tuple after the load. The consumer then reads
   the round's temp, not the load. It gets a different value-number owner from an inline
   `player->aim_heading + c` elsewhere, so the inline copy is not merged and reads memory again. The
   round emits no code. [Verified]
3. This is the only spelling found that reproduces native's blood offset. The spelling uses a
   refused single-use `dx` for the held lane, as in [x87-held-lanes.md](x87-held-lanes.md). It needs
   no extra store, and the output is identical to native.
4. The prologue difference comes from scheduling priority: `fld health` (height 13) beats the
   `previous_pos` copy load (height 9). Native's order needs a dependence edge from the copy to
   `fld`. The only mechanisms found are an escape of `&previous_pos` and an x87-typed copy. Native
   shows neither, so this is open (§3).
5. The raw ratio counts branch labels, which are byte offsets. A fix that changes the byte count can
   lose dozens of lines whose labels matched only because two drifts happened to cancel. Compare
   label-masked results before rejecting a change
   ([`scripts/c2/label_drift.py`](../../../../scripts/c2/label_drift.py), §4).

## 1. The blood offset

Native (0x4137a6..0x4137f1):

```
fld  [edi+0x300]; fadd [pi/2]; push ebx; lea eax,[esp+0x44]; fsub [0.5]
fcos; fmul [-6]                      ; x lane: held on the stack
fld  [edi+0x300]; fadd; fsub; fsin; fmul [-6]
fstp [esp+0x48]                      ; y lane stored to scratch_pos.y
mov  edx,[edi+0x300]; fadd [esi]     ; angle load; x + pos.x on the held value
mov  ebp,edx; mov [esp+0x28],edx; push ebp; push eax
fstp [esp+0x4c]                      ; scratch_pos.x, stored once
fld  [esp+0x50]; fadd [esi+4]; fstp [esp+0x50]
call effect_spawn_blood_splatter
```

Base source (`scratch_pos.x = cos(..)*-6; scratch_pos.y = sin(..)*-6; scratch_pos.x += pos.x;
scratch_pos.y += pos.y; float angle = ...`) stores x after `fmul` and reloads it.

Native constrains three things:

| Native feature | What it requires |
|---|---|
| Heading re-read for `fsin` | The two angle trees are not CSE'd |
| x held across the whole sin lane | x is a single-use temp or local whose forward propagation is refused, and nothing it overlaps dies inside it |
| `mov edx,[edi+0x300]` scheduled before `fstp x` | The angle load comes before the final x store in IL order. The y store orders it (st>ld); the x store must not |

### 1.1 Why the angle is or is not CSE'd [verified, `il_stage_trace.py --lines 41-46`]

- **base**: at `vn` both lanes get the same owners (`lea #4231`, `+ #4232`, `- #4233`). At `cse3`
  lane 2 keeps its own `+`/`-`. The store `scratch_pos.x = ...` lies between the lanes, and
  `avail_transfer_tuple` 0x1070a0d8 handles it as a direct store to a flags5&2 local. It clears
  `g_alias_class_kill_sets2[class]`, and that set contains `[player+0x300]` because function-scope
  `scratch_pos` is in `player`'s alias set ([x87-held-lanes.md](x87-held-lanes.md) §3).
- **b1** (`float dx = cos..; scratch_pos.y = sin..; ...`): no store between the lanes. `cse3`
  deletes lane 2's `+ player,768`, `+ heading,c1` and `- c2`, and lane 2's `cvt` reads `#4233`. The
  angle is computed once (`fld st(0)`). `dx` is born while that CSE temp is live and outlives it, so
  it fails the LIFO test and spills (`fstp [esp+0x28]` … `fld [esp+0x28]`, see
  [x87-spills.md](x87-spills.md) §4).
- **b4** (a block-scoped `blood` passed by address): `blood` is not a member of `player`'s set. The
  `blood.x` store therefore kills nothing, and the angle is CSE'd.
- **b20** (`float heading = player->aim_heading;` used only by the cos lane): `fwd` rewrites the lane
  as `lea t <- [player+0x300]`, `round t' <- t` (inserted at 0x10712643), `+ t', c1`. At `vn` the
  x lane's `+` is owner `#4265` (operand: the round) and the y lane's `+` is `#4271` (operand: the
  load `#4263`). The load itself shares owner `#4263`, but only the load, so `cse3` has nothing to
  delete and both lanes read `[edi+0x300]`.

### 1.2 Why x is held

`dx` has one use. Its forward propagation is refused because the y store (function-scope,
address-taken `scratch_pos`) lies between the def and the use, and the y tree reads through
`player` (`range_between` conflict, [x87-held-lanes.md](x87-held-lanes.md) §1). `dx` stays a named
single-def candidate. With no CSE'd angle to nest against, it stays on the stack from `fmul` to
`fadd [esi]`. y is a plain memory store, and the `+=` reloads it.

### 1.3 How to predict from source

For two lanes that read the same field `p->f` in identical subtrees:

1. Is there a store between them that clears the field's class (an escaping function-scope local, a
   store through a pointer or a global), or a call? Then both lanes read memory, with no CSE.
2. Otherwise, do both subtrees start from the same operand shape? A memory operand `[p+f]` in both
   means CSE: a shared temp, `fld st(0)`, or a spill if a held value crosses it. A propagated
   single-use local in exactly one of them (round, then the consumer) means both read memory.
3. A local read by both lanes has two uses. It is not propagated and becomes a shared x87 value,
   which is not the recompute shape (b29).

## 2. Acceptance tests (predictions written before each compile)

Each variant is a copy of `player_update` at b882202d5 (scratch.conf unchanged). Only the blood
statements change unless noted. "Blood" is the x87 and schedule of 0x4137a6..0x4137f1. Raw and
label-masked ("structural") ratios are whole-function values. Refs are ok/unresolved/mismatch. The
baseline is 72.62%, 82.51% structural, 840/0/1.

| Variant | Source of the lanes | Prediction | Observed blood | Raw / structural / refs |
|---|---|---|---|---|
| b1 | `dx = cos..; y = sin..; x = dx + pos.x; y += pos.y; angle` | CSE'd angle, dx spilled | ✓ `fld st(0)`, dx via `[esp+0x28]` | 71.28 / 82.47 / 838/0/1 |
| b3 | b1 plus `scratch_pos.x = dx;` right after dx | the x store kills CSE, dx held, extra `fst [x]` | ✓ native plus `fst [esp+0x44]` | 71.28 / 82.52 / 840/0/1 |
| b9 | b3 with `angle` before the final x store | as b3, native schedule | ✓ native except `fst` | 71.40 / 82.64 / 840/0/1 |
| b19 | b1 with `angle` before the final x store | as b1 | ✓ | 71.35 / 82.54 / 838/0/1 |
| b4 | block-scoped `blood`, base statements | CSE'd (no member store) | ✓ angle CSE'd, frame changed | 62.37 / 72.56 |
| b16 | b19, y lane reads `player_state_table[player_index].aim_heading` | different operand, no CSE | ✓ native x87, but `edi` becomes `idx*0x360` function-wide | 63.60 / 74.03 |
| b18 | b19, y lane reads through a block copy `bleeder = player` | no CSE | ✗ CSE'd: the copy is propagated to `player` before VN | 71.69 / 83.01 |
| **b20** | `float heading = player->aim_heading; dx = cos(heading..)*-6; y = sin(player->aim_heading..)*-6; angle; x = dx + pos.x; y += pos.y` | round splits VN, no CSE, dx held, native | ✓ **identical to native** | 71.80 / 83.02 / 842/0/2 |
| b30 | b20 with `heading` in the y lane instead | native | ✓ identical | 71.80 / 83.02 / 842/0/2 |
| b31 | b20 with `angle` after the x store | native x87, `mov edx` pinned after `fstp x` | ✓ | 71.68 / 82.90 |
| b29 (neg.) | `heading` used by both lanes | shared value, no recompute | ✓ `fld st(0)`, sin first | 72.20 / 82.92 |
| b21 (neg.?) | `cos((float)player->aim_heading + ..)` | C1 round on the load, native | ✗ CSE'd. A cast of a plain float read did not split VN (not traced) | 71.35 / 82.54 |
| b23, b27 | b20 using existing function-scope floats (`movement_heading`, `angle_step`) instead of new locals | same blood | ✓ identical | 71.91 / 83.15 / 841/0/2 |
| b11 | b1 with inline `cosf`/`sinf` | CSE'd | ✓ CSE'd, sin first | 71.99 / 82.70 |

b20 changes other code too. Through [x87-scheduling.md](x87-scheduling.md) §5, the new symbols flip
the auto-target distance site (`fld st(0); fmul st(1); fld st(2); fmul st(3); faddp; fsqrt;
fstp st(2)`, target lines 524–546) to native (+19 lines). They cost 4 lines at target line 1453.
The extra reference mismatch at 0x413ea0 (`mov ecx, ADDR` before the creature loop, anchor −0x18)
existed before. The candidate instructions are unchanged, and the base diff left that region
unaligned, so its references were not audited [inferred from identical candidate lines].

## 3. Prologue order at 0x4136f3 (open)

Native copies `previous_pos` before the health compare:

```
mov eax,[edi+0x14]; lea esi,[edi+0x14]; mov [esp+0x2c],eax; mov ecx,[esi+4]; mov [esp+0x30],ecx
fld [edi+0x24]; fcomp [0.0]; fnstsw ax; test ah,0x41; je
```

`sched_trace.py` and `alias_trace.py` on base window 1 (19 nodes, ending at the branch):

| Node | h | priority | cycle |
|---|---|---|---|
| `add edi` | 16 | 131072 | 6 |
| `fld [edi+0x24]` | 13 | 172032 | 8 |
| `fcomp` | 11 | 155648 | 9 |
| `lea esi` | 12 | 98304 | 10 |
| `mov eax,[esi]` (emitted `[edi+0x14]`) | 9 | 139264 | 10 |
| `mov s3922 <- eax` | 7 | 57344 | 11 |

The copy stores go to non-escaping locals, so they have no edge to `fld`. Their only successors
are register anti-dependences, such as `st lo -> fnstsw ax`. The load's height (9) cannot reach the
compare's (13) without a memory edge.

| Variant | Prediction | Observed prologue | Raw / structural / refs |
|---|---|---|---|
| p1, p2 (`previous_pos = *player_position;` / `= player->position;`) | unchanged (same lowered halves, no edge) | ✓ unchanged; the symbol count flips the sqrt site | 71.93 / 82.98 / 843/0/2 |
| p4, p5 (inline `copy(vec2&, const vec2&)`, `*(&previous_pos) = ...`) | unchanged | ✓ | 71.93 / 82.98 |
| p15 (copy through a local `previous = &previous_pos`) | unchanged | ✓ | 71.93 / 82.98 |
| p11 (`memcpy(&previous_pos, pos, 8)`) | escape, native | ✗ unchanged. The intrinsic becomes a block copy to direct symbols; no alias edge | 72.18 / 82.89 |
| p6 (copy before the aim-screen store) | unchanged relative order | loads hoisted above the aim stores (native has them after) | 70.87 / 82.44 |
| p9 (`!(health > 0)`), p13 (`goto` label between) | unchanged | ✓ (the label is coalesced) | 72.62 / 82.51 |
| **p12** (mechanism control: `vec2_length(&previous_pos)` at the end) | escape → `st>ld` edges `st lo→ld hi`, `st hi→fld` | ✓ **exact native order**. alias_trace: edges 11→12, 11→14, 13→14. The frame changes (slot 0x48) | 61.27 / 73.03 |
| p3 (`player_update_vec2_set(&previous_pos, pos->x, pos->y)`) | x87 chain orders the copy | ✓ native order, but `fld/fstp` instead of `mov` (the inline parameters are x87 candidates, and `fold_x87_copy_sequences` 0x1072fef2 turns only an `fld m` that directly feeds an `fstp m2` into an integer `mov`; read) | 71.38 / 82.98 |

Native evidence against an escape: no `lea` in the function reaches frame 0x20..0x27, where
`previous_pos` lives (`[esp+0x2c]` at entry and `[esp+0x30]`/`[esp+0x34]` in the `position == previous_pos` compare, target line 1693). Every
`lea [esp+0x38]` has no pending pushes, so it addresses frame 0x28, which is `movement_input`. So
native's edge comes from something not modelled here. The candidates are a class-1 collapse
(`alias-field-records.md` §1, which needs about 0x400 classes; we have 512) or an aggregate whose
other member escapes. `previous_pos` sits directly below `movement_input` (frame 0x28), which
escapes to `D3DXVec2Normalize`. Neither was tested. The second would need edits in the movement
section.

## 4. Raw ratio and label drift

Local labels are byte offsets (`je L18a`). In base the candidate is +8 bytes after the blood block,
but for branches into target lines ~899–1511 the cumulative drift happens to be 0. About 56 label
lines there match only because of that. b20 removes the 8 bytes, so the drift into that range becomes
−8:

```
uv run python scripts/c2/label_drift.py <variant> --against <base>
  raw: b20 gains 25 target lines (4 branch-label lines)
  raw: b20 loses 60 target lines (56 branch-label lines): (899,899), (979,979), (988,988), ...
  labels masked: b20 gains 24 target lines, loses 4
```

`--drift` prints the candidate−native label offset wherever it changes along the function. A fix
that is right locally lowers the raw ratio when it moves code toward native before a zero-drift
range. The label-masked comparison, `crimson match scratch --structural`, shows the real change.

## Tool

```sh
uv run python scripts/c2/label_drift.py <scratch-dir> [--against <baseline-scratch-dir>] [--drift]
```

It compiles through the normal pipeline (`load_scratch_config`, `compile_scratch`, `run_match`) and
does not change any scoring.

## Open questions

- The native mechanism of §3: what orders the `previous_pos` copy before `fld health` without an
  escape of frame 0x20.
- Whether C1 emits a `0x162` for `(float)lvalue` (b21) at all. The observed result is only that it
  does not split the value numbers.
- Why the shared load owner (`lea #4263`) is not deleted in lane 2 at `cse3` while the arithmetic
  owners are. Presumably a bare load tuple is kept because it folds into a memory operand. Not traced.
- The natural original spelling. b20 (a single-use `heading` local in one lane) is the smallest
  source found. Nothing shows it is what the authors wrote.

## Corrections to other notes

- [x87-scheduling.md](x87-scheduling.md) §3, row "(float) on a float expression": a `(float)` cast of
  a plain float field read (`(float)player->aim_heading`) did not change CSE in b21. The row should
  say "expression", not "lvalue".
- [optimizer.md](optimizer.md), "CSE": add that value numbering keys on operand shape. A round
  (`0x162`) inserted by forward propagation between a load and its consumer gives that consumer a
  new owner, so identical-looking source subtrees stop being common (b20 vs b1).
- [x87-held-lanes.md](x87-held-lanes.md): the held lane only stays on the stack if no CSE temp that
  it crosses is born before it. When both lanes share a subexpression (`cos(a)`, `sin(a)`), the
  shared temp makes the held lane spill (b1, b19).
