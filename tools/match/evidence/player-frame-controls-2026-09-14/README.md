# Player frame and vector controls

These 75 source controls isolate vector lifetimes, position expressions, and
Fire Cough call consumers in `player_update`. **None is a full match, and none
is promoted to the canonical scratch.** Every recorded result has been
reproduced by a fresh compilation, including its extracted-body hash,
instruction count, positional reference audit, and both exactness flags.

The baseline is commit `55feaa2bc07de305ffec0c627122d36a787c6de6`:
4,060 candidate instructions against 4,206 native, prefix 7, references
`805/0/2`, and false normalized and encoded-body exactness. Its 64.04549%
instruction ratio is a diagnostic, not an acceptance criterion.

## Frame map

`frame_map.py` propagates ESP through every branch and annotates stack accesses
relative to ESP at function entry. Thus `[FRAME-40]` identifies a physical
stack address even while outgoing arguments change the current ESP. This is
a target-specific diagnostic, not a general x86 stack analyzer.

The baseline map reaches all 4,206 native and 4,060 candidate instructions,
has no conflicting ESP depths at joins, and balances both return paths.
The same checks pass for all 75 controls. Direct-call cleanup is explicit;
Grim virtual-method cleanup comes from the hash-pinned header. Unknown direct
calls, unsupported ESP writes, and indirect jumps are rejected.

Native storage observations in the early movement and Fire Cough region:

| Value or use | Native entry-relative homes |
| --- | --- |
| Previous position snapshot, `0x4136f9/0x413700` | −40 / −36 |
| Fire Cough jittered aim | −32 / −28 |
| Fire Cough relative muzzle offset | −24 / −20 |
| Fire Cough projectile point, then smoke velocity | −16 / −12 |
| Fire Cough subtraction output | −48 / −44 |

In the later smoke-color region, `0x415aae..0x415ace`, the blue and alpha
components occupy −8 and −4. These are the only explicit native accesses to
those two homes. The canonical scratch instead places the previous position
at −48/−44 and uses −8/−4 for the Fire Cough jittered aim.

Physical home reuse does not establish original variable identity. In
particular, removing the hoisted `random_offset` and introducing scoped
vectors does **not** recover the native frame: the two simple four-vector
controls move the previous position to −16/−12; the selected-player control
leaves it at −48/−44. The frame map rules out treating that source cleanup as
a solved lifetime problem.

## Separate Fire Cough questions

At `0x413b7f`, native calls `vec2_sub` with the selected player's position as
the receiver, then consumes the returned EAX: X load, Y load, `fxch`, `fpatan`.
The canonical source calls through the original player position and loads the
named output afterward. Consuming the return pointer restores that ownership
relationship in the expression, but its compiled load order still differs.

At `0x413ba2..0x413bbd`, native forms a separate projectile point from the
relative muzzle offset plus the original player position. After
`projectile_spawn`, it reuses that temporary's homes for smoke velocity and
translates the retained relative offset for the smoke call. The canonical
source translates its muzzle vector in place before the projectile call.

The controls test these independently and in combinations. They are source
and compiler experiments, **not execution-equivalence proofs**. No new gameplay
bug is claimed from hypothetical callback mutations. Earlier vector ABI
evidence already establishes the exact small `vec2_sub` implementation; this
package does not count that helper again.

## Recorded controls

| Prefix | Count | Question |
| --- | ---: | --- |
| `cough-returned-` | 2 | Pointer versus reference consumption of the returned vector |
| `cough-positions-` | 9 | Separate projectile and smoke position expressions |
| `cough-reuse-` | 27 | Output-home reuse and component evaluation order |
| `cough-owner-` | 6 | Selected-player receiver and index ownership |
| `cough-class-` | 8 | Empty construction/destruction and vector addition |
| `four-vectors-` | 6 | Scoped aim vectors and smoke direction scalars |
| `default-ctor-` | 6 | Empty versus zero-initializing constructors |
| `smoke-scalars-` | 3 | Cached cosine and sine stored as scalars |
| `position-expressions-` | 8 | Y temporary or constructor-shaped position addition |

Some source changes produce identical bodies, including both returned-value
consumer spellings. Others change storage without changing the ratio:
`smoke-scalars-xy` keeps the baseline count, ratio, and reference audit but has
a different body hash. The higher-ratio `position-expressions-scratch_pos-temp-y`
control loses aligned references. These are reasons to inspect individual
instruction and lifetime differences rather than rank the sources by score.

`controls.json` stores line-span edits against the pinned baseline, source and
body hashes, native matcher measurements, compiler flags, dependency hashes,
and compiler-tree identities. It includes successful compiler experiments
only. Whole compiler objects and disassembly stay in the replay directory.

## Reproduce

From the repository root, with the pinned VC6 compiler and Wine available:

```sh
uv run --no-sync python tools/match/evidence/player-frame-controls-2026-09-14/replay.py \
  --out /tmp/player-frame-replay --select '.*' --frames
uv run --no-sync python tools/match/evidence/player-frame-controls-2026-09-14/frame_map.py \
  /tmp/player-frame-replay/baseline
```

Use a fresh output directory. Omit `--select` to compile the baseline and
`cough-returned-pointer` only. Add `--reconstruct-only` to check source recipes
without invoking the compiler. Run `frame_map.py` on any reconstructed and
compiled control directory (or use `--frames` during replay) to produce its annotated assembly, ESP depths,
and reachability/return summary. `results.json` records the completed full
replay and frame checks; exactness remains false throughout.
