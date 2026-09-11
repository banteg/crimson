# Native player aim direction and port correction

The native `player_update` keeps the cosine result wide until multiplying by
60, but stores the sine result to float32 before that multiplication. All
subtractions, products, and sums use gameplay x87 PC=24. The old C++ scratch
stored both trig results early. Giving the three cosine values their own local
lifetime removes the premature store with the canonical VC6 compiler.

Python's gameplay helper had the same early cosine store and also kept the
scale/add expression wide. Local input used host-double heading conversion and
arithmetic. Both now share `native_aim_point_from_heading`. Zig local input
used `cos(heading), sin(heading)` directly instead of converting the native
heading by subtracting the native half-pi constant. Its new helper also
preserves the asymmetric trig stores. Keyboard and POV turns now round each
step in local input; both Python aim paths and Zig evaluate POV left before
right, as native does.

## Evidence and limits

`verify.py` executes the original executable and compiled before/current C++
for 3,738 deterministic full-function cases. These include entry/death cases,
all six-by-six movement/aim mode combinations, 300 movement, 600 firing,
900 perk/reload/alternate-weapon, 600 aim/target, 1,050 point, and 240 held-turn
cases. Every current observation agrees; the old source differs in 46 cases.
The comparison includes ordered callback arguments and final bytes for all
whitelisted state regions. Writes outside those regions fail; intermediate
write sequences are recorded by the runner but are not equality criteria.

The original movement/spawn-avoidance, heading approach, vector length,
vector subtraction, and CRT conversion helpers execute as machine code.
Input, random, D3DX normalization, effects, allocation, damage, reload, and
sound boundaries use explicit deterministic models. Allocation returns bounded
indices; damage/reload callbacks do not simulate their downstream effects.
The image, helper bodies, compiler output, source, fixture layout, and harness
hashes are recorded. Unknown execution, unexpected writes, stack imbalance,
changed callee-saved registers, and changed x87 control/tag state fail.

Coverage is 4,077/4,206 native and 3,944/4,060 current body instructions.
This is a bounded call-boundary execution proof, not whole-game equivalence,
full input coverage, exact matching, or pixel validation. The simultaneous POV
left/right cases test callback ordering; they do not claim that a normal
single physical hat can hold both directions simultaneously.

The native 1,050-point and 240-turn witness sets are shared by Python and Zig
regressions. Actual Python gameplay/input dispatch and Zig input dispatch
consume them. `verify_ports.py` additionally measures the pinned prior commit:
170/1,050 Python gameplay stored points, 716/1,050 Python local-input stored
points, and all 1,050 Zig points differ before the fixes. Current paths have
zero differences, including Zig Debug and ReleaseFast. These counts compare
stored float32 coordinates; Python's wider intermediate values are reported
separately. Host trig implementations are tested on these witnesses, not
claimed universally identical to x87 transcendental instructions.

The fuzzy matcher tradeoff is explicit: 64.0473887814% -> 64.0212920397%,
4,066 -> 4,060 candidate instructions, seven-instruction prefix unchanged,
805 clean / zero unresolved / two mismatched references unchanged. Weighted
matching bytes decrease by 4.2425473064. Neither source is exact or byte-exact.
`before.cpp` is the pinned negative control, not an accepted alternative.

## Reproduce

From the repository root, with the original game image and VC6 available:

```sh
uv run --with unicorn==2.1.4 python tools/match/evidence/player-aim-direction-2026-09-11/verify.py --out /tmp/player-aim-native
uv run --with unicorn==2.1.4 python tools/match/evidence/player-aim-direction-2026-09-11/verify_ports.py --out /tmp/player-aim-ports
uv run pytest -q tests/gameplay/test_player_aim_native.py tests/input/test_local_input.py
cd crimson-zig
zig build test --summary all
zig build test -Doptimize=ReleaseFast --summary all
```

The verifier checks exported witness bytes against the tracked test data.
`results.json` and `port-results.json` contain the observed results and hashes.
