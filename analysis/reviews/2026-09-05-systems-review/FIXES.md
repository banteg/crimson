# Systems review implementation

All seven findings in [REPORT.md](REPORT.md) are implemented. Changes were
committed in separate functional chunks; the original probe results remain as
the baseline.

| Finding | Result | Commits |
| --- | --- | --- |
| R1 — run initialization | Tutorial loadout now matches replay. All five modes and playback use `RunSpec` and `initialize_run`; terrain, quest setup, loadouts and pre-start status are owned in one place. Reset and residue types no longer depend on replay DTOs. Placeholder constructor sessions were removed. | `c99b48301`, `53b606fd2`, `14b8bdbe3` |
| R2 — command timing | Live perk picks run before tick timing, matching recorded preludes. Each ordered pick observes earlier timing changes. Typ-o input keeps its separate inside-tick phase after loadout enforcement. | `23d3f5965`, `53b606fd2` |
| R3 — presentation | Completed ticks carry camera focus/shake and the audio time-scale input. Batched playback no longer samples later world state. `AudioBridge` directly consumes plans; the audio router, duplicate sound decisions and dispatch adapter were deleted. | `66c7b784f`, `3bc126b97` |
| R4 — camera latch | Python and Zig camera shake use the latched time-scale flag, including the frame after the bonus timer expires. | `09fbab75e` |
| R5 — save safety | Config, status, scores, replays and checkpoints encode first, write and fsync a temporary file beside the destination, then atomically replace it. Failure leaves the prior file and dirty status intact. | `ecfe679ef` |
| R6 — regression oracle | A complete same-build session digest includes inactive pool entries, allocator cursors, mode state, queues, timers and RNG. Profiling, file paths and tracing metadata are excluded. Sparse capture checkpoints retain their separate purpose. | `7dfa93a3c` |
| R7 — perk phases | Direct calls replace the global optional-field hook bundles and single-entry dispatch collections. The immediate-effect map remains. Global effects require creature and FX context; tests use real empty pools and queues. | `6b8a586a0` |

The run-start comparison also exposed startup weapon usage being captured after
assignment in live recordings, then counted again on playback. The shared
initializer snapshots before mutations and applies quest play/weapon counters
once. Zig quest startup now increments weapon usage for each assigned player.
Tests cover actual mode open/start, recording and playback with all five modes,
one/four configured local players, both preserve-bugs settings, and non-default
detail/violence settings.

The presentation follow-up captures the timer after mode cleanup: Typ-o clears
Reflex Boost at that point. Perk timing remains in the prelude, while Typ-o key
sounds follow its initial reload sound, consistent with the existing Zig replay
checkpoint checks.

## Evidence

[fix-probe-results.json](fix-probe-results.json) reruns the original reproductions:

- Tutorial starts with the same 12-round pistol and zero cooldown; the first shot,
  sound requests and RNG agree.
- Serial and batched audio both receive `0.00833333283662796` for the first tick's
  sound, even after the second tick expires the bonus.
- The reachable camera latch case selects the short interval (`0.06`) after expiry.
- Injected score serialization failure preserves the existing 76-byte record.
- A Reflex Boosted pick yields the same simulation delta, position and elapsed time
  through live commands and replay preludes.
- Mutations invisible to sparse checkpoints produce different complete-state digests.

[perk_traces.py](perk_traces.py) exercised each perk in 232 combinations of local
player count and preserve-bugs settings. All 928 successive full-state digests
were byte-identical before/after the phase cleanup. The compared output hashes
and baseline commit are in [perk-trace-results.json](perk-trace-results.json).
This proves preservation for those scenarios; it is not exhaustive perk-interaction
or native-parity proof. Existing behavioral and RNG tests provide additional coverage.

## Validation

- Python suite: **2,636 passed, 10 skipped**, with **135 snapshots passed**.
- The Python/docs/import/type/native/match/ast-grep stages ran through `just check`.
- Final Zig unit suite: **652/652 passed**. Startup and replay-step modules were
  added to the root test compilation in `66819af3c`, exposing 41 previously omitted
  tests. Stale test input fields and a missing ready-to-fire cooldown setup were
  repaired; production behavior was unchanged by that coverage commit.
- Final `just check-zig` passed, including unit tests, ReleaseFast and WASM builds.
- `uv build` produced both the source distribution and wheel.
- Refreshed reproduction assertions passed; serial/batched and live/replay
  comparisons agree, and failed saves retain their original bytes.

The checks include existing capture fixtures, Python/Zig replay CLI comparisons,
and native artifact/closure verification. No new original-game capture or
interactive visual/audio playtest was performed. The camera change fixes which
latch selects the interval and retains the existing Python floating-point
arithmetic. The complete-state digest is an internal comparison tool, not a new
wire format or a resumable snapshot.
