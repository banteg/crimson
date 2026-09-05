# Systems review and fixes — 2026-09-06

Reviewed progression, collision and pool reuse, terrain/rendering, local co-op,
and configuration after the earlier architecture, screen, input/assets, and
audio reviews. Python was the primary target; corresponding Zig behavior was
checked and corrected. This report records the reviewed changes, not a standing
refactor plan or a claim that every function has been exhaustively verified.

## Resolved findings

| Area | Failure and correction | Evidence and regression coverage |
| --- | --- | --- |
| Score history | Saving rewrote only the current top 100; dated views filtered after that cutoff. Persistence now retains history, filters before ranking/capping, and uses the same date policy for qualification, saving, and browsing. Zig writes use atomic replacement. | Native `highscore_save_record` opens normal saves in append mode; `highscore_load_table` filters dates while reading. Python and Zig tests save a current score behind 105 better historical scores and retain all 107 records. |
| Score ordering and display | Quest health/perk bonuses can produce negative final times. Unsigned accessors ranked/displayed them as huge values; Zig's record builder also clamped them to zero. Time accessors now expose signed values, zero sorts last for quests, and ranking shares the table comparator. | Native signed score comparators in `tools/match/scratches/highscore_compare_*`; negative-time save/read/display and Zig record-builder tests. Survival/Rush comparisons also follow signed native comparisons. |
| Score names and failure recovery | Python trimmed a copied name buffer. Zig removed the first character of an all-space name, unlike native. Quest results reported failed score writes as saved; configuration failures could also duplicate Zig score writes on retry. | Native `highscore_save_record` trims in place only while the index is greater than zero. Real-file trimming tests and a failed-write/retry test cover Python results. Both ports save configuration before publishing a score, and only mark successful score writes saved. |
| Statistics | Python counters could exceed the `u32` save fields and make `game.cfg` unwritable. Gameplay playtime also used wider-than-native rounding. | Increment helpers and playtime now wrap at 32 bits; playtime uses the shared f32 millisecond conversion. Save roundtrip/overflow tests. Zig already wrapped increments; its displayed aggregate now wraps too. |
| Zig persistence checks | Persistence tests were not part of `zig build test`. Enabling them exposed invalid typed expectations and a one-month error in UTC fallback dates. | The library test target includes persistence and links libc for local dates. The existing epoch/calendar tests now run and pass. |
| Collision and slot reuse | The spatial index captured only existing creatures, missing children spawned by splitting enemies during projectile damage, including later slots in the same explosion. Same-cell size changes also left a stale search margin. | Native projectile loops scan live slots in index order. Split-capable frames use that scan; ordinary frames retain the spatial lookup. A production explosion/death test hits newly born children immediately. Margin updates use the common native radius calculation; redundant bucket-size state was removed. Zig already uses live linear scans. |
| Terrain and shaders | Python target bindings were not unwound if shader setup/drawing failed. A global cached shader outlived its graphics context. Zig deactivated its alpha-test shader at the end of an `if` block, before actual terrain drawing. | Target scopes unwind with `finally`; pending generation survives exceptions; unsuccessful target setup releases its allocation. `GroundRenderer` and `RuntimeResources` own their shader handles and release them. Zig shader cleanup encloses the draw passes. Failure/reload/cleanup tests and builds pass. |
| Render imports | Importing a projectile renderer first caused an import cycle through `render.world`'s eager `WorldDrawContext` re-export. | Removed the re-export and used the concrete module. Standalone projectile/render test collection now succeeds. |
| Co-op HUD | Speed, Shield, and Fire Bullets indicators only followed players 1 and 2. P3/P4 bonuses could disappear while active or reset their slide animation on another pickup. | Replaced string timer references and primary/alternate fields with typed bonus lookup and a timer sequence. Python and Zig keep native 1P/2P bar positions and extend to 3P/4P. Tests cover each player count, registration, expiry, and four-bar rendering. |
| Run configuration | Python copied detail/gore settings from mutable Options into an active session, while replays retained the starting values. These settings affect RNG consumption. | Active sessions retain their `RunSpec`; the next run captures new settings. Removed redundant settings accessors and writes in base/quest/tutorial paths. A live tick test changes config, verifies the active session, then verifies the next run. Zig already captures these settings at startup. |
| Gamma and console values | Wrapping the scene in a gamma shader failed when inner world/UI shaders reset the binding. Cached gamma resources also lacked cleanup. Nonfinite numeric commands could alter rendering or fail integer/save conversion. | Gamma now composites the completed frame from a framebuffer sized for the display's pixel density, after inner shaders finish. The loop owns/resizes/releases its resources. Console commands reject invalid/nonfinite input; saved playtime is bounded to its wire field. Tests cover compositing order, DPI dimensions, resource failures/reuse, and numeric commands. Zig has no corresponding console gamma path. |

## Deliberate behavior retained

- The port's deterministic run/session boundary and presentation separation.
- Native quest score filename inversion and the 40 tracked quest attempt slots.
- Shared perk selection and documented native player-zero ownership quirks.
- The existing 3P/4P nearest-living-player targeting and living-player camera focus.
- Pool-specific exhaustion policies: creature allocation can fail; particles use
  the native random overwrite; effects use their established overwrite cursor.
- Bilinear terrain sampling remains an intentional port choice.

Attempts, completion/unlock updates, retries, per-player score paths, target
selection, pool allocation/expiry, and terrain FX ownership were inspected.
This pass did not identify another concrete fault in those inspected paths.

## Commits

- `6d8431b1f` — score history/ranking, save recovery, counters, Zig persistence checks.
- `b09f8bd73` — live collision scans for split children and current size margins.
- `33221f8a5` — render scopes, shader ownership, and import-cycle removal.
- `0c55b6fe4` — all-player bonus timers and simpler HUD state.
- `76c675c96` — run settings, full-frame gamma, and numeric command validation.
- `1acedecb1` — signed quest time construction, persistence, and display.

## Validation

Focused validation passed: 319 creature/projectile tests and 85 snapshots;
171 renderer/projectile/resource tests with 7 skipped and 9 snapshots;
374 bonus/perk/player/HUD tests; 31 console/session tests; signed score
roundtrip/display tests; and 670 Zig tests.

Final validation passed:

- `just check`: lint/import/type/docs checks, native artifact and matching
  regression checks, structural rules; 2,747 Python tests passed with 10 skipped
  and all 135 snapshots passed; 670 Zig tests passed; ReleaseFast and WASM built.
- `uv build`: source distribution and wheel built.
- `uv run --no-sync scripts/check_docs.py`: 136 pages and 136 navigation entries.
- `uv run --no-sync zensical build`: documentation site built.

This session has no active graphics display. GPU-dependent fixture skips do
not establish pixel parity. The rendering tests verify compositing order,
DPI dimensions, ownership, and exception cleanup. This pass does not claim a
live 2–4-player controller session, a live native capture, or native screenshot
comparison for the new gamma/terrain shader behavior.
