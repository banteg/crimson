# Port review implementation

The actionable bugs in the review are fixed. The unfinished custom network stack
was removed from both ports at the user's request. The deterministic session,
local co-op, replay tools, native arithmetic helpers, pool identity, and
synchronous death ordering remain the core of the implementation.

The original [report](REPORT.md) and hashed evidence describe commit
`9ec5ea665f275bd075ebaea9af819c6574058d6d`. Their probe script deliberately uses
that revision's APIs and asserts the old failures. Its hashes are unchanged; it
is historical evidence, not a test for the current implementation.

## Correctness changes

| Review IDs | Result | Commit |
| --- | --- | --- |
| B2, B3 | Pending edges survive zero-tick render frames. Later ticks preserve held controls and explicit movement/aim modes. Pause clears pending edges. | `535d2f726`, `db2bed527` |
| B1 | Python and Zig Freeze use current active/dead guards, including same-tick kills and corpses below the lifecycle cutoff. Removed corpse snapshots and unused deferred effect plumbing. | `c4a6a470c` |
| B5 | Python Man Bomb uses native float constants and PC24 operations in instruction order. Stored-angle bits are tested at three jitter values. | `92414a212` |
| B4 | Quest sound/music requests belong to immutable tick plans. Live, replay, and headless presentation share one consumer. Mode stop decisions run before another tick; the final tick is recorded before game-over can save the replay. | `db2bed527` |
| B6–B8 | Removed custom LAN/rollback/lockstep/relay implementations, wire formats, lobby UI, CLI commands, and adapters in both ports. Local co-op and replays remain. | `bc45c5b6a` |

The same-tick kill/Freeze regression now records nine Freeze angle draws and
212 total RNG draws, including effect helpers, instead of the old 119. This is
an intentional deterministic behavior correction. Recordings produced by the
old implementation that encounter this discrepancy can diverge when replayed
with the corrected implementation.

## Structural changes

| Proposal | Implementation | Commit |
| --- | --- | --- |
| S1 | Flattened session tick payloads, moved profiling outside them, removed reaction reconstruction and several one-method application adapters, and made batch stopping immediate. | `db2bed527` |
| S2 | `SimWorldState` owns one world and derives its children through properties. Moved concrete `GameplayState` into its own module, removed the runtime `object` alias and trivial construction wrapper. Zig quest slices now derive from owned storage. | `191a614d6` |
| S3 | Replaced the two-entry clip modifier registry and singleton Poison Bullets registry with direct ordered code. | `8eb246d59` |
| S4 | Damage resolution is required for projectiles, particles, and bonuses. Removed production HP-only fallbacks. Lethal handling takes a required synchronous callback; reduced recording fakes live in test support. | `2dc088f79` |
| S5 | Normalize player slots once at the world boundary and pass immutable inputs through the runner/session. Removed redundant object/list/tuple reconstruction. | `adecc3fcc` |
| S6 | Extracted player movement, reload, and low-health phases; corpse and periodic self-damage updates; and secondary-projectile movement/steering, trails, and detonation. | `bab75bd23`, `0948d4d27`, `ef348df21` |

The main `player_update` is now 190 lines, `CreaturePool.update` 429, and
`SecondaryProjectilePool.step` 281, compared with 505, 499, and 459 in the review.
Their operation order and native arithmetic expressions were retained.

The broader perk manifest, bonus/projectile variation tables, native ownership
encoding, and explicit view/configuration caches remain. The Zig creature-effects
pointer still has explicit rebinding; the removable quest-storage slice no
longer does. A new network design and complete recoverable session format remain
future work, as requested; see [Netplay](../../../docs/rewrite/netplay.md).

## Validation

Focused checks cover exact Man Bomb angle bits, same-tick Freeze effects/RNG,
held controls, pending edges and pause behavior, quest completion audio under
multiple render partitions, real contact death during a multi-tick frame,
reset/load identity, copied Zig storage, snapshot restoration, synchronous death
follow-ups, and the existing original-capture/Python–Zig parity regressions.

The final render-partition regression compares every checkpoint, input, and
ordered presentation request at 120/60/30 Hz, including Anxious Loader, relative
movement, keyboard aim, and held reload.

Final gate: `just check && uv build`, with task-specific writable uv/Zig caches.

- Python: **2,541 passed, 10 skipped; 135 snapshots passed**.
- Zig: **611/611 tests passed**, plus ReleaseFast and WASM builds.
- Ruff, import boundaries, types, docs, structural rules and rule fixtures passed.
- Matching experiment validation: zero strict errors; matching regressions: zero errors.
- Native artifact digests and game-owned closure are current for both binaries.
  This checks repository artifacts; it does not rerun the original executable or
  establish closure for external references.
- Python source distribution and wheel built successfully.

The obsolete LAN-framework lint rule and its fixtures were retired with the
final validation tests. The historical evidence hashes remain unchanged.

The native evidence is original-instruction inspection plus existing capture
fixtures. No fresh original-game capture or interactive visual playtest was
performed during this implementation.
