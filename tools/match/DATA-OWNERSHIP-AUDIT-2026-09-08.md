# Runtime data ownership and recovery gaps

Baseline: `058583de6`. Reference: the pinned Crimsonland 1.9.93 GOG images.

## Runtime counters and serialized fields

`quest_unlock_index` at `0x00487034` and `quest_unlock_index_full` at
`0x00487038` are four-byte runtime members, at offsets `0x8c` and `0x90`
of `gameplay_run_state_original_t`. Native quest completion loads/stores the
first dword at `0x00407240`/`0x0040724a` and compares/stores the second at
`0x00407259`/`0x00407261`. Status loading publishes dwords at
`0x00412d30` and `0x00412d35`. Status saving alone reads their low words at
`0x00412b20` and `0x00412b27`. The old data map had transferred the serialized
width to the runtime objects. The source declaration was already correct.

Native definitions now cover all four bytes and require four-byte alignment;
VC6 ABI assertions verify both member widths and offsets. Independently compiled
source definitions must reproduce the pinned zero initializers. The native
data provider uses the corrected extents when rebuilding the structural link.

`player_plaguebearer_active` is a one-byte interior label at player offset
`0x09`, not a separately owned array. Its bytes are already covered by the
matched `player_state_table`. The inventory retains that declaration note but
does not present it as unresolved byte debt. No additional credit is claimed.

## Grim state tables

`tools/native/recovered/grim/state/state_init.cpp` supplies explicit typed
declarations, loop bounds, and consumers for these engine-owned arrays:

| Object | Native address | Type | Bytes |
|---|---|---|---:|
| `grim_key_repeat_timers` | `0x1005a058` | `float[256]` | 1024 |
| `grim_subrect_table` | `0x1005a678` | `GrimUV[256]` | 2048 |
| `grim_font2_uv_u` | `0x1005b2c8` | `GrimUV[256]` | 2048 |
| `grim_subrect_table_2` | `0x1005c908` | `GrimUV[64]` | 512 |
| `grim_subrect_table_1` | `0x1005cb08` | `GrimUV[16]` | 128 |
| `grim_config_values` | `0x1005cb88` | `grim_config_value_t[128]` | 2048 |
| `grim_subrect_table_0` | `0x1005d388` | `GrimUV[4]` | 32 |

The initializer fills the UV arrays with nested grid loops, publishes the
four subrect arrays into `grim_subrect_ptr_table`, resets key-repeat timers,
and initializes the configuration array from its default record. Text and
atlas renderers consume these same identities. `grim_uv.h` shares the exact
recovered two-float class with the data compilation; it does not change the
initializer's operations. The pre-startup zero bytes are distinct from the
values written by runtime initialization. Compiled-data grouping does not
assert historical translation-unit co-residence.

## Inventory blind spot

The old inventory enumerated only native data definitions. Mapped labels
without definitions silently disappeared, although their unknown bytes stayed
in the section denominator. The inventory now joins the data map and retains
in-section labels without proven extents in `unbounded_objects`. It assigns
neither guessed sizes nor ownership and gives them no matching credit.
Code-local tables outside the data sections remain outside this backlog.

The remaining blockers are different obligations: recover source lifetimes
for the non-exact functions; prove unknown data extents and initializers;
establish additional original source ownership only from actual evidence;
and validate linked images at runtime. Structural linking and static closure
alone do not prove whole-image identity or successful execution.

## Demonstration

Compiled data increases from 304,765 to 312,613 of 517,738 bytes (+7,848).
Game/engine ownership increases from 341,469 to 347,269 bytes (+5,800),
leaving 143,170 bytes unattributed. The complete map join exposes 130 labels
without proven extents. These ownership and matching totals count overlapping
objects only once.

Two CRT entry prefixes gain archive identity as documented in
`CRT-MATH-ENTRIES-2026-09-08.md`; no source-only code credit is claimed for them.
All 793/810 normalized and 791/810 encoded-body port matches are preserved.
Both structural native links rebuild with game-owned closure and no retained
placeholders (the EXE discards all ten configured link-only placeholders).

Validation: 343 focused matching/native/report tests pass, along with repository
lint, type, import-contract, and documentation checks. The final checkpoint
reports zero scope, claim, evaluation, metadata, experiment, strict-experiment,
native, and regression errors against `058583de6`. Full-image evidence retains
the same addresses and extents and loses no normalized or encoded-body match.
The report and inventory regenerate successfully; `git diff --check` passes.
