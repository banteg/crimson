# quest_spawn_timeline_update

Native target: `crimsonland.exe` at `0x00434250` (368 bytes, 115
instructions).

The recovered MSVC 6.5 `/O2 /GB` source is an honest WIP:

```txt
match=91.23% prefix=51/115 target_insns=115 candidate_insns=113 refs=13/0/0
```

## Recovered source shape

- The integer stall timer resets while any creature is active and otherwise
  accumulates integer `frame_dt_ms` directly in the global.
- A six-int cursor scans the 24-byte quest entries for the first positive count
  whose trigger is strictly earlier than the quest timeline.
- The fail-safe may select a future entry only when no creature is active, the
  stall timer is strictly above 3000 ms, and the timeline is strictly above
  1700 ms.
- One update fires only the selected trigger group. Adjacent entries with the
  same trigger are consumed together, and every consumed count is cleared.
- Each entry spreads successive creatures by `0, -40, +80, -120, ...`. An
  off-screen x coordinate applies that spread vertically; an on-screen x
  coordinate applies it horizontally.
- The entry heading and template id are forwarded unchanged to
  `creature_spawn_template`. Firing any group clears the global none-active
  flag.
- The entry's first two floats are the same position value object recovered in
  the quest builders. Adding the alternating offset through its inlined vector
  operator reproduces the native x87 construction and right-to-left call-
  argument schedule for the temporary passed to `creature_spawn_template`.
- The canonical entry now exposes its first two floats both as the legacy
  `pos_x`/`pos_y` scalars and as a `vec2f_t position` aggregate. This scratch
  uses `entry->position.x/y` in the ordinary dispatch path, while still
  starting the scan from `trigger_time_ms` because the native loop is an
  evidenced six-int interior cursor.
- The dispatch loop now also uses `quest_spawn_entry_t` directly instead of a
  private layout duplicate. Its position, heading, template, trigger, and count
  accesses therefore share the canonical quest type while preserving identical
  codegen. The live Binary Ninja split `ESI` cursor was independently retyped
  to the same pointer type, replacing raw float-array indexing throughout the
  spawn and group-consumption loop.
- The authoritative Binary Ninja map presents that current entry as a
  `quest_spawn_entries_binja_t *spawn_batch`. This retains the canonical entry
  layout while giving the lookahead a real array relationship: the trigger
  group test now reads
  `spawn_batch->entries[0].trigger_time_ms !=
  spawn_batch->entries[1].trigger_time_ms`, and the cursor advance becomes
  `spawn_batch = &spawn_batch->entries[1]`. The former raw `+0x28` access is
  therefore fully recovered as the next entry's trigger field.

The first 51 instructions, complete scan/fail-safe policy, 28-byte frame, x87
spread loop, group-consumption tail, and all 13 masked references agree.

## Remaining compiler delta

Native creates an interior pointer to the current entry's template-id field
after the positive-count guard, briefly homes it in the stack slot that is then
reused by the integer spread, and loads heading/template through that pointer.
The source retains the scoped template-id pointer but expresses heading through
the recovered `entry->heading` field instead of a preceding-word cast. A shadow
probe confirms that VC6 folds both forms to identical code. The calibrated
compiler also folds the template pointer back to the typed entry base, removing
the native `lea` and dead home store. Those are the candidate's only two missing
instructions; their byte-length shift also changes local branch-label tokens in
the normalized diff. Recovering the typed position and vector addition raises
the honest score from `88.60%` to `91.23%` without changing the exact prefix,
instruction count delta, frame, or reference audit.

Adding the canonical position aggregate and using its components is
byte-neutral: the candidate remains `113/115` instructions at `91.23%`, with
the same 51-instruction prefix and `13/0/0` reference audit. The exact
`quest_build_evil_zombies_at_large` consumer also remains `81/81`.

MSVC 6.0 and 6.6 produce the same best body, 6.5pp is slightly worse, and 7.0
adds its aligned-frame prologue. `/Og-` broadly deoptimizes the function. No
volatile pointer, artificial union, dummy access, or other register-forcing
construct is retained.

Two recorded sweeps exhaust 14 honest source-level lifetime variants around
the template field and its interior pointer. All are byte-neutral, confirming
that VC6 folds the recovered pointer regardless of declaration position,
scope, constness, alias, or explicit initialization form. A separate ten-profile
compiler matrix is also closed: base, `/Ob1`, `/Ot`, `/Oa`, `/Ow`, `/Oi-`, and
`/G5` are neutral, while `/G6`, `/Op`, and `/Oy-` regress. This bounds the
remaining two instructions as a compiler-local lifetime artifact rather than
an untried optimizer flag.

## Port parity

The Python and Zig quest-timeline models already implement the recovered strict
thresholds, trigger grouping, alternating spread axis, count clearing, and
none-active reset. No port edit is required.

## Recovery classification audit

Fresh Binary Ninja HLIL confirms the complete stall selection, grouped trigger
dispatch, alternating spread, spawn arguments, count clearing, and active-flag
policy. The candidate emits 113 instructions against 115 native instructions
with `13/0/0` references. Its localized delta is the documented folded
template-field interior pointer/home store plus resulting register and x87
scheduling. The scratch is classified `semantic-complete` with a `compiler`
residual.

## Authenticated SDK vector identity replay

The MOD SDK `vec2_t` differs from the local value class in three concrete ways:
anonymous-union `x/y` plus `v[2]` storage, an assignment-body scalar
constructor, and a non-const member `operator+`. The seven complete single,
pair, and three-way combinations in `original-vector-type-mutations.json`
replay those exact features at the only inlined vector-add region.

Every combination is byte-identical to the current **91.22807%**, 113/115,
prefix-51, `13/0/0` candidate. The authenticated class spelling therefore does
not restore the folded template-field pointer/home store, and no cosmetic type
rewrite is retained. The spec SHA-256 is
`96fca03448be5ca6d9a3cf5fe98a825f584838dca866eea5da537409b218f0bd`.
