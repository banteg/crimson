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

Two recorded sweeps tested 14 source-level lifetime variants around the
template field and its interior pointer. All were byte-neutral for the tested
declaration positions, scopes, qualifiers, aliases, and initialization forms.
A separate ten-profile compiler matrix found base, `/Ob1`, `/Ot`, `/Oa`, `/Ow`,
`/Oi-`, and `/G5` neutral, while `/G6`, `/Op`, and `/Oy-` regressed. These are
bounded source and profile observations; they do not establish the original
source shape, compiler causation, or a limit on future recovery.

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

## Focused follow-up (2026-09-05)

Six metadata-subobject and template-relative count forms were tested against
91.23%. Template-first inner ownership is neutral, while heading-first and
outer-owner forms regress. These forms do not recover the native retained
template pointer and stack copy.

The complete bounded matrix is recorded in
`spawn-parameter-owner-followup-mutations.json`. No source change is retained;
this result bounds these specific hypotheses only.

## Batch 02 focused value boundaries (2026-09-05)

`batch-02-focused-value-boundaries-mutations.json` records 4 complete, compiling
controls against the 91.228070% baseline. The source forms are
`template-relative-heading`, `template-relative-record`,
`template-cursor-outside-count`, `spread-from-index`.

No control improves the retained baseline without a metric tradeoff. Canonical source
and configuration are unchanged. These results bound the recorded hypothesis, not the
function's matchability.


## Spawn-loop source ownership controls (2026-09-07)

Four complete representative controls in
`spawn-loop-source-ownership-2026-09-07-mutations.json` cover a whole-loop
position/template/count helper, a direct SDK-form vector-add expression at the
spawn call, and template/heading cursor ownership derived either from each
current entry or from the retained scan cursor. All four compile with no
unresolved or mismatched references. The helper, vector expression, and
member-refreshed cursor each retain 91.228070%, 113/115 instructions, prefix 51,
and `13/0/0` references. Retaining and advancing the scan cursor instead regresses
to 44.255319%, 120/115 instructions, prefix 0, and `8/0/0` references.

None produces the exact native 115-instruction body. Canonical source is unchanged. These controls bound the
specified source boundaries, not the function's matchability; broader sources
and results from this run remain in `/private/tmp/timeline-review`.

## Distinct VC6 build controls (2026-09-09)

The [bounded address-allocation record](../../evidence/address-allocation-controls-2026-09-09/README.md)
compares the current source across five independently fingerprinted VC6 builds.
None improves this candidate; canonical source and configuration are unchanged.

## Template-pointer removal trace (2026-09-10)

The [verified C2 trace](../../evidence/vc6-timeline-address-2026-09-10/README.md)
locates removal of the local template-pointer `LEA` and `COPY` inside
`C2+0x306c1`, before global allocation finishes. The preserving observer emits
the same whole COFF object as normal compilation, except for the timestamp.
The original nodes disappear rather than receiving new source-line labels.

This identifies a concrete transformation in the candidate. It does not
explain the native pointer home store or establish that keeping those nodes
alone would make the function exact. The source remains unchanged at
113/115 instructions, prefix 51, 13 clean references, and non-exact encoded
body; no new source match is claimed.

## Redundant-store research (2026-09-11)

The [web research and stock-VC6 positive control](../../evidence/vc6-redundant-stores-2026-09-11/README.md)
identify three adjacent overwritten stack stores in the byte-exact
`dx_get_version_from_dxdiag` reconstruction. They arise from intrinsic zeroing
followed by field assignments; explicit `memset` remains exact. This supplies a
reproducible analogue for compiler-pass investigation, but does not yet explain
the timeline's derived-pointer home store or improve its candidate.

## Source-boundary follow-up (2026-09-11)

The canonical build remains **91.228070%**, 113/115 instructions, prefix 51,
`13/0/0` references, and `body_byte_exact: false`. This follow-up adds **zero
matches** and retains no candidate source or compiler-configuration change.

The recorded sweep evaluates 98 complete controls with zero compilation errors:
table indexing and scan ownership, loop placement, positive-count and whole-group
inlining, explicit object copies, early entry-cursor advancement, pointer
definitions inside the spawn loop, scalar types, aggregate spawn state, and
reference-returning accessors. Of these controls, 49 retain the baseline score;
the others regress. None restores the native template-pointer setup and dead
home store. The full result set is in `experiments.jsonl`.

The adjacent [source generator](source-boundary-controls-2026-09-11.py) pins the
canonical source hash and reproduces all 98 tested sources byte for byte. Its
generated mutation-plan SHA-256 is
`4ed2622a03304b4f58577a953297d1509b4a520bd26d8b3c68e475bcba2ac98a`.
Replay from the repository root:

```sh
python3 tools/match/scratches/quest_spawn_timeline_update/source-boundary-controls-2026-09-11.py \
  /private/tmp/quest-timeline-source-boundaries.json
.venv/bin/crimson match mutate tools/match/scratches/quest_spawn_timeline_update \
  --spec /private/tmp/quest-timeline-source-boundaries.json --jobs 6
```

Read-only inspection of the stock C2 pass at RVA `0x306c1` showed its derived
address/copy eligibility and intervening-definition checks. This motivated the
early-cursor and reference-lifetime controls; it does not explain how the native
home store arose. The compiler was not patched for these source experiments.
The previously recorded preserving observer remains the dynamic evidence for
where the canonical pointer is removed. These controls leave the target open.

## Dxdiag pass comparison (2026-09-11)

The [preserving two-function trace](../../evidence/vc6-store-pass-comparison-2026-09-11/README.md)
locates dxdiag's intrinsic expansion in `C2+0x29511`. Its four zeroing stores
have memory operands; the following assignments to the same field symbols
temporarily have register/temporary operands until `C2+0x26d75`. All eight
writes survive the later pointer-folding pass. The timeline's pointer instead
reaches `C2+0x306c1` as a temporary definition, and its `LEA`/`COPY` identities
are removed. Both observed whole objects equal their stock builds except for
the COFF timestamp.

Twelve implicit pointer-wrapper copy/assignment/return controls motivated by
this distinction compile cleanly but retain the same 91.228070%, 113/115,
prefix-51 candidate with 13 clean references and a non-exact body. Their
reproducible generator and full results are adjacent to the trace. This
explains the difference between these candidates' compiler paths; the native
timeline pointer home store remains unexplained.

## GPT Pro hypothesis tests (2026-09-11)

The [consumer and predicate traces](../../evidence/vc6-timeline-consumers-2026-09-11/README.md)
test the consultation's proposed mechanisms. The canonical heading/ID load
nodes still use derived bases before `C2+0x306c1`; both are rebased to entry
inside that routine. The earlier-rewrite/later-definition-cleanup explanation
therefore does not describe this candidate. Pointer-relative heading has a
different COPY-forwarding history through `0x30308`, despite identical final
normalized instructions.

Rebuilding the 98 recorded sources recovers a useful partial positive:
`advance-after-pointer-template-relative` retains both field loads through its
template pointer. Its watched definition reaches `0x309bb` as COPY and is
rejected; the canonical definition reaches the predicate as LEA and is accepted.
Actual return values are observed with unchanged whole COFF output. This
explains the address-retention distinction, but the partial source regresses to
162 instructions/27.436823%, has reference debt, and produces no dead pointer
home. It is not retained as a matching source.

Ten additional source/profile controls test a scoped assignment, a pointer-object
`memcpy` with/without intrinsics, a generic const-reference helper against a
by-value control, and an actual embedded ID object. Ordinary four-byte `memcpy`
is scalarized during `0x130cb` and does not enter the late memory-store path.
The embedded accessor returns the baseline instructions; the two generic
helper forms produce identical regressed instructions. The native immediately
overwritten pointer-valued write remains unexplained. Canonical source, flags,
113/115 instruction count, 91.228070% score, 13 clean references, and non-exact
encoded body are unchanged.

## Source-shape controls (2026-09-12)

The canonical build remains **91.228070%**, 113/115 instructions, prefix 51,
`13/0/0` references, and `body_byte_exact: false`. This sweep adds **zero
matches** and retains no source or configuration change.

The recorded sweep evaluates 232 complete controls with zero compilation
errors, all generated by [source-shape-controls-2026-09-12.py](source-shape-controls-2026-09-12.py)
(plan SHA-256 `335417e6908ef3d92af778f6543e280a7dcd3d4244f353044076f84962e76447`).
Ten families target the native interior template-id pointer and its overwritten
stack home: inline call wrappers with every reference/pointer/value parameter
spelling, non-POD return temporaries and const-reference bindings, memory-class
holders (arrays, unions, 8/12-byte aggregates, `__int64`), by-value pointer
parameters to inlined group helpers with caller-retained uses, out-parameters by
pointer and reference, multi-word aggregates holding the pointer, short-lived
scoped holders, pointers derived from sibling fields, `this`-anchored methods on
heading/template sub-object views, and redefined entry-base copies. 183 controls
retain the baseline; 49 regress.

Regression buckets: heading passed by value through a wrapper (82.96%, 114
instructions), address-taken pointer or const-reference to a returned
temporary (87.71%, x87/push reordering), aggregate spawn state containing the
pointer (63-78%, prefix 1), and sub-object `this` methods or caller uses that
split the entry cursor into two induction pointers (28-44%, prefix 0). Three
regressed controls retain a `lea [esi+0xc]` (null-initialized outer pointer
cleared after the loop; 8-byte aggregate copy; same-value entry reassignment)
but none reproduces the dead pointer home store. A plain C translation of the
same logic compiles to 78.07% with a different prologue schedule.

Scanning the 31 cached native listings for `lea reg, [base+disp]` followed by
`mov [esp+X], reg` then `mov [esp+X], other` finds the idiom only here within
that listing set. These tested C++ spellings do not explain the pointer home;
they do not establish source exhaustion.
Replay from the repository root:

```sh
python3 tools/match/scratches/quest_spawn_timeline_update/source-shape-controls-2026-09-12.py \
  /private/tmp/quest-timeline-source-shapes.json
.venv/bin/crimson match mutate tools/match/scratches/quest_spawn_timeline_update \
  --spec /private/tmp/quest-timeline-source-shapes.json --jobs 8
```

## Second pointer-removal route (2026-09-12)

An [isolated diagnostic replay](../../evidence/vc6-timeline-late-removal-2026-09-12/README.md)
changes exactly one template-pointer eligibility return at `C2+0x309bb`.
The LEA then survives `0x306c1`, but is removed inside the later `0x32216`:
its node identity disappears and the ID load is rebased to the entry. Additional
observation hooks preserve each parent COFF, apart from timestamps.

The intervened output has 113 instructions, 84.210526% agreement, and no dead
pointer home. It is diagnostic evidence, not a source match. Preventing the
first folding decision alone is insufficient for this candidate. The later
routine's address-substitution conditions are a concrete next investigation
target; the memory write and frame-slot overlap remain unexplained.

A broader adjacent-store screen across both original executable sections finds
only the timeline pair and three known dxdiag zeroing pairs. Canonical source,
flags, 91.228070% agreement, 113/115 instructions, prefix 51, and 13 clean
references are unchanged.

## Rematerialization and actual cursor motion (2026-09-12)

The [follow-up trace and source controls](../../evidence/vc6-timeline-rematerialization-2026-09-12/README.md)
identify the late path as `0x32216 -> 0x526d3 -> 0x527b2 -> 0x1f578`.
For the surviving canonical LEA, the candidate collector succeeds and the late
predicate accepts substitution. Under the pinned `/O2` profile, its use-cost
and definition-cost helpers return 0 and 1, with the size-cost branch bypassed.

Rejecting both the early and late substitutions retains `lea edi, [esi+0xc]`
and the ID load through EDI, but produces no pointer home store (114
instructions, 85.589520%, prefix 14, 12 clean aligned references). Intervening
at the early base-conflict check instead gives the same result. These are
diagnostic compiler interventions, not candidate matches. They show that
retaining this pointer alone does not automatically generate its native home.

The earlier `ptr-bump-restore` control actually used `template_id += 0`.
Its source and label remain stable; its misleading generator comment is fixed.
Twelve real cursor-motion controls and eight reference/pointer counterparts
now exercise sequenced increments/decrements. A float-value control keeps EDI
and emits an unused heading home, but its trace starts with a memory-class
float store and later rewrites the float load/store pair to integer copies.
It does not produce the native pointer-valued overwrite. No control improves
the canonical source. Six source/context controls and ten successful debug/
exception/incremental-profile controls reproduce baseline instructions;
two `/ZI` controls fail because `/ZI` conflicts with `/O2`.

## Source-produced dead pointer store (2026-09-12)

The [next witness](../../evidence/vc6-timeline-pointer-home-2026-09-12/README.md)
reproduces `lea edi, [esi+0xc]; mov [esp+0x10], edi; mov [esp+0x10], ebx`
with the stock compiler. A byte loop copies a two-pointer object, but only the
last copied member is used. Global optimization recognizes a copy intrinsic;
late lowering emits both member stores. The used member becomes a temporary,
while the unused member remains a memory store with the same node and symbol
through the remaining observed passes. The final stores are adjacent, so the
pointer-valued memory write is dead.

This is a diagnostic source witness, not recovered original source. Its
115 instructions have 71.304348% agreement, prefix 1, 12 clean references, and
a non-exact body. It reserves 32 stack bytes instead of 28, and zero-register
sharing/count tests differ. Canonical source and flags remain unchanged at
91.228070%, 113/115 instructions, prefix 51, and 13 clean references.

The witness demonstrates that the write need not be a spill of the live pointer:
an unused copied member can hold the same value. Replacing the loop with
`memcpy` or assignment, or reducing it to a wholly unused scalar copy, removes
the witness. The full 119-variant follow-up yields no match. Three preserving
traces verify whole-COFF equivalence except timestamps and reject missing
streams. An overlapping-byte-range audit rejects six partial-read false
positives from the historical equal-slot screen; the adjacent witness passes.
