# `quest_build_deja_vu`

Native target: `crimsonland.exe` at `0x00437920` (209 bytes).

Live Binary Ninja evidence recovers 18 radial waves of four aliens each. The
trigger starts at 2000 ms. Its step also starts at 2000 ms, falls by 80 after
each wave, and continues while the next step is greater than 560. Each wave
uses `(crt_rand() % 612) * 0.01`, radii 84, 126, 168, and 210, center
`(512, 512)`, template `0x0d`, and count 1. The native writes the constant
final count 72.

The key source-shape recovery is the two-stage vector construction. A rounded
radial offset is constructed first and then translated by `(512, 512)`. This
reproduces the native 24-byte frame and its x87 sequence, including the saved
cosine, live sine, rounded x product, and copied final position words. The typed
trigger-field cursor makes the native induction base explicit without changing
the record layout. Publishing the position through the record view and the
metadata through that trigger-field cursor preserves their distinct source
ownership and recovers the native late metadata stores. Giving the trigger step
an ordinary local lifetime before constructing the cursor recovers the final
prologue order. The result matches all 63 instructions and all four audited
references exactly.

## Recovery classification audit

The live Binary Ninja loop accounts for all 18 waves, random-angle reduction,
four radii, translated vector construction, trigger recurrence, metadata, and
the constant count 72. The candidate is an exact normalized instruction and
reference match, so no recovery or compiler residual remains.

## Recorded mutation evidence

`trigger-cursor-mutations.json` evaluated four record/field cursor forms. The
retained typed current-record cursor adds 1.94 weighted bytes and is the only
improving form. Thirteen declaration/lifetime combinations and four
entry-store boundary forms were then exhaustively checked; they were neutral,
failed to compile, or regressed. Their complete scores are recorded in
`experiments.jsonl`.

## 2026-08-08 split-publication exact recovery

The earlier boundary sweep wrote metadata through the record pointer, leaving
VC6 free to hoist it across the x87 position work. Writing position through
`wave_entry` but template, trigger, and count through `entry_trigger[-1..1]`
raises the candidate from 84.13% to 98.41% while preserving 63/63 instructions
and references 4/0/0. Hoisting the semantic `trigger_step_ms` declaration out
of the `for` initializer and placing it before the trigger cursor recovers the
last stack-store/LEA ordering swap. Retained source SHA-256:
`1f8b55703adb9ef197648f1a36d298506c893c6dab08ac1097047bbc7b80a0e0`.
