# `quest_build_the_annihilation`

Native target: `crimsonland.exe` at `0x004382c0` (278 bytes).

Live Binary Ninja evidence recovers one template `0x2b` alien at `(128,
terrain_width / 2)`, trigger 500 ms, count two. Two twelve-entry template
`0x07` columns follow. Both use y positions 128 through 832 in steps of 64.
The first alternates x 832/896, triggers 500 through 6000 in 500 ms steps;
the second alternates x 896/832, triggers 45000 through 48300 in 300 ms
steps. All column entries have count one, and the final count is 25.

The candidate reproduces the native registers, signed division by twelve,
parity branches, loop limits, update order, 24-byte stride, and output count.
Placing the loop locals after the initial position assignment preserves the
native 15-instruction prefix. The candidate has the same 77 instructions and
resolves the terrain-width reference.

The residual is induction-base selection and independent-store scheduling.
The native anchors both loops at `template_id` and addresses position through
negative offsets; VC6 anchors the equivalent source at the record start. A
metadata-only setter emits the same best result, while moving the loop-local
lifetimes earlier degrades register initialization. `msvc6.5pp` is identical.
The 74.03% candidate remains an honest WIP rather than encoding the optimizer's
negative-field cursor into the source.
