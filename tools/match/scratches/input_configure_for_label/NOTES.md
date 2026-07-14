# `input_configure_for_label`

Exact 58-byte, 18-instruction match with MSVC 6.5 `/O2 /GB`; all eight masked
references align, including the six-way jump-table destinations.

The native source order groups the two mouse modes before keyboard and
joystick: cases `0, 3, 1, 2, 4, 5`. This is material to the case-block layout;
the compiler-generated table still maps ids in numeric order. Live Binary
Ninja shows seven uses in `controls_menu_update` and confirms the labels
`Mouse`, `Mouse relative`, `Keyboard`, `Joystick`, `Dual Action Pad`, and
`Computer`, with `Unknown` outside `0..5`.

This switch exposed an appended-COFF-table matcher bug fixed separately in
`b20caf1f`: the table is now audited structurally and excluded from candidate
instructions. The adjacent already-matched `input_scheme_label` also supplied
clear port evidence that its native id-4 label contains an ampersand. The
Python controls panel, tests, and provenance doc now use `Mouse point&click`
instead of the normalized but inaccurate `Mouse point click`.
