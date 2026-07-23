# `input_key_name`

Native target: `crimsonland.exe` at `0x004036d0` (2970 bytes).

Exact MSVC 6.5 `/O2 /GB` match: 1097/1097 normalized instructions and all
256 references resolve. The custom-device half is one ordered `if`/`else if`
chain with a single final buffer return. That source shape is material: VC6
emits the native linear comparisons and alternates inlined `strcpy` bodies
with one shared copy tail. A dense custom-key `switch` instead produces a
non-native jump table.

Recovers the complete input-label policy. Codes above `0xff` cover five mouse
buttons, wheel directions, twelve joystick buttons, POV directions, three
axes and rotations, and the raw-input device/button namespace. Recognized
custom labels are copied into the shared 64-byte buffer. Unknown values up to
`0x163` preserve that buffer; higher unknown raw-input values become
`"RawInput ?"`; `0x17e` explicitly becomes `"unbound"`.

Keyboard scan codes first use `GetKeyNameTextA(scan << 16, buffer, 63)`. If
Windows supplies no localized label, the function falls back to the complete
DirectInput `DIK_*` table and returns the native static label, including the
single-character alphabet labels.

The DirectInput fallback compiles to a 237-byte case-id map followed by a jump
table. `input_key_name_dik_dispatch_map` names the native byte map at
`0x004044b0`; the scratch-local `$L43706` alias binds VC6's generated COFF
symbol so the table reference is audited rather than ignored. Compatibility
defines supply the DirectInput 8 scan-code constants missing from VC6's
bundled older `dinput.h` without changing generated code.

The implementation now lives in
`tools/match/include/input_key_name_impl.h`. The standalone scratch includes
it unchanged and remains exact; `controls_menu_update` defines
`CONTROLS_INLINE_KEY_NAME` to reproduce the three native force-inlined copies
without duplicating or diverging the recovered label policy.
