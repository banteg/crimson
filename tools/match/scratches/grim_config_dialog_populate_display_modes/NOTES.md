# grim_config_dialog_populate_display_modes

`grim_config_dialog_populate_display_modes` at `0x10001e90` initializes the
legacy launcher's display controls. It latches the renderer capability flags,
populates a fixed windowed/16-bit/32-bit mode list, and selects the entry that
corresponds to the persisted width, depth, and windowed-mode fields.

The persisted windowed flag is compared to the canonical byte value `1`, not
merely tested for nonzero. That source distinction produces the native
`cmp cl, 1` control flow. The natural MSVC 6.5 `/O2 /GB` reconstruction then
matches all 207 native instructions, all 646 bytes, and all 42 references.
This function remains `platform-replaced` for port ownership, but its exact
object is included in the recovered Grim platform provider.
