# grim_config_dialog_proc

`grim_config_dialog_proc` at `0x10002120` owns the legacy launcher's main
configuration dialog. It filters display adapters through the required 16-bit
and 32-bit `CheckDeviceType` probes, parses the selected mode string into the
persisted width, height, depth, and windowed globals, and routes the website,
manual, parental-lock, and advanced-settings commands.

The diagnostic `sprintf` promotes the one-byte BPP flag through the native
32-bit storage load and masks it back to `0xff`. The MSVC 6.5 `/O2 /GB /W3
/GR- /MD` reconstruction matches all 404 instructions, all 86 references, and
all 1,318 bytes. This callback remains `platform-replaced` for port ownership,
but its exact object is included in the recovered Grim platform provider.

## Freeware builds

The 1.0.2 launcher has two color depths and a hardware capability check
for windowed mode. Later freeware releases enumerate adapters and populate a
fixed-size resolution list. Both read the top visible list index when the Run
button is pressed. The 1.4.0 launcher also exposes safe mode and sound
controls and chooses its website link from the system date.

The final return in 1.0.2 ends at 0x100012c0, directly against the next
function. The 1.4.0 callback ends at 0x100016ca. Two bytes of alignment and
thirteen WM_COMMAND jump-table addresses fill the remaining space before
the next function. Every destination is inside the callback's code.
