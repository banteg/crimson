# `ui_profile_menu_update`

Native target: `crimsonland.exe` at `0x004443c0` (1033 bytes).

Live Binary Ninja evidence recovers the complete saved-profile selector used
by the high-score screen. It constructs function-local text-input, Add/Delete
button, and list-widget state; exposes the live `saved_name_count` prefix plus
a temporary `<add new named list>` row; reloads scores after concrete selection
or deletion; and toggles the dropdown through primary input or key `0x1c`.

The editor copies submitted text into the next 27-byte slot, tracks that slot
as selected, clears the input state, and preserves the native full-list edge
behavior. Deleting a nonzero slot decrements the count, moves the last live
name into the deleted slot, and selects slot zero. The returned value is always
`false` in `AL`, and `ui_button_update` is likewise confirmed as a byte-returning
`bool`.

The natural C++ function-local statics reproduce VC6's shared four-bit guard
and four empty atexit destructor thunks. With the static-object identities,
working buffers, and existing high-score jump thunk named, VC6 `/O2 /GB`
matches all 261 instructions and references `109/0/0`; the source uses no dead
expressions or register coercion.

The recovered live-count rule also revealed a Zig port mismatch: its high-score
dropdown exposed all eight backing slots even when only the first slot was
live. The port now bounds both rendering and selection to the clamped
`saved_name_index` prefix, matching the Python model and native menu contract.
