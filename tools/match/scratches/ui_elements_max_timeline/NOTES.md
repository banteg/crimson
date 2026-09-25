# `ui_elements_max_timeline`

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

Exact 35-byte, 13-instruction match with MSVC 6.5 `/O2 /GB`; both masked
references align.

The function walks the same 41-entry UI pointer table and returns the greatest
`timeline_end_ms` among active elements, starting from zero. Live Binary Ninja
shows four callers: two in the top-level frame update and two in
`ui_elements_update_and_render`, covering both transition completion and render
progress.

The Python menu views compute their transition maximum from the active entries
owned by each screen. That is the same effective rule under the port's
screen-local UI model, so the match does not imply a parity change.
