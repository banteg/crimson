# `highscore_record_init`

Exact 165-byte, 46-instruction match with MSVC 6.5 `/O2 /GB`; all 17 masked
references align.

Live Binary Ninja shows callers in `quest_results_screen_update` and
`highscore_save_record`. The helper finalizes the active record: it selects the
most-used weapon from 64 accumulated time slots (weapon 1 wins ties), clamps
hits to shots fired, copies mode and quest coordinates, clears record flags,
generates a bounded random tag with a `0x310` offset, and writes the legacy
hardcore marker byte `0x75`.

The random tag is expressed as the signed `% 0x10000000` operation recovered
from VC6's mask/negative-remainder sequence. The record fields are accessed
through the established 72-byte `highscore_record_t`, so every relocation must
prove the corresponding base-plus-field address.

The Python high-score builder currently chooses a weapon from per-player shot
counts and falls back to the current weapon when all counts are zero. Native
instead accumulates equipped time in milliseconds, scans slots 1 through 63,
and leaves weapon 1 as the zero/tie winner. This is a confirmed parity gap;
fixing it requires adding the native timing accumulator to simulation state,
not merely changing this selector.
