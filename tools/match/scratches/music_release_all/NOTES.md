# music_release_all

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

When the global audio-active flag is set, releases all 128 music entries and
flushes the console log. The native guard reuses `sfx_unmuted_flag`; it does not
consult the music-disabled configuration byte here.

Exact 16/16-instruction match with all seven native references aligned.
