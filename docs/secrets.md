# Secrets and unlocks (draft)

This page tracks hidden unlock conditions and Easter eggs (ex: Secret Path, secret weapons) so we can wire
save editing and runtime validation around concrete logic instead of string hints.

## Current status

- We have string hints in the binary, but we have not mapped the conditions or flags yet.
- No save-file fields are confirmed to drive these secrets.

## Known hints (string table)

Source: `analysis/ghidra/raw/crimsonland.exe_strings.txt`.

- `0x00472e90` — "Secret" (menu/label text).
- `0x00473b8c` — hint describing a credit-screen click pattern that starts the Secret Path.
- `0x00473d50` — hint stating there are hidden secret weapons in the game.

## Mapping checklist

1) Ghidra Xrefs for the hint strings (`0x00473b8c`, `0x00473d50`, `0x00472e90`).
2) Label the owning UI/credits functions and identify any state flags they read/write.
3) Track where those flags persist (save file, in-memory globals, or per-profile data).
4) Validate the flag flip at runtime (Frida / MemAccessMonitor) while triggering the secret.
5) Wire confirmed flags into the save editor once identified.

## Open questions

- Which functions gate the Secret Path transition?
- Are secret weapon unlocks stored in `game.cfg`, or derived from other state?
- Are any of these flags version-specific (v1.9.93 vs earlier)?
