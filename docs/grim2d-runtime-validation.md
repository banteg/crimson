# Grim2D runtime validation notes

This doc tracks runtime validation sessions for the Grim2D vtable.

## 2026-01-18 (Win11 ARM, UTM, Frida)

### Environment

- Host: macOS (UTM VM)
- Guest: Windows 11 ARM64
- Game: `crimsonland.exe`
- Tooling: Frida (`frida-tools`)

### Session summary

Goal: validate a small backlog subset using Frida hooks without pausing.

How to run (Frida hook script):

1) Game path (this VM): `C:\Crimsonland\crimsonland.exe`.
2) Copy `scripts/frida/grim_hooks.js` and `scripts/frida/grim_hooks_targets.json`
   into the VM shared drive (example uses `Z:\`).
3) Optionally edit `grim_hooks_targets.json` to swap the target list.
4) Launch the game, then attach by process name (recommended):

   ```text
   frida -n crimsonland.exe -l Z:\grim_hooks.js
   ```

   Spawned runs on Win11 ARM64 caused empty textures and a crash before the main menu
   (observed 2026-01-18), so attach is preferred.

5) To capture the very beginning, spawn instead of attach:

   ```text
   frida -f "C:\Crimsonland\crimsonland.exe" -l Z:\grim_hooks.js
   ```

   If the process pauses on spawn, type `%resume` in the Frida REPL.
6) Logs are written to `Z:\grim_hits.log` by default. If JSON logging is enabled
   (default in `grim_hooks_targets.json`), events also stream to `Z:\grim_hits.jsonl`.

Artifacts:

- Hook script: `scripts/frida/grim_hooks.js`
- Target list: `scripts/frida/grim_hooks_targets.json`
- Log: `Z:\grim_hits.log`
- JSONL log: `Z:\grim_hits.jsonl`
- `grim.dll` base at runtime: `0x0A990000`

Observed hits (counts at end of run):

- Hit: `grim_init_system` (`0x014`, `grim.dll+0x05EB0`) — 1
- Hit: `grim_apply_settings` (`0x01C`, `grim.dll+0x06020`) — 1
- Hit: `grim_create_texture` (`0xAC`, `grim.dll+0x075D0`) — 1
- Hit: `grim_load_texture` (`0xB4`, `grim.dll+0x076E0`) — 69
- Hit: `grim_destroy_texture` (`0xBC`, `grim.dll+0x07700`) — 4
- Hit: `grim_flush_batch` (`0xEC`, `grim.dll+0x083C0`) — 104

No hits in this run:

- `grim_apply_config` (`0x010`, `grim.dll+0x05D40`)
- `grim_check_device` (`0x00C`, `grim.dll+0x05CB0`)
- `grim_get_error_text` (`0x028`, `grim.dll+0x06CA0`)
- `grim_validate_texture` (`0xB8`, `grim.dll+0x07750`)
- `grim_recreate_texture` (`0xB0`, `grim.dll+0x07790`)
