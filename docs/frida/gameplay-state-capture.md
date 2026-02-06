---
tags:
  - status-validation
  - frida
---

# Gameplay/state capture

`scripts/frida/gameplay_state_capture.js` is the default "large run" capture for
gameplay-focused mapping work.

It runs fully automatically after attach:

- Periodic compact/full snapshots of gameplay globals + player state.
- Transition snapshots around `game_state_set`, `ui_menu_assets_init`,
  `ui_menu_layout_init`, and key gameplay hooks.
- Per-frame deltas for `ui_menu_item_subtemplate_block_01..06`
  (`0x0048fd78..0x004902ff`) while in UI/gameplay-interest states
  (`0`, `2`, `4`, `6`, `9`).
- Automatic `MemoryAccessMonitor` write tracing for:
  - `0x0048fd78..0x004902ff` (UI subtemplate blocks),
  - gameplay timer/state ranges (`0x00480840..`, `0x00482600..`,
    `0x00486fac..`, `0x0048718c..`, `0x004aaf1c`, `0x004c3654`).
- `ui_element_render` pointer trace and `ui_menu_item_update` pointer trace to
  correlate render-time usage with subtemplate storage.

Output file:

- `C:\share\frida\gameplay_state_capture.jsonl` (default)
- override via `CRIMSON_FRIDA_DIR`

Attach:

```text
frida -n crimsonland.exe -l C:\share\frida\gameplay_state_capture.js
```

Just shortcut (Windows VM):

```text
just frida-gameplay-state-capture
```

Recommended session:

1. Main menu (`0`) -> Play menu (`1`) -> Options (`2`) -> Statistics (`4`).
2. Start gameplay (`9`), fire/reload, swap weapons, pick several bonuses, level
   up into perk screen (`6`), return to gameplay.
3. Run a quest to quest results (`8`) and quest fail (`12`) once each.
4. Visit Typ-o-Shooter (`18`) briefly.

This single pass yields enough evidence to continue field-level carving and type
fixes without manual REPL interactions.
