# TypoShooter Mode Text Input Field Rendering

## Summary

The implementation in `src/crimson/modes/typo_mode.py` now matches the original game's rendering. The original uses a custom rendering path in `typo_gameplay_update_and_render` (for Typ-o-Shooter mode), not the standardized `ui_text_input_update` function.

## Current Implementation Status: ✅ FIXED

The implementation now correctly matches the original at `0x004457C0`:

### Constants (lines 36-43)
```python
TYPING_PANEL_WIDTH = 182.0      # Original: 182.0
TYPING_PANEL_HEIGHT = 53.0      # Original: 53.0
TYPING_PANEL_ALPHA = 0.7        # Original: 0.7
TYPING_TEXT_X = 6.0             # Original: 6.0
TYPING_PROMPT = "> "            # Original: part of format string
TYPING_CURSOR = "_"             # Original: DAT_004712b8 = "_"
TYPING_CURSOR_X_OFFSET = 14.0   # Original: text_width + 14.0
```

### Rendering Sequence (`_draw_typing_box`)

1. **Panel Backdrop** 
   - Texture: `ind_panel` (original: `DAT_0048f7c4` = `ui/ui_indPanel.jaz`)
   - Position: `x=-1.0, y=screen_height - 144.0`
   - Size: `182.0 × 53.0`
   - Alpha: `0.7`
   - UV: Full texture `(0.0, 0.0, 1.0, 1.0)` - simple stretch, no 9-slice

2. **Typing Text**
   - Position: `x=6.0, y=screen_height - 127.0`
   - Format: `"> " + text` (prompt + user input)
   - Color: White (255, 255, 255, 255)
   - Uses `_draw_ui_text` (equivalent to `grim_draw_text_small_fmt`)

3. **Cursor**
   - Character: `"_"` (underscore) from `DAT_004712b8`
   - Alpha: `sin(t * 4.0) > 0.0 ? 1.0 : 0.4`
   - Position: `x = 6.0 + prompt_width + text_width + 14.0, y=screen_height - 127.0`

### Positioning Details

From the decompiled code at `0x004457C0`:
```c
v38 = config_screen_height - 128.0;     // Base Y position

// Panel drawn at:
//   x = -1.0
//   y = v38 - 16.0 = screen_height - 144.0

// Text drawn at:
//   x = 6.0
//   y = v38 + 1.0 = screen_height - 127.0

// Cursor drawn at:
//   x = text_width + 14.0
//   y = same as text (v38 + 1.0)
```

The text is vertically centered within the panel (17 pixels from top of 53-pixel panel).

### Original Decompiled Reference

From `analysis/ghidra/raw/crimsonland.exe_decompiled.c` lines 37565-37586:
```c
// Bind ind_panel texture
(*grim_interface_ptr->vtable->grim_bind_texture)(DAT_0048f7c4,0);
(*grim_interface_ptr->vtable->grim_set_uv)(0.0,0.0,1.0,1.0);
(*grim_interface_ptr->vtable->grim_set_color)(1.0,1.0,1.0,0.7);

// Draw panel backdrop at (-1.0, fStack_20 - 16.0, 182.0, 53.0)
(*grim_interface_ptr->vtable->grim_draw_quad)(-1.0,fStack_20 - 16.0,182.0,53.0);

// Draw text at (6.0, unaff_ESI + 1.0)
fVar12 = unaff_ESI + 1.0;
(*grim_interface_ptr->vtable->grim_draw_text_small_fmt)(grim_interface_ptr,6.0,fVar12,...);

// Draw cursor with blink
if (sin(game_time_s * 4.0) > 0.0) a = 0.4; else a = 1.0;
iVar5 = (*grim_measure_text_width)(text);
(*grim_draw_text_small_fmt)(grim_interface_ptr,(float)iVar5 + 14.0,fVar12,\"|\");
```

## Comparison: Before vs After

| Aspect | Before (Incorrect) | After (Correct) |
|--------|-------------------|-----------------|
| **Backdrop** | White border + black fill rectangle | `ind_panel` texture stretched |
| **Panel X** | 18.0 | -1.0 |
| **Panel Y** | `screen_h - 36.0` | `screen_h - 144.0` |
| **Text X** | 22.0 (18+4) | 6.0 |
| **Text Y** | `panel_y + 1.0` | `screen_h - 127.0` |
| **Prompt** | None | `"> "` |
| **Cursor** | `\|` | `_` (underscore) |
| **Cursor offset** | Text width + 4.0 | Prompt + text width + 14.0 |
| **9-slice** | N/A (no texture) | No - simple UV stretch |

## Files Referenced

- Original implementation: `analysis/ghidra/raw/crimsonland.exe_decompiled.c` lines 37565-37586
- Original implementation: `analysis/ida/raw/crimsonland.exe/crimsonland.exe_decompiled.c` lines 51199-51462
- Current implementation: `src/crimson/modes/typo_mode.py` lines 36-41, 363-400
