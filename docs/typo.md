# TypoShooter Mode Text Input Field Rendering

## Summary

The implementation in `src/crimson/modes/typo_mode.py` now matches the original game's rendering. The original uses a custom rendering path in `survival_gameplay_update_and_render` (for typoshooter mode), not the standardized `ui_text_input_update` function.

## Current Implementation Status: ✅ FIXED

The implementation now correctly matches the original at `0x004457C0`:

### Constants (lines 36-42)
```python
TYPING_PANEL_WIDTH = 182.0      # Original: 182.0
TYPING_PANEL_HEIGHT = 53.0      # Original: 53.0
TYPING_PANEL_ALPHA = 0.7        # Original: 0.7
TYPING_TEXT_X = 6.0             # Original: 6.0
TYPING_TEXT_Y_OFFSET = 1.0      # Original: y + 1.0
TYPING_CURSOR_X_OFFSET = 14.0   # Original: text_width + 14.0
```

### Rendering Sequence (`_draw_typing_box`)

1. **Panel Backdrop** (lines 371-381)
   - Texture: `ind_panel` (original: `DAT_0048f7c4` = `ui/ui_indPanel.jaz`)
   - Position: `x=-1.0, y=screen_h - 128 - 16`
   - Size: `182.0 × 53.0`
   - Alpha: `0.7`
   - UV: Full texture `(0.0, 0.0, 1.0, 1.0)` - simple stretch, no 9-slice

2. **Typing Text** (lines 384-386)
   - Position: `x=6.0, y=panel_y + 1.0`
   - Color: White (255, 255, 255, 255)
   - Uses `_draw_ui_text` (equivalent to `grim_draw_text_small_fmt`)

3. **Cursor** (lines 389-400)
   - Alpha: `sin(t * 4.0) > 0.0 ? 1.0 : 0.4`
   - Position: `x = 6.0 + text_width + 14.0, y = text_y`
   - Rendered as "|" character

### Original Decompiled Reference

From `analysis/ghidra/raw/crimsonland.exe_decompiled.c` lines 37565-37586:
```c
// Bind ind_panel texture
(*grim_interface_ptr->vtable->grim_bind_texture)(DAT_0048f7c4,0);
(*grim_interface_ptr->vtable->grim_set_uv)(0.0,0.0,1.0,1.0);
(*grim_interface_ptr->vtable->grim_set_color)(1.0,1.0,1.0,0.7);
// Draw panel backdrop
(*grim_interface_ptr->vtable->grim_draw_quad)(-1.0,fStack_20 - 16.0,182.0,53.0);
// Draw text
(*grim_interface_ptr->vtable->grim_draw_text_small_fmt)(grim_interface_ptr,6.0,fVar12,...);
// Draw cursor with blink
if (sin(game_time_s * 4.0) > 0.0) a = 0.4; else a = 1.0;
(*grim_interface_ptr->vtable->grim_draw_text_small_fmt)(grim_interface_ptr,text_width + 14.0,...);
```

## Comparison: Before vs After

| Aspect | Before (Incorrect) | After (Correct) |
|--------|-------------------|-----------------|
| **Backdrop** | White border + black fill rectangle | `ind_panel` texture stretched |
| **Position X** | 18.0 | -1.0 |
| **Position Y** | `screen_h - 36.0` | `screen_h - 144.0` |
| **Size** | 220.0 × 18.0 variable | 182.0 × 53.0 fixed |
| **Text X** | 22.0 (18+4) | 6.0 |
| **Cursor offset** | Text width + 4.0 | Text width + 14.0 |
| **9-slice** | N/A (no texture) | No - simple UV stretch |

## Files Referenced

- Original implementation: `analysis/ghidra/raw/crimsonland.exe_decompiled.c` lines 37565-37586
- Current implementation: `src/crimson/modes/typo_mode.py` lines 36-42, 363-400
