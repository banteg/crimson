# Rendering Inconsistencies Report: Python Implementation vs Decompiled Code

Generated: January 29, 2026

## Summary

This document catalogs discrepancies between the current Python/Raylib rendering implementation and the original decompiled Crimsonland executable. The render pipeline order and specific behaviors show several significant mismatches that may cause visual differences.

## Triage (2026-01-29)

### Fix (separate commits; check off when done)
- [x] 1. FX Queue Baking Timing (move bake to start of world draw)
- [x] 2. Player Overlay Render Order (split DEAD-before-creatures, ALIVE-after-creatures)
- [x] 3. Creature Render Type Ordering (match `creature_render_all` type order)
- [x] 6. Missing Monster Vision Overlays (yellow overlay quads when perk active)
- [x] 9. Player Sprite Shadow/Outline Scale (1.02/1.03 passes with offsets; include dead shadow pass)
- [x] 10. Death Frame Calculation (match UV run 32..52 and hold at 52)
- [ ] 12. Missing Radioactive Perk Aura (pulsing green aura)
- [ ] 13. Missing Shield Effect Rendering (two rotating bubbles)
- [x] 14. Player Color Tinting in Multiplayer (blue/orange tint)

### Defer (needs more evidence / larger refactor)
- 4. Missing Batch Rendering (performance)
- 5. Effect Pool Rendering Order (layering; needs broader render pipeline audit)
- 7. Screen Fade Implementation (minor; currently handled as global transition)
- 8. Terrain UV Scrolling (minor; likely close enough with src-rect scrolling)
- 11. Creature Shadow Alpha Fade (blend/state details unclear)
- 15. Projectile Trail Per-Vertex Alpha (needs side-by-side capture)

### No issue
- 16. Muzzle Flash Position Calculation (matches)

---

## 1. FX Queue Baking Timing (Major)

### Decompiled (`gameplay_render_world` @ 0x00405960)
```c
void gameplay_render_world(void) {
    // ... fade calculations ...
    fx_queue_render();     // <- Called FIRST
    terrain_render();      // <- Then terrain
    // ... player/creature/projectile/bonus renders ...
}
```

FX queues are baked into the terrain render target **at the start** of the render pass, immediately before rendering the terrain.

### Python (`game_world.py`)
```python
def tick(self, dt: float) -> list[ProjectileHit]:
    # ... update logic ...
    self._bake_fx_queues()  # <- Called in tick(), BEFORE draw()
    self.update_camera(dt)
    return events.hits

def draw(self, *, draw_aim_indicators: bool = True) -> None:
    self.renderer.draw(draw_aim_indicators=draw_aim_indicators)
```

FX queues are baked at the **end of the update phase**, not at the start of rendering.

### Impact
Effects queued during the last update are rendered one frame later than in the original game. Blood splatters and corpse decals appear with a 1-frame delay.

---

## 2. Player Overlay Render Order (Major)

### Decompiled (`gameplay_render_world`)
```c
// First pass: DEAD players (health <= 0)
render_overlay_player_index = 0;
if (0 < player_count) {
    do {
        if (player_state_table[render_overlay_player_index].health <= 0.0) {
            player_render_overlays();
        }
        render_overlay_player_index++;
    } while (render_overlay_player_index < player_count);
}

creature_render_all();

// Second pass: ALIVE players (health > 0)
render_overlay_player_index = 0;
if (0 < player_count) {
    do {
        if (0.0 < player_state_table[render_overlay_player_index].health) {
            player_render_overlays();
        }
        render_overlay_player_index++;
    } while (render_overlay_player_index < player_count);
}
```

Dead players render **before** creatures, alive players render **after** creatures.

### Python (`world_renderer.py`)
```python
# All creatures rendered first
for creature in self.creatures.entries:
    if creature.active:
        self._draw_creature_sprite(...)

# All players rendered after (single loop)
texture = self.creature_textures.get(CREATURE_ASSET.get(CreatureTypeId.TROOPER))
for player in self.players:
    if texture is not None:
        self._draw_player_trooper_sprite(...)
```

No separation between dead and alive players - all render after creatures.

### Impact
Dead player corpses should appear **underneath** live creatures but currently render **on top of** them. This is a significant visual layering difference.

---

## 3. Creature Render Type Ordering (Minor)

### Decompiled (`creature_render_all` @ 0x00419680)
```c
creature_render_type(0);  // ZOMBIE
creature_render_type(3);  // SPIDER
creature_render_type(4);  // TAKING_SPIDER
creature_render_type(2);  // FAT_ZOMBIE
creature_render_type(1);  // RUNNER
```

Creatures are grouped by type and rendered in a specific order.

### Python
```python
for creature in self.creatures.entries:
    if not creature.active:
        continue
    # Render in pool iteration order
```

Creatures render in pool slot order, not type order.

### Impact
Potential z-fighting or layering differences when multiple creature types overlap. The original game likely batches by type for performance and visual consistency.

---

## 4. Missing Batch Rendering (Performance/Visual)

### Decompiled
Extensive use of `grim_begin_batch()` / `grim_end_batch()`:
```c
(*grim_interface_ptr->vtable->grim_begin_batch)();
// ... multiple draw calls with same texture ...
(*grim_interface_ptr->vtable->grim_end_batch)();
```

### Python
No batching - each entity calls `rl.draw_texture_pro()` individually:
```python
for creature in self.creatures.entries:
    # ... setup ...
    rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)  # Per-entity
```

### Impact
- **Performance**: More draw calls than necessary
- **Visual**: Potential blend state differences between batched vs individual draws

---

## 5. Effect Pool Rendering Order (Minor)

### Decompiled
Effects rendered as part of `creature_render_all()` with specific texture binding:
```c
(*grim_interface_ptr->vtable->grim_bind_texture)(particles_texture, 0);
effect_select_texture(0x10);
// ... batch draw overlays for Monster Vision, shadows, etc ...
```

### Python (`world_renderer.py`)
```python
# In draw() method order:
self._draw_creature_sprite(...)  # Creatures
self._draw_player_trooper_sprite(...)  # Players
self._draw_projectile(...)  # Projectiles
self._draw_bonus_pickups(...)  # Bonuses
self._draw_effect_pool(...)  # Effects LAST
```

Effects are drawn **after** bonuses instead of interleaved with creature rendering.

### Impact
Effects may layer incorrectly relative to other world elements.

---

## 6. Missing Monster Vision Overlays (Feature Gap)

### Decompiled (`creature_render_all` lines ~14370-14400)
```c
// Monster Vision perk: yellow overlay
if (perk_count_get(perk_id_monster_vision) != 0) {
    if (hitbox_size >= 0.0 || (fade = (hitbox_size + 10.0) * 0.1, fade <= 1.0)) {
        (*grim_interface_ptr->vtable->grim_set_color)(1.0, 1.0, 0.0, fade);
        (*grim_interface_ptr->vtable->grim_draw_quad)(
            _camera_offset_x + x - 45.0,
            _camera_offset_y + y - 45.0,
            90.0, 90.0
        );
    }
}

// Shadow under creatures
if (creature_is_boss) {
    (*grim_interface_ptr->vtable->grim_set_color)(0.0, 0.0, 0.0, alpha);
    (*grim_interface_ptr->vtable->grim_draw_quad)(...);
}

// Red indicator for certain creatures
if (creature_flags & 1) {
    (*grim_interface_ptr->vtable->grim_set_color)(1.0, 0.0, 0.0, alpha);
    (*grim_interface_ptr->vtable->grim_draw_quad)(...);
}
```

### Python
```python
fx_detail = bool(self.config.data.get("fx_detail_0", 0)) if self.config is not None else True
# Mirrors `creature_render_type`: the "shadow-ish" pass is gated by fx_detail_0
# and is disabled when the Monster Vision perk is active.
shadow = fx_detail and (not self.players or not perk_active(self.players[0], PerkId.MONSTER_VISION))
```

The code only **disables** the shadow when Monster Vision is active - it does NOT render the yellow Monster Vision overlay.

### Impact
Players with Monster Vision perk see no visual indicator of creature locations through walls.

---

## 7. Screen Fade Implementation (Minor)

### Decompiled
```c
if (0.0 < screen_fade_alpha) {
    (*grim_interface_ptr->vtable->grim_draw_fullscreen_color)(0.0, 0.0, 0.0, screen_fade_alpha);
}
```
Called **within** `gameplay_render_world()` at the end.

### Python (`base_gameplay_mode.py`)
```python
def draw(self) -> None:
    self._world.draw(draw_aim_indicators=...)
    self._draw_screen_fade()  # Called AFTER world draw

def _draw_screen_fade(self) -> None:
    # ...
    rl.draw_rectangle(0, 0, screen_w, screen_h, rl.Color(0, 0, 0, alpha))
```

Uses `rl.draw_rectangle()` instead of a fullscreen quad, and applies **after** the world render instead of being the final step of it.

### Impact
Slight behavioral difference in when fade is applied during the frame. Using a rectangle may have different edge behavior than a fullscreen quad.

---

## 8. Terrain UV Scrolling (Minor)

### Decompiled (`terrain_render` @ 0x004188a0)
```c
u0 = -(_camera_offset_x / terrain_texture_width);
v0 = -(_camera_offset_y / terrain_texture_height);
(*grim_interface_ptr->vtable->grim_set_uv)(
    u0, v0,
    screen_width / terrain_texture_width + u0,
    screen_height / terrain_texture_height + v0
);
(*grim_interface_ptr->vtable->grim_draw_fullscreen_quad)(0);
```

Uses UV coordinate scrolling based on camera offset.

### Python (`terrain_render.py`)
```python
def draw(self, cam_x: float, cam_y: float, screen_w: float, screen_h: float) -> None:
    if self.render_target is None:
        return
    src = rl.Rectangle(-cam_x, -cam_y, screen_w, screen_h)
    dst = rl.Rectangle(0, 0, screen_w, screen_h)
    rl.draw_texture_pro(self.render_target.texture, src, dst, rl.Vector2(0, 0), 0.0, rl.WHITE)
```

Uses source rectangle offset instead of UV coordinate transformation.

### Impact
May produce slightly different visual results at screen edges or with certain scaling modes.

---

## Render Order Comparison Table

| Step | Decompiled Order | Python Order | Status |
|------|------------------|--------------|--------|
| 1 | FX Queue Bake | Clear background | **MISMATCH** |
| 2 | Terrain Render | Terrain Render | Match (but wrong timing) |
| 3 | Dead Players | Creatures | **MISMATCH** |
| 4 | Creatures (type-ordered) | Players (all) | **MISMATCH** |
| 5 | Alive Players | Projectiles | **MISMATCH** |
| 6 | Projectiles | Bonuses | Match (relative) |
| 7 | Bonuses | Effects | **MISMATCH** |
| 8 | Effects | - | - |
| 9 | Screen Fade | Screen Fade | Minor mismatch |

---

## Recommended Fixes (Priority Order)

### P0 (Critical)
1. **Move FX queue baking** from `tick()` to the start of `draw()`
2. **Split player rendering** into dead (before creatures) and alive (after creatures) passes

### P1 (Important)
3. **Add Monster Vision overlay rendering** - yellow quads under creatures when perk is active
4. **Implement creature type ordering** - batch creatures by type in the correct order

### P2 (Polish)
5. **Add batch rendering** - group draws by texture to reduce state changes
6. **Review effect pool ordering** - ensure effects layer correctly with world elements
7. **Verify terrain UV math** - ensure scrolling behavior matches original

---

## Evidence Sources

- `analysis/ghidra/raw/crimsonland.exe_decompiled.c`:
  - `gameplay_render_world` @ 0x00405960
  - `fx_queue_render` @ 0x00427920
  - `terrain_render` @ 0x004188a0
  - `creature_render_all` @ 0x00419680
  - `creature_render_type` @ 0x00418b60
  - `player_render_overlays` @ 0x00428390
  - `projectile_render` @ 0x00422c70
  - `bonus_render` @ 0x004295f0

- `src/crimson/render/world_renderer.py` - Main world rendering
- `src/crimson/game_world.py` - Game world tick/draw coordination
- `src/crimson/render/terrain_fx.py` - FX queue baking
- `src/grim/terrain_render.py` - Terrain rendering

---

# Additional Rendering Inconsistencies (2026-01-29 Analysis)

## 9. Player Sprite Shadow/Outline Scale (Medium)

### Decompiled (`player_render_overlays` @ 0x00428390)
```c
// Shadow/outline pass (before main pass)
fVar16 = player_state_table[render_overlay_player_index].size * 1.02;  // legs shadow
(*grim_interface_ptr->vtable->grim_draw_quad)(render_scratch_f0 + 1.0, render_scratch_f1 + 1.0, fVar16, fVar16);

fVar16 = player_state_table[render_overlay_player_index].size * 1.03;  // torso shadow
(*grim_interface_ptr->vtable->grim_draw_quad)(render_scratch_f0 + 1.0, render_scratch_f1 + 1.0, fVar16, fVar16);
```

Uses **1.02x scale for legs** and **1.03x scale for torso** with **+1,+1 pixel offset**.

### Python (`world_renderer.py:_draw_player_trooper_sprite()`)
```python
shadow_scale = 1.07  # Used for creature shadow, not player
def draw(frame, *, x, y, scale_mul, rotation, color):
    self._draw_atlas_sprite(
        texture, grid=grid, frame=frame, x=x, y=y,
        scale=base_scale * float(scale_mul),  # scale_mul is 1.0
        rotation_rad=float(rotation), tint=color,
    )
```

**No shadow scaling for player sprites** - the 1.02/1.03 shadow pass is missing entirely.

### Impact
Player sprites lack the subtle outline/shadow effect that helps them stand out from the terrain.

---

## 10. Death Frame Calculation (Medium)

### Decompiled (`player_render_overlays`)
```c
if (player.health <= 0.0) {
    // death_frame = ftol(death_timer) starting at 32
    int frame = 32 + ftol(16.0 - death_timer);  // 32..52 range
    if (frame > 52) frame = 52;
    // Uses effect_uv8[frame] directly
}
```

Death animation uses `ftol(death_timer)` directly, not a computed ramp.

### Python (`world_renderer.py`)
```python
if player.death_timer >= 0.0:
    frame = 32 + int((16.0 - float(player.death_timer)) * 1.25)
    if frame > 52: frame = 52
    if frame < 32: frame = 32
else:
    frame = 53
```

Uses `* 1.25` multiplier which doesn't match the decompiled logic.

### Impact
Death animation timing differs from original.

---

## 11. Creature Shadow Alpha Fade (Medium)

### Decompiled (`creature_render_type` @ 0x00418b60)
```c
// Long strip corpses (hitbox_size < 0)
fStack_1c = *pfVar6 * 0.5 + fStack_1c;  // hitbox_size * 0.5 + alpha
if (fStack_1c < 0.0) fStack_1c = 0.0;

// Ping-pong strip corpses
if (*pfVar6 < 0.0) {
    fStack_1c = *pfVar6 * 0.1 + fStack_1c;
    if (fStack_1c < 0.0) fStack_1c = 0.0;
}
```

Different fade rates for long-strip (0.5) vs ping-pong (0.1) animations.

### Python (`world_renderer.py`)
```python
shadow_a = float(creature.tint_a) * 0.4
if hitbox_size < 0.0:
    shadow_a += hitbox_size * (0.5 if long_strip else 0.1)
```

Similar logic but uses `tint_a * 0.4` base, decompiled uses `tint_a * 0.4` in shadow pass and different blending.

---

## 12. Missing Radioactive Perk Aura (Feature Gap)

### Decompiled (`player_render_overlays`)
```c
iVar4 = perk_count_get(perk_id_radioactive);
if (iVar4 != 0) {
    (*grim_interface_ptr->vtable->grim_set_config_var)(0x13,5);  // src blend
    (*grim_interface_ptr->vtable->grim_set_config_var)(0x14,2);  // dst blend (ONE)
    (*grim_interface_ptr->vtable->grim_bind_texture)((int)particles_texture,0);
    effect_select_texture(0x10);  // radioactive effect
    fVar8 = (float10)fsin((float10)game_time_s);
    (*grim_interface_ptr->vtable->grim_set_color)(
        0.3, 0.6, 0.3,  // greenish
        (float)(((fVar8 + 1.0) * 0.1875 + 0.25) * (float10)fVar16)
    );
    // Draws 100x100 quad centered on player
}
```

Renders a pulsing green aura around player with radioactive perk.

### Python
**Not implemented.**

---

## 13. Missing Shield Effect Rendering (Feature Gap)

### Decompiled (`player_render_overlays`)
```c
if (0.0 < player_state_table[render_overlay_player_index].shield_timer) {
    (*grim_interface_ptr->vtable->grim_set_config_var)(0x13,5);
    (*grim_interface_ptr->vtable->grim_set_config_var)(0x14,2);
    (*grim_interface_ptr->vtable->grim_bind_texture)((int)particles_texture,0);
    effect_select_texture(2);  // shield bubble
    
    // Two rotating bubbles with sine-wave modulation
    fVar8 = (float10)fsin((float10)game_time_s);
    (*grim_interface_ptr->vtable->grim_set_rotation)(game_time_s + game_time_s);
    // ... draw first bubble ...
    
    fVar8 = (float10)fsin((float10)game_time_s * (float10)3.0);
    (*grim_interface_ptr->vtable->grim_set_rotation)(game_time_s * -2.0);
    // ... draw second bubble ...
}
```

### Python
**Not implemented.**

---

## 14. Player Color Tinting in Multiplayer (Minor)

### Decompiled (`player_render_overlays`)
```c
if (1 < player_count) {
    if (render_overlay_player_index == 0) {
        (*grim_interface_ptr->vtable->grim_set_color)(0.3, 0.3, 1.0, fVar14);  // Blue for P1
    } else {
        (*grim_interface_ptr->vtable->grim_set_color)(1.0, 0.55, 0.35, fVar14);  // Orange for P2
    }
}
```

### Python
**Not implemented** - no player tinting in multiplayer mode.

---

## 15. Projectile Trail Per-Vertex Alpha (Minor)

### Decompiled (`projectile_render` @ 0x00422c70)
```c
(*grim_interface_ptr->vtable->grim_set_color_slot)(0, 0.5, 0.5, 0.5, 0.0);  // tail alpha = 0
(*grim_interface_ptr->vtable->grim_set_color_slot)(1, 0.5, 0.5, 0.5, 0.0);  // tail alpha = 0
(*grim_interface_ptr->vtable->grim_set_color_slot)(2, 0.5, 0.5, 0.5, life * 0.5);  // head alpha
(*grim_interface_ptr->vtable->grim_set_color_slot)(3, 0.5, 0.5, 0.5, life * 0.5);  // head alpha
(*grim_interface_ptr->vtable->grim_draw_quad_points)(...);
```

Uses per-vertex color slots for head→tail gradient.

### Python (`world_renderer.py:_draw_bullet_trail()`)
```python
head = rl.Color(200, 200, 200, alpha)
tail = rl.Color(200, 200, 200, 0)
# RLGL quad with per-vertex colors
```

Approach is correct but alpha calculation may differ.

---

## 16. Muzzle Flash Position Calculation (Minor)

### Decompiled
```c
// Offset calculation
fVar9 = (float10)fcos((float10)aim_heading + (float10)1.5707964);
fVar8 = (float10)fsin((float10)aim_heading + (float10)1.5707964);
offset = (muzzle_flash_alpha * 12.0 - 21.0);  // Note: -21.0 constant
pos_x = player_x + fVar9 * offset;
pos_y = player_y + fVar8 * offset;
```

### Python
```python
heading = float(player.aim_heading) + math.pi / 2.0
offset = (float(player.muzzle_flash_alpha) * 12.0 - 21.0) * scale  # Matches
```

Actually matches - no issue here.

---

## Updated Summary Table

| Issue | Severity | Status |
|-------|----------|--------|
| FX Queue timing | **HIGH** | Needs fix |
| Player render order (dead/alive split) | **HIGH** | Needs fix |
| Player shadow scale (1.02/1.03) | MEDIUM | Missing |
| Radioactive perk aura | MEDIUM | Not implemented |
| Shield bubble effect | MEDIUM | Not implemented |
| Monster Vision overlay | MEDIUM | Not implemented |
| Creature type ordering | LOW | Minor visual |
| Death frame calculation | LOW | Timing off |
| Multiplayer player tint | LOW | Not implemented |

---

## Complete Render Order (Original vs Current)

### Original (Decompiled)
1. `fx_queue_render()` - Bake decals into terrain RT
2. `terrain_render()` - Draw terrain to screen
3. `player_render_overlays()` - **DEAD players only**
4. `creature_render_all()` - All creatures (with Monster Vision overlays)
5. `player_render_overlays()` - **ALIVE players only** (+ shield, radioactive)
6. `projectile_render()` - Projectiles with trails
7. `bonus_render()` - Bonus pickups
8. `grim_draw_fullscreen_color()` - Fade overlay

### Current Python
1. `ground.draw()` - Terrain (FX baked earlier in tick())
2. Creatures (all, in pool order)
3. Players (all, no health-based split)
4. Projectiles (primary)
5. Secondary projectiles
6. Bonus pickups
7. Effect pool
8. Bonus hover labels
9. Aim indicators
10. Screen fade (in base_gameplay_mode.py)

**Key mismatches:**
- FX bake timing (end of tick vs start of draw)
- Player dead/alive split around creatures
- Missing radioactive/shield overlays
- Missing Monster Vision yellow overlays
- Effect pool renders after bonuses instead of interleaved
