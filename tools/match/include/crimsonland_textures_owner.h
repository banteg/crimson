#ifndef CRIMSONLAND_TEXTURES_OWNER_H
#define CRIMSONLAND_TEXTURES_OWNER_H

/*
 * Authenticated 2003 textures_t layout rooted at ui_cursor_texture
 * (0x0048f798).  The target-era semantic names preserve the independently
 * recovered 1.9.93 texture identities while restoring their aggregate owner.
 */
typedef struct texture_handles_original_t {
    int ui_cursor_texture;
    int ui_aim_texture;
    int ui_text_level_complete_texture;
    int ui_quest_number_textures[6];
    int ui_hud_arrow_texture;
    int ui_hud_life_indicator_texture;
    int ui_hud_panel_texture;
    int ui_clock_table_texture;
    int ui_clock_pointer_texture;
    int ui_well_done_unused_texture;
    int projectile_texture;
    int world_arrow_marker_texture;
    int bodyset_texture;
    int muzzle_flash_texture;
    int ui_weapon_icons_texture;
    int bullet_trail_texture;
    int particles_texture;
    int bonus_texture;
    int ui_item_texts_texture;
    int ui_text_reaper_texture;
    int ui_text_controls_texture;
    int ui_text_pick_perk_texture;
    int ui_text_well_done_texture;
} texture_handles_original_t;

#ifdef __cplusplus
extern "C" {
#endif
extern int ui_cursor_texture;
#ifdef __cplusplus
}
#endif

#define texture_handles \
    (*(texture_handles_original_t *)&ui_cursor_texture)

#ifdef CRIMSONLAND_USE_ORIGINAL_TEXTURES_OWNER
#define ui_aim_texture texture_handles.ui_aim_texture
#define ui_text_level_complete_texture \
    texture_handles.ui_text_level_complete_texture
#define ui_text_quest_texture texture_handles.ui_quest_number_textures[0]
#define ui_digit_1_texture texture_handles.ui_quest_number_textures[1]
#define ui_digit_2_texture texture_handles.ui_quest_number_textures[2]
#define ui_digit_3_texture texture_handles.ui_quest_number_textures[3]
#define ui_digit_4_texture texture_handles.ui_quest_number_textures[4]
#define ui_digit_5_texture texture_handles.ui_quest_number_textures[5]
#define ui_hud_arrow_texture texture_handles.ui_hud_arrow_texture
#define ui_hud_life_indicator_texture \
    texture_handles.ui_hud_life_indicator_texture
#define ui_hud_panel_texture texture_handles.ui_hud_panel_texture
#define ui_clock_table_texture texture_handles.ui_clock_table_texture
#define ui_clock_pointer_texture texture_handles.ui_clock_pointer_texture
#define projectile_texture texture_handles.projectile_texture
#define world_arrow_marker_texture texture_handles.world_arrow_marker_texture
#define bodyset_texture texture_handles.bodyset_texture
#define muzzle_flash_texture texture_handles.muzzle_flash_texture
#define ui_weapon_icons_texture texture_handles.ui_weapon_icons_texture
#define bullet_trail_texture texture_handles.bullet_trail_texture
#define particles_texture texture_handles.particles_texture
#define bonus_texture texture_handles.bonus_texture
#define ui_item_texts_texture texture_handles.ui_item_texts_texture
#define ui_text_reaper_texture texture_handles.ui_text_reaper_texture
#define ui_text_controls_texture texture_handles.ui_text_controls_texture
#define ui_text_pick_perk_texture texture_handles.ui_text_pick_perk_texture
#define ui_text_well_done_texture texture_handles.ui_text_well_done_texture
#endif

#endif
