#include <stddef.h>
#include <windows.h>

#include "crimsonland_types.h"
#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"

#define CRIMSON_ABI_ASSERT(name, condition) \
    typedef char crimson_abi_assert_##name[(condition) ? 1 : -1]

#define CRIMSON_ABI_ASSERT_ALIGN4(name, type) \
    struct crimson_##name##_alignment_probe_t { \
        char prefix; \
        type value; \
    }; \
    CRIMSON_ABI_ASSERT( \
        name##_alignment_is_four, \
        offsetof(crimson_##name##_alignment_probe_t, value) == 4)

struct crimson_char_alignment_probe_t {
    char prefix;
    unsigned char value;
};

struct crimson_int_alignment_probe_t {
    char prefix;
    int value;
};

struct crimson_unsigned_int_alignment_probe_t {
    char prefix;
    unsigned int value;
};

struct crimson_float_alignment_probe_t {
    char prefix;
    float value;
};

struct crimson_double_alignment_probe_t {
    char prefix;
    double value;
};

struct crimson_pointer_alignment_probe_t {
    char prefix;
    void *value;
};

struct crimson_game_mode_alignment_probe_t {
    char prefix;
    game_mode_id_t value;
};

struct crimson_game_state_alignment_probe_t {
    char prefix;
    game_state_id_t value;
};

struct crimson_console_queue_alignment_probe_t {
    char prefix;
    console_queue_t value;
};

struct crimson_config_alignment_probe_t {
    char prefix;
    crimson_cfg_t value;
};

struct crimson_player_state_alignment_probe_t {
    char prefix;
    player_state_t value;
};

struct crimson_creature_alignment_probe_t {
    char prefix;
    creature_t value;
};

struct crimson_u16_alignment_probe_t {
    char prefix;
    u16_t value;
};

CRIMSON_ABI_ASSERT(pointer_is_32_bit, sizeof(void *) == 4);
CRIMSON_ABI_ASSERT(
    pointer_array_2_is_0x08,
    sizeof(char *[2]) == 0x08);
CRIMSON_ABI_ASSERT(
    pointer_array_6_is_0x18,
    sizeof(void *[6]) == 0x18);
CRIMSON_ABI_ASSERT(
    pointer_array_9_is_0x24,
    sizeof(char *[9]) == 0x24);
CRIMSON_ABI_ASSERT(
    pointer_array_10_is_0x28,
    sizeof(char *[10]) == 0x28);
CRIMSON_ABI_ASSERT(
    pointer_array_32_is_0x80,
    sizeof(char *[32]) == 0x80);
CRIMSON_ABI_ASSERT(
    pointer_array_57_is_0xe4,
    sizeof(void *[57]) == 0xe4);
CRIMSON_ABI_ASSERT(char_array_128_is_0x80, sizeof(char[128]) == 0x80);
CRIMSON_ABI_ASSERT(
    uchar_array_172_is_0xac,
    sizeof(unsigned char[172]) == 0xac);
CRIMSON_ABI_ASSERT(
    uchar_array_640_is_0x280,
    sizeof(unsigned char[640]) == 0x280);
CRIMSON_ABI_ASSERT(
    highscore_line_buffers_are_0x668,
    sizeof(char[10][164]) == 0x668);
CRIMSON_ABI_ASSERT(int_is_32_bit, sizeof(int) == 4);
CRIMSON_ABI_ASSERT(unsigned_int_is_32_bit, sizeof(unsigned int) == 4);
CRIMSON_ABI_ASSERT(long_is_32_bit, sizeof(long) == 4);
CRIMSON_ABI_ASSERT(float_is_32_bit, sizeof(float) == 4);
CRIMSON_ABI_ASSERT(double_is_64_bit, sizeof(double) == 8);
CRIMSON_ABI_ASSERT(bool_is_one_byte, sizeof(bool) == 1);
CRIMSON_ABI_ASSERT(unsigned_char_is_one_byte, sizeof(unsigned char) == 1);
CRIMSON_ABI_ASSERT(game_mode_id_is_32_bit, sizeof(game_mode_id_t) == 4);
CRIMSON_ABI_ASSERT(game_state_id_is_32_bit, sizeof(game_state_id_t) == 4);
CRIMSON_ABI_ASSERT(
    projectile_type_id_is_32_bit,
    sizeof(projectile_type_id_t) == 4);
CRIMSON_ABI_ASSERT(
    secondary_projectile_type_id_is_32_bit,
    sizeof(secondary_projectile_type_id_t) == 4);
CRIMSON_ABI_ASSERT(unsigned_short_is_16_bit, sizeof(unsigned short) == 2);
CRIMSON_ABI_ASSERT(u16_is_16_bit, sizeof(u16_t) == 2);
CRIMSON_ABI_ASSERT(guid_is_0x10, sizeof(GUID) == 0x10);
CRIMSON_ABI_ASSERT(systemtime_is_0x10, sizeof(SYSTEMTIME) == 0x10);
CRIMSON_ABI_ASSERT(hmodule_is_32_bit, sizeof(HMODULE) == 4);
CRIMSON_ABI_ASSERT(
    crt_dosmaperr_entry_is_0x08,
    sizeof(crt_dosmaperr_entry_t) == 0x08);
CRIMSON_ABI_ASSERT(
    crt_dosmaperr_errno_is_at_0x04,
    offsetof(crt_dosmaperr_entry_t, crt_errno) == 0x04);
CRIMSON_ABI_ASSERT(
    crt_dosmaperr_table_is_0x168,
    sizeof(crt_dosmaperr_entry_t[45]) == 0x168);
CRIMSON_ABI_ASSERT(
    crt_onexit_fn_is_32_bit,
    sizeof(crt_onexit_fn_t) == 4);
CRIMSON_ABI_ASSERT(
    crt_onexit_cursor_is_32_bit,
    sizeof(crt_onexit_fn_t *) == 4);
CRIMSON_ABI_ASSERT_ALIGN4(crt_dosmaperr_entry, crt_dosmaperr_entry_t);
CRIMSON_ABI_ASSERT_ALIGN4(guid, GUID);

CRIMSON_ABI_ASSERT(
    default_char_alignment_is_one,
    offsetof(crimson_char_alignment_probe_t, value) == 1);
CRIMSON_ABI_ASSERT(
    default_int_alignment_is_four,
    offsetof(crimson_int_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    default_unsigned_int_alignment_is_four,
    offsetof(crimson_unsigned_int_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    default_float_alignment_is_four,
    offsetof(crimson_float_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    default_double_alignment_is_eight,
    offsetof(crimson_double_alignment_probe_t, value) == 8);
CRIMSON_ABI_ASSERT(
    default_pointer_alignment_is_four,
    offsetof(crimson_pointer_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    default_game_mode_alignment_is_four,
    offsetof(crimson_game_mode_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    default_game_state_alignment_is_four,
    offsetof(crimson_game_state_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    default_u16_alignment_is_two,
    offsetof(crimson_u16_alignment_probe_t, value) == 2);

CRIMSON_ABI_ASSERT(vec2_is_8_bytes, sizeof(vec2f_t) == 0x08);
CRIMSON_ABI_ASSERT(vec2_array_3_is_0x18, sizeof(vec2f_t[3]) == 0x18);
CRIMSON_ABI_ASSERT(vec2_array_64_is_0x200, sizeof(vec2f_t[64]) == 0x200);
CRIMSON_ABI_ASSERT(float_array_64_is_0x100, sizeof(float[64]) == 0x100);
CRIMSON_ABI_ASSERT(int_array_3_is_0x0c, sizeof(int[3]) == 0x0c);
CRIMSON_ABI_ASSERT(int_array_4_is_0x10, sizeof(int[4]) == 0x10);
CRIMSON_ABI_ASSERT(int_array_13_is_0x34, sizeof(int[13]) == 0x34);
CRIMSON_ABI_ASSERT(int_array_36_is_0x90, sizeof(int[36]) == 0x90);
CRIMSON_ABI_ASSERT(int_array_64_is_0x100, sizeof(int[64]) == 0x100);
CRIMSON_ABI_ASSERT(cvar_float_is_16_bytes, sizeof(cvar_float_t) == 0x10);
CRIMSON_ABI_ASSERT(
    cvar_value_is_at_0x0c,
    offsetof(cvar_float_t, value) == 0x0c);
CRIMSON_ABI_ASSERT(weapon_entry_is_0x7c, sizeof(weapon_stats_t) == 0x7c);
CRIMSON_ABI_ASSERT(
    weapon_table_is_0x1f00,
    sizeof(weapon_stats_t[64]) == 0x1f00);
CRIMSON_ABI_ASSERT_ALIGN4(weapon, weapon_stats_t);
CRIMSON_ABI_ASSERT(
    weapon_storage_entry_is_0x7c,
    sizeof(weapon_storage_entry_t) == 0x7c);
CRIMSON_ABI_ASSERT(
    weapon_storage_table_is_0x1f00,
    sizeof(weapon_storage_table_t) == 0x1f00);
CRIMSON_ABI_ASSERT_ALIGN4(weapon_storage, weapon_storage_entry_t);
CRIMSON_ABI_ASSERT(audio_entry_is_0x84, sizeof(audio_entry_t) == 0x84);
CRIMSON_ABI_ASSERT(
    audio_entry_table_is_0x4200,
    sizeof(audio_entry_t[128]) == 0x4200);
CRIMSON_ABI_ASSERT_ALIGN4(audio_entry, audio_entry_t);
CRIMSON_ABI_ASSERT(
    sfx_cooldown_table_is_0x200,
    sizeof(sfx_cooldown_table_t) == 0x200);
CRIMSON_ABI_ASSERT(
    sfx_voice_table_is_0x80,
    sizeof(sfx_voice_table_t) == 0x80);
CRIMSON_ABI_ASSERT(
    sfx_volume_table_is_0x200,
    sizeof(sfx_volume_table_t) == 0x200);
CRIMSON_ABI_ASSERT(
    music_playlist_is_0x200,
    sizeof(music_playlist_t) == 0x200);
CRIMSON_ABI_ASSERT(
    weapon_usage_time_is_0x100,
    sizeof(weapon_usage_time_t) == 0x100);
CRIMSON_ABI_ASSERT(player_aux_timer_is_0x08, sizeof(player_aux_timer_t) == 0x08);
CRIMSON_ABI_ASSERT(
    player_aim_screen_xy_is_0x10,
    sizeof(player_aim_screen_xy_t) == 0x10);
CRIMSON_ABI_ASSERT_ALIGN4(sfx_cooldown_table, sfx_cooldown_table_t);
CRIMSON_ABI_ASSERT_ALIGN4(sfx_voice_table, sfx_voice_table_t);
CRIMSON_ABI_ASSERT_ALIGN4(sfx_volume_table, sfx_volume_table_t);
CRIMSON_ABI_ASSERT_ALIGN4(music_playlist, music_playlist_t);
CRIMSON_ABI_ASSERT_ALIGN4(weapon_usage_time, weapon_usage_time_t);
CRIMSON_ABI_ASSERT_ALIGN4(player_aux_timer, player_aux_timer_t);
CRIMSON_ABI_ASSERT_ALIGN4(player_aim_screen_xy, player_aim_screen_xy_t);

CRIMSON_ABI_ASSERT(player_input_is_0x34, sizeof(player_input_t) == 0x34);
CRIMSON_ABI_ASSERT(
    player_input_config_is_0x40,
    sizeof(player_input_config_t) == 0x40);
CRIMSON_ABI_ASSERT(config_is_0x480, sizeof(crimson_cfg_t) == 0x480);
CRIMSON_ABI_ASSERT(
    config_alignment_is_four,
    offsetof(crimson_config_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(player_state_is_0x360, sizeof(player_state_t) == 0x360);
CRIMSON_ABI_ASSERT(
    player_state_table_is_0x6c0,
    sizeof(player_state_t[2]) == 0x6c0);
CRIMSON_ABI_ASSERT(
    player_state_alignment_is_four,
    offsetof(crimson_player_state_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    configured_aim_y_is_at_0x24,
    offsetof(player_input_config_t, axis_aim_y) == 0x24);
CRIMSON_ABI_ASSERT(
    configured_aim_x_is_at_0x28,
    offsetof(player_input_config_t, axis_aim_x) == 0x28);

CRIMSON_ABI_ASSERT(creature_is_0x98, sizeof(creature_t) == 0x98);
CRIMSON_ABI_ASSERT(
    creature_pool_is_0xe400,
    sizeof(creature_t[384]) == 0xe400);
CRIMSON_ABI_ASSERT(
    creature_alignment_is_four,
    offsetof(crimson_creature_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    creature_lifecycle_is_at_0x10,
    offsetof(creature_t, lifecycle_stage) == 0x10);
CRIMSON_ABI_ASSERT(
    creature_link_index_is_at_0x78,
    offsetof(creature_t, link_index) == 0x78);
CRIMSON_ABI_ASSERT(
    creature_flags_are_at_0x8c,
    offsetof(creature_t, flags) == 0x8c);
CRIMSON_ABI_ASSERT(creature_type_is_0x44, sizeof(creature_type_t) == 0x44);
CRIMSON_ABI_ASSERT(
    creature_type_table_is_0x198,
    sizeof(creature_type_table_t) == 0x198);
CRIMSON_ABI_ASSERT_ALIGN4(creature_type, creature_type_t);
CRIMSON_ABI_ASSERT(
    creature_spawn_slot_is_0x18,
    sizeof(creature_spawn_slot_t) == 0x18);
CRIMSON_ABI_ASSERT(
    creature_spawn_slot_table_is_0x300,
    sizeof(creature_spawn_slot_t[32]) == 0x300);
CRIMSON_ABI_ASSERT_ALIGN4(creature_spawn_slot, creature_spawn_slot_t);
CRIMSON_ABI_ASSERT(projectile_is_0x40, sizeof(projectile_t) == 0x40);
CRIMSON_ABI_ASSERT(
    projectile_pool_is_0x1800,
    sizeof(projectile_pool_t) == 0x1800);
CRIMSON_ABI_ASSERT_ALIGN4(projectile, projectile_t);
CRIMSON_ABI_ASSERT(particle_is_0x38, sizeof(particle_t) == 0x38);
CRIMSON_ABI_ASSERT(
    particle_pool_is_0x1c00,
    sizeof(particle_t[128]) == 0x1c00);
CRIMSON_ABI_ASSERT_ALIGN4(particle, particle_t);
CRIMSON_ABI_ASSERT(
    secondary_projectile_is_0x2c,
    sizeof(secondary_projectile_t) == 0x2c);
CRIMSON_ABI_ASSERT(
    secondary_projectile_pool_is_0xb00,
    sizeof(secondary_projectile_pool_t) == 0xb00);
CRIMSON_ABI_ASSERT_ALIGN4(secondary_projectile, secondary_projectile_t);
CRIMSON_ABI_ASSERT(sprite_effect_is_0x2c, sizeof(sprite_effect_t) == 0x2c);
CRIMSON_ABI_ASSERT(
    sprite_effect_pool_is_0x4200,
    sizeof(sprite_effect_t[384]) == 0x4200);
CRIMSON_ABI_ASSERT_ALIGN4(sprite_effect, sprite_effect_t);
CRIMSON_ABI_ASSERT(fx_queue_entry_is_0x28, sizeof(fx_queue_entry_t) == 0x28);
CRIMSON_ABI_ASSERT(
    fx_queue_is_0x1400,
    sizeof(fx_queue_entry_t[128]) == 0x1400);
CRIMSON_ABI_ASSERT_ALIGN4(fx_queue_entry, fx_queue_entry_t);
CRIMSON_ABI_ASSERT(bonus_entry_is_0x1c, sizeof(bonus_entry_t) == 0x1c);
CRIMSON_ABI_ASSERT(bonus_pool_is_0x1c0, sizeof(bonus_pool_t) == 0x1c0);
CRIMSON_ABI_ASSERT_ALIGN4(bonus_entry, bonus_entry_t);
CRIMSON_ABI_ASSERT(bonus_meta_is_0x14, sizeof(bonus_meta_t) == 0x14);
CRIMSON_ABI_ASSERT(
    bonus_meta_table_is_0x12c,
    sizeof(bonus_meta_t[15]) == 0x12c);
CRIMSON_ABI_ASSERT_ALIGN4(bonus_meta, bonus_meta_t);
CRIMSON_ABI_ASSERT(
    quest_builder_fn_is_32_bit,
    sizeof(quest_builder_fn_t) == 4);
CRIMSON_ABI_ASSERT(quest_meta_is_0x2c, sizeof(quest_meta_t) == 0x2c);
CRIMSON_ABI_ASSERT(
    quest_meta_table_is_0x898,
    sizeof(quest_meta_t[50]) == 0x898);
CRIMSON_ABI_ASSERT_ALIGN4(quest_meta, quest_meta_t);
CRIMSON_ABI_ASSERT(perk_meta_is_0x14, sizeof(perk_meta_t) == 0x14);
CRIMSON_ABI_ASSERT(
    perk_meta_table_is_0xa00,
    sizeof(perk_meta_t[128]) == 0xa00);
CRIMSON_ABI_ASSERT_ALIGN4(perk_meta, perk_meta_t);
CRIMSON_ABI_ASSERT(
    highscore_record_is_0x48,
    sizeof(highscore_record_t) == 0x48);
CRIMSON_ABI_ASSERT(
    highscore_table_is_0x1c20,
    sizeof(highscore_record_t[100]) == 0x1c20);
CRIMSON_ABI_ASSERT_ALIGN4(highscore_record, highscore_record_t);
CRIMSON_ABI_ASSERT(
    credits_line_table_is_0x800,
    sizeof(credits_line_table_t) == 0x800);
CRIMSON_ABI_ASSERT_ALIGN4(credits_line_table, credits_line_table_t);
CRIMSON_ABI_ASSERT(
    weapon_usage_counts_is_0xd4,
    sizeof(weapon_usage_counts_t) == 0xd4);
CRIMSON_ABI_ASSERT(
    quest_play_counts_is_0x16c,
    sizeof(quest_play_counts_t) == 0x16c);
CRIMSON_ABI_ASSERT(game_status_is_0x268, sizeof(game_status_t) == 0x268);
CRIMSON_ABI_ASSERT_ALIGN4(game_status, game_status_t);
CRIMSON_ABI_ASSERT(
    quest_spawn_entry_is_0x18,
    sizeof(quest_spawn_entry_t) == 0x18);
CRIMSON_ABI_ASSERT(
    quest_spawn_table_is_0x1800,
    sizeof(quest_spawn_entry_t[256]) == 0x1800);
CRIMSON_ABI_ASSERT_ALIGN4(quest_spawn_entry, quest_spawn_entry_t);
CRIMSON_ABI_ASSERT(
    bonus_hud_slot_is_0x20,
    sizeof(bonus_hud_slot_t) == 0x20);
CRIMSON_ABI_ASSERT(
    bonus_hud_slot_table_is_0x200,
    sizeof(bonus_hud_slot_table_t) == 0x200);
CRIMSON_ABI_ASSERT_ALIGN4(bonus_hud_slot, bonus_hud_slot_t);
CRIMSON_ABI_ASSERT(
    effect_template_is_0x3c,
    sizeof(effect_template_t) == 0x3c);
CRIMSON_ABI_ASSERT_ALIGN4(effect_template, effect_template_t);
CRIMSON_ABI_ASSERT(effect_color_is_0x10, sizeof(effect_color_t) == 0x10);
CRIMSON_ABI_ASSERT(
    effect_id_entry_is_0x08,
    sizeof(effect_id_entry_t) == 0x08);
CRIMSON_ABI_ASSERT(
    effect_color_array_64_is_0x400,
    sizeof(effect_color_t[64]) == 0x400);
CRIMSON_ABI_ASSERT(effect_vec2_is_0x08, sizeof(effect_vec2_t) == 0x08);
CRIMSON_ABI_ASSERT(effect_entry_is_0xbc, sizeof(effect_entry_t) == 0xbc);
CRIMSON_ABI_ASSERT(
    effect_pool_is_0x17800,
    sizeof(effect_pool_t) == 0x17800);
CRIMSON_ABI_ASSERT_ALIGN4(effect_color, effect_color_t);
CRIMSON_ABI_ASSERT_ALIGN4(effect_vec2, effect_vec2_t);
CRIMSON_ABI_ASSERT_ALIGN4(effect_entry, effect_entry_t);
CRIMSON_ABI_ASSERT_ALIGN4(effect_pool, effect_pool_t);
CRIMSON_ABI_ASSERT(
    sfx_mute_flags_is_0x80,
    sizeof(sfx_mute_flags_t) == 0x80);

CRIMSON_ABI_ASSERT(effect_vertex_is_0x1c, sizeof(effect_vertex_t) == 0x1c);
CRIMSON_ABI_ASSERT(uv2_is_0x08, sizeof(uv2f_t) == 0x08);
CRIMSON_ABI_ASSERT(uv2_array_4_is_0x20, sizeof(uv2f_t[4]) == 0x20);
CRIMSON_ABI_ASSERT(uv2_array_16_is_0x80, sizeof(uv2f_t[16]) == 0x80);
CRIMSON_ABI_ASSERT(uv2_array_64_is_0x200, sizeof(uv2f_t[64]) == 0x200);
CRIMSON_ABI_ASSERT(uv2_array_256_is_0x800, sizeof(uv2f_t[256]) == 0x800);
CRIMSON_ABI_ASSERT_ALIGN4(uv2, uv2f_t);
CRIMSON_ABI_ASSERT(ui_vertex_is_0x1c, sizeof(ui_element_vertex_t) == 0x1c);
CRIMSON_ABI_ASSERT(
    ui_subtemplate_is_0xe8,
    sizeof(ui_menu_item_subtemplate_block_t) == 0xe8);
CRIMSON_ABI_ASSERT(
    ui_element_callback_is_32_bit,
    sizeof(ui_element_callback_t) == 4);
CRIMSON_ABI_ASSERT(ui_element_is_0x318, sizeof(ui_element_t) == 0x318);
CRIMSON_ABI_ASSERT(
    ui_element_pointer_table_is_0xa4,
    sizeof(ui_element_t *[41]) == 0xa4);
CRIMSON_ABI_ASSERT_ALIGN4(ui_element, ui_element_t);
CRIMSON_ABI_ASSERT(ui_menu_item_is_0x10, sizeof(ui_menu_item_t) == 0x10);
CRIMSON_ABI_ASSERT(ui_button_is_0x18, sizeof(ui_button_t) == 0x18);
CRIMSON_ABI_ASSERT(
    perk_selection_choice_items_are_0xa0,
    sizeof(perk_selection_choice_item_table_t) == 0xa0);
CRIMSON_ABI_ASSERT(
    ui_segmented_slider_is_0x10,
    sizeof(ui_segmented_slider_t) == 0x10);
CRIMSON_ABI_ASSERT(ui_list_widget_is_0x1c, sizeof(ui_list_widget_t) == 0x1c);
CRIMSON_ABI_ASSERT(ui_scrollbar_is_0x38, sizeof(ui_scrollbar_t) == 0x38);
CRIMSON_ABI_ASSERT(ui_checkbox_is_0x08, sizeof(ui_checkbox_t) == 0x08);
CRIMSON_ABI_ASSERT(
    ui_text_input_state_is_0x14,
    sizeof(ui_text_input_state_t) == 0x14);
CRIMSON_ABI_ASSERT(
    controls_rebind_items_is_0xf0,
    sizeof(controls_rebind_item_table_t) == 0xf0);
CRIMSON_ABI_ASSERT_ALIGN4(ui_button, ui_button_t);
CRIMSON_ABI_ASSERT_ALIGN4(ui_menu_item, ui_menu_item_t);
CRIMSON_ABI_ASSERT_ALIGN4(
    perk_selection_choice_items,
    perk_selection_choice_item_table_t);
CRIMSON_ABI_ASSERT_ALIGN4(ui_segmented_slider, ui_segmented_slider_t);
CRIMSON_ABI_ASSERT_ALIGN4(ui_list_widget, ui_list_widget_t);
CRIMSON_ABI_ASSERT_ALIGN4(ui_scrollbar, ui_scrollbar_t);
CRIMSON_ABI_ASSERT_ALIGN4(ui_checkbox, ui_checkbox_t);
CRIMSON_ABI_ASSERT_ALIGN4(ui_text_input_state, ui_text_input_state_t);
CRIMSON_ABI_ASSERT_ALIGN4(
    controls_rebind_items,
    controls_rebind_item_table_t);

CRIMSON_ABI_ASSERT(
    console_history_entry_is_8_bytes,
    sizeof(console_history_entry_t) == 8);
CRIMSON_ABI_ASSERT(console_log_node_is_8_bytes, sizeof(console_log_node_t) == 8);
CRIMSON_ABI_ASSERT(console_queue_is_0x2c, sizeof(console_queue_t) == 0x2c);
CRIMSON_ABI_ASSERT(
    console_queue_alignment_is_four,
    offsetof(crimson_console_queue_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    console_queue_open_is_at_0x28,
    offsetof(console_queue_t, open) == 0x28);

CRIMSON_ABI_ASSERT(mod_api_vtable_is_0x88, sizeof(mod_api_vtbl_t) == 0x88);
CRIMSON_ABI_ASSERT_ALIGN4(mod_api_vtable, mod_api_vtbl_t);
CRIMSON_ABI_ASSERT(mod_api_cpp_is_0x6c, sizeof(mod_api_cpp_t) == 0x6c);
CRIMSON_ABI_ASSERT(mod_api_is_0x68, sizeof(mod_api_t) == 0x68);
CRIMSON_ABI_ASSERT(mod_info_is_0x48, sizeof(mod_info_t) == 0x48);
CRIMSON_ABI_ASSERT_ALIGN4(mod_api, mod_api_t);
CRIMSON_ABI_ASSERT_ALIGN4(mod_info, mod_info_t);
CRIMSON_ABI_ASSERT(
    mod_api_state_is_at_0x68,
    offsetof(mod_api_cpp_t, field_0x68) == 0x68);
CRIMSON_ABI_ASSERT(mod_interface_is_0x408, sizeof(mod_interface_cpp_t) == 0x408);

typedef void (mod_api_cpp_t::*crimson_mod_execute_fn)(char *);
typedef unsigned char (mod_interface_cpp_t::*crimson_mod_frame_fn)(int);

CRIMSON_ABI_ASSERT(
    mod_api_member_pointer_is_32_bit,
    sizeof(crimson_mod_execute_fn) == 4);
CRIMSON_ABI_ASSERT(
    mod_interface_member_pointer_is_32_bit,
    sizeof(crimson_mod_frame_fn) == 4);

static crimson_mod_execute_fn crimson_abi_mod_execute =
    &mod_api_cpp_t::mod_api_core_execute;
static crimson_mod_frame_fn crimson_abi_mod_frame =
    &mod_interface_cpp_t::frame;
