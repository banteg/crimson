#include <stddef.h>

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

struct crimson_float_alignment_probe_t {
    char prefix;
    float value;
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
CRIMSON_ABI_ASSERT(int_is_32_bit, sizeof(int) == 4);
CRIMSON_ABI_ASSERT(unsigned_int_is_32_bit, sizeof(unsigned int) == 4);
CRIMSON_ABI_ASSERT(long_is_32_bit, sizeof(long) == 4);
CRIMSON_ABI_ASSERT(float_is_32_bit, sizeof(float) == 4);
CRIMSON_ABI_ASSERT(bool_is_one_byte, sizeof(bool) == 1);
CRIMSON_ABI_ASSERT(unsigned_char_is_one_byte, sizeof(unsigned char) == 1);
CRIMSON_ABI_ASSERT(game_mode_id_is_32_bit, sizeof(game_mode_id_t) == 4);
CRIMSON_ABI_ASSERT(game_state_id_is_32_bit, sizeof(game_state_id_t) == 4);
CRIMSON_ABI_ASSERT(u16_is_16_bit, sizeof(u16_t) == 2);

CRIMSON_ABI_ASSERT(
    default_char_alignment_is_one,
    offsetof(crimson_char_alignment_probe_t, value) == 1);
CRIMSON_ABI_ASSERT(
    default_int_alignment_is_four,
    offsetof(crimson_int_alignment_probe_t, value) == 4);
CRIMSON_ABI_ASSERT(
    default_float_alignment_is_four,
    offsetof(crimson_float_alignment_probe_t, value) == 4);
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
CRIMSON_ABI_ASSERT(audio_entry_is_0x84, sizeof(audio_entry_t) == 0x84);
CRIMSON_ABI_ASSERT(
    audio_entry_table_is_0x4200,
    sizeof(audio_entry_t[128]) == 0x4200);
CRIMSON_ABI_ASSERT_ALIGN4(audio_entry, audio_entry_t);

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
CRIMSON_ABI_ASSERT(bonus_entry_is_0x1c, sizeof(bonus_entry_t) == 0x1c);
CRIMSON_ABI_ASSERT(bonus_pool_is_0x1c0, sizeof(bonus_pool_t) == 0x1c0);
CRIMSON_ABI_ASSERT_ALIGN4(bonus_entry, bonus_entry_t);
CRIMSON_ABI_ASSERT(bonus_meta_is_0x14, sizeof(bonus_meta_t) == 0x14);
CRIMSON_ABI_ASSERT(
    bonus_meta_table_is_0x12c,
    sizeof(bonus_meta_t[15]) == 0x12c);
CRIMSON_ABI_ASSERT_ALIGN4(bonus_meta, bonus_meta_t);
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
CRIMSON_ABI_ASSERT(game_status_is_0x268, sizeof(game_status_t) == 0x268);
CRIMSON_ABI_ASSERT_ALIGN4(game_status, game_status_t);
CRIMSON_ABI_ASSERT(
    effect_template_is_0x3c,
    sizeof(effect_template_t) == 0x3c);
CRIMSON_ABI_ASSERT_ALIGN4(effect_template, effect_template_t);
CRIMSON_ABI_ASSERT(
    sfx_mute_flags_is_0x80,
    sizeof(sfx_mute_flags_t) == 0x80);

CRIMSON_ABI_ASSERT(effect_vertex_is_0x1c, sizeof(effect_vertex_t) == 0x1c);
CRIMSON_ABI_ASSERT(ui_vertex_is_0x1c, sizeof(ui_element_vertex_t) == 0x1c);
CRIMSON_ABI_ASSERT(
    ui_subtemplate_is_0xe8,
    sizeof(ui_menu_item_subtemplate_block_t) == 0xe8);
CRIMSON_ABI_ASSERT(ui_element_is_0x318, sizeof(ui_element_t) == 0x318);
CRIMSON_ABI_ASSERT(
    ui_element_pointer_table_is_0xa4,
    sizeof(ui_element_t *[41]) == 0xa4);
CRIMSON_ABI_ASSERT_ALIGN4(ui_element, ui_element_t);

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

CRIMSON_ABI_ASSERT(mod_api_cpp_is_0x6c, sizeof(mod_api_cpp_t) == 0x6c);
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
