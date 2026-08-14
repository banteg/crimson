#ifndef CRIMSONLAND_UI_STATE_OWNER_H
#define CRIMSONLAND_UI_STATE_OWNER_H

/*
 * Target-era prefix of the contiguous UI owner rooted at 0x004871cc.
 * The authenticated 2003 ui_t declaration fixes the member order through the
 * two layout scale factors.  Several meanings changed by 1.9.93, so the
 * semantic names below follow the target while preserving that ownership.
 */
struct ui_element_t;

typedef struct ui_runtime_state_original_t {
    unsigned char ui_mouse_blocked;
    unsigned char pad_01[3];
    float player_aux_timer[2];
    float camera_shake_offset_value[2];
    float camera_shake_timer;
    int camera_shake_pulses;
    int player_name_length;
    float ui_mouse[2];
    float player_aim_screen_xy[16];
    int ui_screen_phase;
    int ui_element_hover_focus_index;
    struct ui_element_t *ui_element_hover_focus_ptr;
    unsigned char render_pass_mode;
    unsigned char gameplay_transition_latch;
    unsigned char pad_76[2];
    int quest_stage_banner_timer_ms;
    int ui_elements_timeline;
    unsigned char ui_transition_direction;
    unsigned char highscore_return_latch;
    unsigned char pad_82[2];
    int highscore_return_quest_stage_major;
    int highscore_return_quest_stage_minor;
    int highscore_return_game_mode_id;
    unsigned char highscore_return_hardcore_flag;
    unsigned char pad_91[3];
    int game_over_reserved_zero;
    float screen_fade_alpha;
    int perk_doctor_target_creature_id;
    int game_state_prev;
    int game_state_id;
    int game_state_pending;
    float ui_transition_alpha;
    unsigned char player_overlay_suppressed_latch;
    unsigned char pad_b1[3];
    int ui_level_up_position;
    int pause_keybind_help_alpha_ms;
    float ui_layout_scale_x;
    float ui_layout_scale_y;
    struct ui_element_t ui_sign_crimson;
    struct ui_element_t ui_element_slot_01_main_menu_aux;
    struct ui_element_t ui_element_slot_03_main_menu_play_game;
    struct ui_element_t ui_element_slot_04_main_menu_options;
    struct ui_element_t ui_element_slot_05_main_menu_statistics;
    struct ui_element_t ui_element_slot_02_main_menu_primary;
    struct ui_element_t ui_element_slot_footer_variant_a;
    struct ui_element_t ui_element_slot_footer_variant_b;
    struct ui_element_t ui_element_slot_31;
    struct ui_element_t ui_element_slot_32_layout_c;
    struct ui_element_t ui_element_slot_10;
    struct ui_element_t ui_element_slot_11;
    struct ui_element_t ui_element_slot_12_layout_a;
    struct ui_element_t ui_element_slot_08;
    struct ui_element_t ui_element_slot_09;
    struct ui_element_t ui_element_slot_33;
    struct ui_element_t ui_element_slot_15;
    struct ui_element_t ui_element_slot_16;
    struct ui_element_t ui_element_slot_17;
    struct ui_element_t ui_element_slot_19;
    struct ui_element_t ui_element_slot_20;
    struct ui_element_t ui_element_slot_21;
    struct ui_element_t ui_element_slot_22;
    struct ui_element_t ui_element_slot_23;
    struct ui_element_t ui_element_slot_24;
    struct ui_element_t ui_element_slot_25;
    struct ui_element_t ui_element_slot_26;
    struct ui_element_t ui_element_slot_27;
    struct ui_element_t ui_element_slot_29;
    struct ui_element_t ui_element_slot_30;
    struct ui_element_t ui_element_slot_13;
    struct ui_element_t ui_element_slot_14;
    struct ui_element_t ui_element_slot_18_layout_b;
    struct ui_element_t ui_element_slot_34;
    struct ui_element_t ui_element_slot_35;
    struct ui_element_t ui_element_slot_36;
    struct ui_element_t ui_element_slot_37;
    struct ui_element_t ui_element_slot_38;
    struct ui_element_t ui_element_slot_39;
    struct ui_element_t ui_element_slot_28;
    struct ui_element_t ui_element_slot_40;
    struct ui_element_t *element_table_member[41];
    struct ui_element_t ui_perk_prompt_element;
    int perk_prompt_timer;
} ui_runtime_state_original_t;

#ifdef __cplusplus
extern "C" {
#endif
extern unsigned char ui_mouse_blocked;
#ifdef __cplusplus
}
#endif

#define ui_runtime_state \
    (*(ui_runtime_state_original_t *)&ui_mouse_blocked)

#ifdef CRIMSONLAND_USE_ORIGINAL_UI_OWNER
#define player_aux_timer ui_runtime_state.player_aux_timer
#define camera_shake_offset_x ui_runtime_state.camera_shake_offset_value[0]
#define camera_shake_offset_y ui_runtime_state.camera_shake_offset_value[1]
#define camera_shake_timer ui_runtime_state.camera_shake_timer
#define camera_shake_pulses ui_runtime_state.camera_shake_pulses
#define player_name_length ui_runtime_state.player_name_length
#define ui_mouse_x ui_runtime_state.ui_mouse[0]
#define ui_mouse_y ui_runtime_state.ui_mouse[1]
#define player_aim_screen_x ui_runtime_state.player_aim_screen_xy
#define ui_screen_phase ui_runtime_state.ui_screen_phase
#define ui_element_hover_focus_index \
    ui_runtime_state.ui_element_hover_focus_index
#define ui_element_hover_focus_ptr ui_runtime_state.ui_element_hover_focus_ptr
#define render_pass_mode ui_runtime_state.render_pass_mode
#define gameplay_transition_latch ui_runtime_state.gameplay_transition_latch
#define quest_stage_banner_timer_ms \
    ui_runtime_state.quest_stage_banner_timer_ms
#define ui_elements_timeline ui_runtime_state.ui_elements_timeline
#define ui_transition_direction ui_runtime_state.ui_transition_direction
#define highscore_return_latch ui_runtime_state.highscore_return_latch
#define highscore_return_quest_stage_major \
    ui_runtime_state.highscore_return_quest_stage_major
#define highscore_return_quest_stage_minor \
    ui_runtime_state.highscore_return_quest_stage_minor
#define highscore_return_game_mode_id \
    ui_runtime_state.highscore_return_game_mode_id
#define highscore_return_hardcore_flag \
    ui_runtime_state.highscore_return_hardcore_flag
#define data_487260 ui_runtime_state.game_over_reserved_zero
#define screen_fade_alpha ui_runtime_state.screen_fade_alpha
#define perk_doctor_target_creature_id \
    ui_runtime_state.perk_doctor_target_creature_id
#define game_state_prev ui_runtime_state.game_state_prev
#define game_state_id ui_runtime_state.game_state_id
#define game_state_pending ui_runtime_state.game_state_pending
#define ui_transition_alpha ui_runtime_state.ui_transition_alpha
#define player_overlay_suppressed_latch \
    ui_runtime_state.player_overlay_suppressed_latch
#define pause_keybind_help_alpha_ms \
    ui_runtime_state.pause_keybind_help_alpha_ms
#define ui_layout_scale_x ui_runtime_state.ui_layout_scale_x
#define ui_layout_scale_y ui_runtime_state.ui_layout_scale_y
#define ui_sign_crimson ui_runtime_state.ui_sign_crimson
#define ui_element_slot_01_main_menu_aux \
    ui_runtime_state.ui_element_slot_01_main_menu_aux
#define ui_element_slot_02_main_menu_primary \
    ui_runtime_state.ui_element_slot_02_main_menu_primary
#define ui_element_slot_03_main_menu_play_game \
    ui_runtime_state.ui_element_slot_03_main_menu_play_game
#define ui_element_slot_04_main_menu_options \
    ui_runtime_state.ui_element_slot_04_main_menu_options
#define ui_element_slot_05_main_menu_statistics \
    ui_runtime_state.ui_element_slot_05_main_menu_statistics
#define ui_element_slot_footer_variant_a \
    ui_runtime_state.ui_element_slot_footer_variant_a
#define ui_element_slot_footer_variant_b \
    ui_runtime_state.ui_element_slot_footer_variant_b
#define ui_element_slot_08 ui_runtime_state.ui_element_slot_08
#define ui_element_slot_09 ui_runtime_state.ui_element_slot_09
#define ui_element_slot_10 ui_runtime_state.ui_element_slot_10
#define ui_element_slot_11 ui_runtime_state.ui_element_slot_11
#define ui_element_slot_12_layout_a \
    ui_runtime_state.ui_element_slot_12_layout_a
#define ui_element_slot_13 ui_runtime_state.ui_element_slot_13
#define ui_element_slot_14 ui_runtime_state.ui_element_slot_14
#define ui_element_slot_15 ui_runtime_state.ui_element_slot_15
#define ui_element_slot_16 ui_runtime_state.ui_element_slot_16
#define ui_element_slot_17 ui_runtime_state.ui_element_slot_17
#define ui_element_slot_18_layout_b \
    ui_runtime_state.ui_element_slot_18_layout_b
#define ui_element_slot_19 ui_runtime_state.ui_element_slot_19
#define ui_element_slot_20 ui_runtime_state.ui_element_slot_20
#define ui_element_slot_21 ui_runtime_state.ui_element_slot_21
#define ui_element_slot_22 ui_runtime_state.ui_element_slot_22
#define ui_element_slot_23 ui_runtime_state.ui_element_slot_23
#define ui_element_slot_24 ui_runtime_state.ui_element_slot_24
#define ui_element_slot_25 ui_runtime_state.ui_element_slot_25
#define ui_element_slot_26 ui_runtime_state.ui_element_slot_26
#define ui_element_slot_27 ui_runtime_state.ui_element_slot_27
#define ui_element_slot_28 ui_runtime_state.ui_element_slot_28
#define ui_element_slot_29 ui_runtime_state.ui_element_slot_29
#define ui_element_slot_30 ui_runtime_state.ui_element_slot_30
#define ui_element_slot_31 ui_runtime_state.ui_element_slot_31
#define ui_element_slot_32_layout_c \
    ui_runtime_state.ui_element_slot_32_layout_c
#define ui_element_slot_33 ui_runtime_state.ui_element_slot_33
#define ui_element_slot_34 ui_runtime_state.ui_element_slot_34
#define ui_element_slot_35 ui_runtime_state.ui_element_slot_35
#define ui_element_slot_36 ui_runtime_state.ui_element_slot_36
#define ui_element_slot_37 ui_runtime_state.ui_element_slot_37
#define ui_element_slot_38 ui_runtime_state.ui_element_slot_38
#define ui_element_slot_39 ui_runtime_state.ui_element_slot_39
#define ui_element_slot_40 ui_runtime_state.ui_element_slot_40
#define ui_element_table ui_runtime_state.element_table_member
#define ui_element_table_end ui_runtime_state.element_table_member[0]
#define ui_element_table_slot_01_main_menu_aux \
    ui_runtime_state.element_table_member[1]
#define ui_element_table_slot_02_main_menu_primary \
    ui_runtime_state.element_table_member[2]
#define ui_element_table_slot_03_main_menu_play_game \
    ui_runtime_state.element_table_member[3]
#define ui_element_table_slot_04_main_menu_options \
    ui_runtime_state.element_table_member[4]
#define ui_element_table_slot_05_main_menu_statistics \
    ui_runtime_state.element_table_member[5]
#define ui_element_table_slot_06_main_menu_footer_a \
    ui_runtime_state.element_table_member[6]
#define ui_element_table_slot_07_main_menu_footer_b \
    ui_runtime_state.element_table_member[7]
#define ui_element_table_slot_08 ui_runtime_state.element_table_member[8]
#define ui_element_table_slot_09 ui_runtime_state.element_table_member[9]
#define ui_element_table_slot_10 ui_runtime_state.element_table_member[10]
#define ui_element_table_slot_11 ui_runtime_state.element_table_member[11]
#define ui_menu_layout_a ui_runtime_state.element_table_member[12]
#define ui_element_table_slot_13 ui_runtime_state.element_table_member[13]
#define ui_element_table_slot_14 ui_runtime_state.element_table_member[14]
#define ui_element_table_slot_15 ui_runtime_state.element_table_member[15]
#define ui_element_table_slot_16 ui_runtime_state.element_table_member[16]
#define ui_element_table_slot_17 ui_runtime_state.element_table_member[17]
#define ui_menu_layout_b ui_runtime_state.element_table_member[18]
#define ui_element_table_slot_19 ui_runtime_state.element_table_member[19]
#define ui_element_table_slot_20 ui_runtime_state.element_table_member[20]
#define ui_element_table_slot_21 ui_runtime_state.element_table_member[21]
#define ui_element_table_slot_22 ui_runtime_state.element_table_member[22]
#define ui_element_table_slot_23 ui_runtime_state.element_table_member[23]
#define ui_element_table_slot_24 ui_runtime_state.element_table_member[24]
#define ui_element_table_slot_25 ui_runtime_state.element_table_member[25]
#define ui_element_table_slot_26 ui_runtime_state.element_table_member[26]
#define ui_element_table_slot_27 ui_runtime_state.element_table_member[27]
#define ui_element_table_slot_28 ui_runtime_state.element_table_member[28]
#define ui_element_table_slot_29 ui_runtime_state.element_table_member[29]
#define ui_element_table_slot_30 ui_runtime_state.element_table_member[30]
#define ui_element_table_slot_31 ui_runtime_state.element_table_member[31]
#define ui_menu_layout_c ui_runtime_state.element_table_member[32]
#define ui_element_table_slot_33 ui_runtime_state.element_table_member[33]
#define ui_element_table_slot_34 ui_runtime_state.element_table_member[34]
#define ui_element_table_slot_35 ui_runtime_state.element_table_member[35]
#define ui_element_table_slot_36 ui_runtime_state.element_table_member[36]
#define ui_element_table_slot_37 ui_runtime_state.element_table_member[37]
#define ui_element_table_slot_38 ui_runtime_state.element_table_member[38]
#define ui_element_table_slot_39 ui_runtime_state.element_table_member[39]
#define ui_element_table_start ui_runtime_state.element_table_member[40]
#define ui_perk_prompt_element ui_runtime_state.ui_perk_prompt_element
#define perk_prompt_timer ui_runtime_state.perk_prompt_timer
#endif

#endif
