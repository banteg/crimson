/* Crimsonland types derived from static analysis. */
#ifndef CRIMSONLAND_TYPES_H
#define CRIMSONLAND_TYPES_H

typedef struct weapon_stats_t {
    char name[0x40];
    unsigned char unlocked;
    unsigned char _pad0[3];
    int clip_size;
    float shot_cooldown;
    float reload_time;
    float spread_heat;
    unsigned char _pad1[4];
    int shot_sfx_base_id;
    int shot_sfx_variant_count;
    int reload_sfx_id;
    int hud_icon_id;
    unsigned char flags;
    unsigned char _pad2[3];
    float projectile_meta;
    float damage_scale;
    int pellet_count;
    unsigned char _pad3[4];
} weapon_stats_t;

typedef struct audio_entry_t {
    unsigned short format_tag;
    unsigned short channels;
    unsigned int sample_rate;
    unsigned int avg_bytes_per_sec;
    unsigned short block_align;
    unsigned short bits_per_sample;
    unsigned short cb_size;
    unsigned short _pad0;
    void *pcm_data;
    unsigned int pcm_bytes;
    unsigned int stream_cursor;
    float volume;
    void *buffers[16];
    unsigned char buffer_in_use[16];
    void *vorbis_stream;
    unsigned int stream_fill_bytes;
    unsigned int stream_total_bytes;
    unsigned int stream_cursor_bytes;
} audio_entry_t;

typedef audio_entry_t sfx_entry_t;
typedef audio_entry_t music_entry_t;

typedef struct player_input_t {
    int move_key_forward;
    int move_key_backward;
    int turn_key_left;
    int turn_key_right;
    int fire_key;
    int key_reserved_0;
    int key_reserved_1;
    int aim_key_left;
    int aim_key_right;
    int axis_aim_x;
    int axis_aim_y;
    int axis_move_x;
    int axis_move_y;
} player_input_t;

typedef struct player_state_t {
    unsigned char _pad0[0x308];
    player_input_t input;
    unsigned char _pad1[0x24];
} player_state_t;

typedef struct creature_t {
    unsigned char active;
    unsigned char _pad0[3];
    float phase_seed;
    unsigned char state_flag;
    unsigned char collision_flag;
    unsigned char _pad1[2];
    float collision_timer;
    float hitbox_size;
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    float health;
    float max_health;
    float heading;
    float target_heading;
    float size;
    float hit_flash_timer;
    float tint_r;
    float tint_g;
    float tint_b;
    float tint_a;
    int force_target;
    float target_x;
    float target_y;
    float contact_damage;
    float move_speed;
    float attack_cooldown;
    float reward_value;
    unsigned char _pad2[4];
    int type_id;
    int target_player;
    unsigned char _pad3[4];
    int link_index;
    float target_offset_x;
    float target_offset_y;
    float orbit_angle;
    float orbit_radius;
    int flags;
    int ai_mode;
    float anim_phase;
} creature_t;

typedef struct projectile_t {
    unsigned char active;
    unsigned char _pad0[3];
    float angle;
    float pos_x;
    float pos_y;
    float origin_x;
    float origin_y;
    float vel_x;
    float vel_y;
    int type_id;
    float life_timer;
    float reserved;
    float speed_scale;
    float damage_pool;
    float hit_radius;
    float base_damage;
    int owner_id;
} projectile_t;

typedef struct particle_t {
    unsigned char active;
    unsigned char render_flag;
    unsigned char _pad0[2];
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    float scale_x;
    float scale_y;
    float scale_z;
    float age;
    float intensity;
    float angle;
    float spin;
    int style_id;
    int target_id;
} particle_t;

typedef struct secondary_projectile_t {
    unsigned char active;
    unsigned char _pad0[3];
    float angle;
    float speed;
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    int type_id;
    float lifetime;
    int target_id;
} secondary_projectile_t;

typedef struct fx_queue_entry_t {
    int effect_id;
    float rotation;
    float pos_x;
    float pos_y;
    float height;
    float width;
    float color_r;
    float color_g;
    float color_b;
    float color_a;
} fx_queue_entry_t;

typedef struct sprite_effect_t {
    int active;
    float color_r;
    float color_g;
    float color_b;
    float color_a;
    float rotation;
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    float scale;
} sprite_effect_t;

typedef struct effect_entry_t {
    float pos_x;
    float pos_y;
    unsigned char effect_id;
    unsigned char _pad0[3];
    float vel_x;
    float vel_y;
    float rotation;
    float scale;
    float half_width;
    float half_height;
    float age;
    float lifetime;
    int flags;
    float color_r;
    float color_g;
    float color_b;
    float color_a;
    float rotation_step;
    float scale_step;
    float quad_data[29];
} effect_entry_t;

typedef struct ui_element_t {
    unsigned char active;
    unsigned char enabled;
    unsigned char _pad0[0x16];
    float pos_x;
    float pos_y;
    unsigned char _pad1[0x14];
    void (*on_activate)(void);
    unsigned char _pad2[4];
    float quad0[14];
    float quad1[14];
    float quad2[14];
    unsigned char _pad3[0x38];
    int texture_handle;
    int quad_mode;
    unsigned char _pad4[0xe0];
    int counter_id;
    unsigned char _pad5[0xf0];
    int counter_value;
    int counter_timer;
    float render_scale;
    float rot_m00;
    float rot_m01;
    float rot_m10;
    float rot_m11;
} ui_element_t;

typedef struct crimson_cfg_t {
    unsigned char reserved0[0x0a8];
    char saved_names[8][27];
    char player_name[32];
    int player_name_length;
    unsigned char reserved1[0x14];
    int display_bpp;
    int screen_width;
    int screen_height;
    int windowed;
    int keybinds_p1[13];
    unsigned char reserved2[0x0c];
    int keybinds_p2[13];
    unsigned char reserved3[0x0c];
    unsigned char reserved4[0x200];
    unsigned char hardcore;
    unsigned char full_version;
    unsigned char reserved5[2];
    int perk_prompt_counter;
    unsigned char reserved6[0x14];
    float sfx_volume;
    float music_volume;
    unsigned char fx_toggle;
    unsigned char score_load_gate;
    unsigned char reserved7[2];
    int detail_preset;
    unsigned char reserved8[4];
    int key_pick_perk;
    int key_reload;
} crimson_cfg_t;

typedef struct game_status_t {
    unsigned short quest_unlock_index;
    unsigned short quest_unlock_index_full;
    unsigned int weapon_usage_counts[53];
    unsigned int quest_play_counts[91];
    unsigned int mode_play_survival;
    unsigned int mode_play_rush;
    unsigned int mode_play_typo;
    unsigned int mode_play_other;
    unsigned int game_sequence_id;
    unsigned char reserved0[0x10];
} game_status_t;

typedef struct highscore_record_t {
    char player_name[0x20];
    unsigned int survival_elapsed_ms;
    unsigned int score_xp;
    unsigned char game_mode_id;
    unsigned char quest_stage_major;
    unsigned char quest_stage_minor;
    unsigned char most_used_weapon_id;
    unsigned int shots_fired;
    unsigned int shots_hit;
    unsigned int creature_kill_count;
    unsigned char reserved0[0x08];
    unsigned char day;
    unsigned char date_checksum;
    unsigned char month;
    unsigned char year_offset;
    unsigned char flags;
    unsigned char full_version_marker;
    unsigned char sentinel_pipe;
    unsigned char sentinel_ff;
} highscore_record_t;

#endif
