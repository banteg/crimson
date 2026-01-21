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

#endif
