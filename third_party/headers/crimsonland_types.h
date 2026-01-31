/* Crimsonland types derived from static analysis. */
#ifndef CRIMSONLAND_TYPES_H
#define CRIMSONLAND_TYPES_H

typedef struct vec2f_t {
    float x;
    float y;
} vec2f_t;

typedef struct uv2f_t {
    float u;
    float v;
} uv2f_t;

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

typedef float sfx_cooldown_table_t[0x80];
typedef LPDIRECTSOUNDBUFFER sfx_voice_table_t[0x20];
typedef float sfx_volume_table_t[0x80];
typedef char sfx_mute_flags_t[0x80];
typedef int music_playlist_t[0x80];

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
    float death_timer;
    float pos_x;
    float pos_y;
    float move_dx;
    float move_dy;
    float health;
    float max_health;
    float heading;
    float target_heading;
    float size;
    unsigned char _pad0[0x18];
    float aim_x;
    float aim_y;
    unsigned char _pad1[4];
    float speed_multiplier;
    int weapon_reset_latch;
    unsigned char _pad2[4];
    float move_speed;
    unsigned char _pad3[0x28];
    float move_phase;
    unsigned char _pad4[4];
    float hot_tempered_timer;
    float man_bomb_timer;
    float living_fortress_timer;
    float fire_cough_timer;
    int experience;
    unsigned char _pad5[4];
    int level;
    int perk_counts[0x80];
    float spread_heat;
    unsigned char _pad6[4];
    int weapon_id;
    int clip_size;
    int reload_active;
    int ammo;
    float reload_timer;
    float shot_cooldown;
    float reload_timer_max;
    int alt_weapon_id;
    int alt_clip_size;
    int alt_reload_active;
    int alt_ammo;
    float alt_reload_timer;
    float alt_shot_cooldown;
    float alt_reload_timer_max;
    unsigned char _pad7[4];
    float muzzle_flash_alpha;
    float aim_heading;
    float turn_speed;
    int state_aux;
    int evil_eyes_target_creature;
    float low_health_timer;
    float speed_bonus_timer;
    float shield_timer;
    float fire_bullets_timer;
    int auto_target;
    float move_target_x;
    float move_target_y;
    player_input_t input;
    unsigned char _pad8[0x10];
} player_state_t;

typedef struct creature_type_t {
    int texture_handle;
    int sfx_bank_a[4];
    int sfx_bank_b[2];
    unsigned char _pad0[4];
    float field_0x20;
    unsigned char _pad1[0x10];
    float anim_rate;
    int base_frame;
    int corpse_frame;
    int anim_flags;
} creature_type_t;

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

typedef struct creature_spawn_slot_t {
    creature_t *owner;
    int count;
    int limit;
    float interval_s;
    float timer_s;
    int template_id;
} creature_spawn_slot_t;

// Canonical projectile template ids used by `projectile_t.type_id`.
//
// Many weapons share a projectile template id (e.g. shotgun variants). We keep
// unique enum values here so Ghidra doesn't have to pick between duplicate
// names for the same value.
typedef enum projectile_type_id_t {
    PROJECTILE_TYPE_NONE = 0x00,
    PROJECTILE_TYPE_PISTOL = 0x01,
    PROJECTILE_TYPE_ASSAULT_RIFLE = 0x02,
    PROJECTILE_TYPE_SHOTGUN = 0x03,
    PROJECTILE_TYPE_SUBMACHINE_GUN = 0x05,
    PROJECTILE_TYPE_GAUSS_GUN = 0x06,
    PROJECTILE_TYPE_PLASMA_RIFLE = 0x09,
    PROJECTILE_TYPE_PLASMA_MINIGUN = 0x0B,
    PROJECTILE_TYPE_PULSE_GUN = 0x13,
    PROJECTILE_TYPE_ION_RIFLE = 0x15,
    PROJECTILE_TYPE_ION_MINIGUN = 0x16,
    PROJECTILE_TYPE_ION_CANNON = 0x17,
    PROJECTILE_TYPE_SHRINKIFIER = 0x18,
    PROJECTILE_TYPE_BLADE_GUN = 0x19,
    PROJECTILE_TYPE_PLASMA_CANNON = 0x1C,
    PROJECTILE_TYPE_SPLITTER_GUN = 0x1D,
    PROJECTILE_TYPE_PLAGUE_SPREADER = 0x29,
    PROJECTILE_TYPE_RAINBOW_GUN = 0x2B,
    PROJECTILE_TYPE_FIRE_BULLETS = 0x2D,
} projectile_type_id_t;

// Field grouping used to steer the decompiler away from float-bitpattern enums.
// A lot of native code takes the address of `origin_y` and then indexes into
// subsequent fields (+0xc hits `type_id`, etc).
typedef struct projectile_vel_y_block_t {
    float vel_y;
    projectile_type_id_t type_id;
    float life_timer;
    float reserved;
    float speed_scale;
    float damage_pool;
    float hit_radius;
    float base_damage;
    int owner_id;
} projectile_vel_y_block_t;

typedef struct projectile_tail_t {
    float origin_y;
    float vel_x;
    projectile_vel_y_block_t vy;
} projectile_tail_t;

// Similar to projectile_tail_t, but anchored at `pos_y` so loops that take
// `&projectile_t.pos_y` get a mixed-type view (type_id as enum/int, not float).
typedef struct projectile_pos_y_block_t {
    float pos_y;
    float origin_x;
    projectile_tail_t tail;
} projectile_pos_y_block_t;

typedef struct projectile_t {
    unsigned char active;
    unsigned char _pad0[3];
    float angle;
    float pos_x;
    projectile_pos_y_block_t pos;
} projectile_t;

typedef projectile_t projectile_pool_t[0x60];

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

typedef secondary_projectile_t secondary_projectile_pool_t[0x40];

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

typedef struct effect_id_entry_t {
    int size_code;
    int frame;
} effect_id_entry_t;

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

typedef struct ui_button_t {
    char *label;
    unsigned char hovered;
    unsigned char activated;
    unsigned char enabled;
    unsigned char _pad0;
    int hover_anim;
    int click_anim;
    float alpha;
    unsigned char force_small;
    unsigned char force_wide;
    unsigned char _pad1[2];
} ui_button_t;

typedef struct credits_line_t {
    char *text;
    int flags;
} credits_line_t;

typedef credits_line_t credits_line_table_t[0x100];

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

typedef struct quest_spawn_entry_t {
    float pos_x;
    // Field grouping used to steer the decompiler away from float-bitpattern ints.
    //
    // Quest builder code frequently takes the address of `pos_y` or `heading` and
    // then indexes into subsequent (mixed-type) fields.
    struct quest_spawn_entry_pos_y_block_t {
        float pos_y;
        struct quest_spawn_entry_heading_block_t {
            float heading;
            int template_id;
            int trigger_time_ms;
            int count;
        } heading_block;
    } pos_y_block;
} quest_spawn_entry_t;

typedef void (*quest_builder_fn_t)(quest_spawn_entry_t *entries, int *count);

typedef struct quest_meta_t {
    int tier;
    int index;
    int time_limit_ms;
    char *name;
    int terrain_id;
    int terrain_id_b;
    int terrain_id_c;
    quest_builder_fn_t builder;
    int unlock_perk_id;
    int unlock_weapon_id;
    int start_weapon_id;
} quest_meta_t;

typedef struct perk_meta_t {
    char *name;
    char *description;
    int flags;
    int available;
    int prerequisite;
} perk_meta_t;

typedef struct bonus_meta_t {
    char *label;
    char *description;
    int icon_id;
    unsigned char enabled;
    unsigned char _pad0[3];
    int default_amount;
} bonus_meta_t;

typedef struct bonus_entry_t {
    int bonus_id;
    unsigned char state;
    unsigned char _pad0[3];
    float time_left;
    float time_max;
    float pos_x;
    float pos_y;
    int amount;
} bonus_entry_t;

typedef struct bonus_hud_slot_t {
    unsigned char active;
    unsigned char _pad0[3];
    float slide_x;
    float field_0x08;
    float *timer_ptr;
    float *alt_timer_ptr;
    char *label;
    int icon_id;
    float field_0x1c;
} bonus_hud_slot_t;

typedef struct mod_info_t {
    char name[0x20];
    char author[0x20];
    float version;
    unsigned int usesApiVersion;
} mod_info_t;

typedef struct mod_var_t {
    char *id;
    char *stringValue;
    float *floatValue;
} mod_var_t;

typedef struct mod_vec2_t {
    float x;
    float y;
} mod_vec2_t;

typedef struct mod_vertex2_t {
    mod_vec2_t pos;
    mod_vec2_t zrhw;
    unsigned int col;
    mod_vec2_t tex;
} mod_vertex2_t;

typedef struct mod_key_config_t {
    int up[2];
    int down[2];
    int left[2];
    int right[2];
    int fire[2];
    int torsoLeft[2];
    int torsoRight[2];
    int joyAimAxisX[2];
    int joyAimAxisY[2];
    int joyMoveAxisX[2];
    int joyMoveAxisY[2];
    int levelUp;
    int reload;
} mod_key_config_t;

typedef struct mod_api_vtbl_t mod_api_vtbl_t;
typedef struct mod_api_t mod_api_t;
typedef struct mod_interface_t mod_interface_t;
typedef struct mod_interface_vtbl_t mod_interface_vtbl_t;

struct mod_api_t {
    mod_api_vtbl_t *vtable;
    int version;
    mod_key_config_t keyConfig;
};

struct mod_api_vtbl_t {
    void (*CORE_Printf)(mod_api_t *self, const char *fmt, ...);
    mod_var_t *(*CORE_GetVar)(mod_api_t *self, const char *id);
    unsigned char (*CORE_DelVar)(mod_api_t *self, const char *id);
    void (*CORE_Execute)(mod_api_t *self, const char *string);
    void (*CORE_AddCommand)(mod_api_t *self, const char *id, void (*cmd)(void));
    unsigned char (*CORE_DelCommand)(mod_api_t *self, const char *id);
    void *(*CORE_GetExtension)(mod_api_t *self, const char *ext);
    void (*GFX_Clear)(mod_api_t *self, float r, float g, float b, float a);
    int (*GFX_GetStringWidth)(mod_api_t *self, const char *string);
    void (*GFX_Printf)(mod_api_t *self, float x, float y, const char *fmt, ...);
    int (*GFX_LoadTexture)(mod_api_t *self, const char *filename);
    unsigned char (*GFX_FreeTexture)(mod_api_t *self, int texId);
    void (*GFX_SetTexture)(mod_api_t *self, int texId);
    void (*GFX_SetTextureFilter)(mod_api_t *self, int filter);
    void (*GFX_SetBlendMode)(mod_api_t *self, int src, int dst);
    void (*GFX_SetColor)(mod_api_t *self, float r, float g, float b, float a);
    void (*GFX_SetSubset)(mod_api_t *self, float x1, float y1, float x2, float y2);
    void (*GFX_Begin)(mod_api_t *self);
    void (*GFX_End)(mod_api_t *self);
    void (*GFX_Quad)(mod_api_t *self, float x, float y, float w, float h);
    void (*GFX_QuadRot)(mod_api_t *self, float x, float y, float w, float h, float a);
    void (*GFX_DrawQuads)(mod_api_t *self, mod_vertex2_t *v, int numQuads);
    int (*SFX_LoadSample)(mod_api_t *self, const char *filename);
    unsigned char (*SFX_FreeSample)(mod_api_t *self, int sfxId);
    void (*SFX_PlaySample)(mod_api_t *self, int sfxId, float pan, float volume);
    int (*SFX_LoadTune)(mod_api_t *self, const char *filename);
    unsigned char (*SFX_FreeTune)(mod_api_t *self, int tuneId);
    void (*SFX_PlayTune)(mod_api_t *self, int tuneId);
    void (*SFX_StopTune)(mod_api_t *self, int tuneId);
    unsigned char (*INP_KeyDown)(mod_api_t *self, int key);
    float (*INP_GetAnalog)(mod_api_t *self, int key);
    char (*INP_GetPressedChar)(mod_api_t *self);
    char *(*INP_GetKeyName)(mod_api_t *self, int key);
    void (*CL_EnterMenu)(mod_api_t *self, const char *menu);
};

struct mod_interface_vtbl_t {
    unsigned char (*Init)(mod_interface_t *self);
    void (*Shutdown)(mod_interface_t *self);
    unsigned char (*Frame)(mod_interface_t *self, int frame_dt_ms);
};

typedef union mod_parms_t {
    int reserved[256];
    struct {
        unsigned char drawMouseCursor;
        unsigned char onPause;
        unsigned char reserved0[0x1a];
        unsigned char request_exit;
        unsigned char reserved1[0x3e3];
    } fields;
} mod_parms_t;

struct mod_interface_t {
    mod_interface_vtbl_t *vtable;
    mod_api_t *cl;
    mod_parms_t parms;
};

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
