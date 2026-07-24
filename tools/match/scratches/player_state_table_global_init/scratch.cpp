struct player_vec2_t {
    float x;
    float y;

    player_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct player_state_native_t {
    unsigned char active;
    unsigned char padding00[3];
    int phase_seed;
    unsigned char state_flag;
    unsigned char collision_flag;
    unsigned char padding0a[2];
    float collision_timer;
    unsigned char padding10[0x28];
    float hit_flash_timer;
    unsigned char padding3c[0x38];
    int entity_reserved_74;
    int link_index;
    unsigned char padding7c[0x14];
    int ai_mode;
    float anim_phase;
    float player_reserved_98;
    float hot_tempered_timer;
    float man_bomb_timer;
    float living_fortress_timer;
    float fire_cough_timer;
    int experience;
    int reset_reserved_b0;
    int level;
    unsigned char padding_b8[0x20c];
    float clip_size;
    unsigned char reload_active;
    unsigned char padding2c9[3];
    float ammo;
    float reload_timer;
    float shot_cooldown;
    float reload_timer_max;
    int alt_weapon_id;
    float alt_clip_size;
    unsigned char alt_reload_active;
    unsigned char padding2e5[3];
    float alt_ammo;
    float alt_reload_timer;
    float alt_shot_cooldown;
    float alt_reload_timer_max;
    int reset_reserved_zero;
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
    player_vec2_t move_target;
    unsigned char input[0x34];

    void construct_entity(void)
    {
        entity_reserved_74 = 0;
        phase_seed = 0;
        hit_flash_timer = 0.0f;
        active = 0;
        ai_mode = 0;
        state_flag = 0;
        anim_phase = 0.0f;
        collision_flag = 0;
        collision_timer = 0.0f;
        link_index = -1;
    }
};

extern "C" player_state_native_t player_state_table[2];

extern "C" void player_state_table_global_init(void)
{
    int remaining = 2;
    player_state_native_t *entry = player_state_table;

    do {
        entry->construct_entity();

        entry->fire_bullets_timer = 0.0f;
        entry->low_health_timer = 0.0f;
        entry->man_bomb_timer = 0.0f;
        entry->living_fortress_timer = 0.0f;
        entry->fire_cough_timer = 0.0f;
        entry->move_target = player_vec2_t(-1.0f, -1.0f);
        entry->evil_eyes_target_creature = -1;
        entry->auto_target = 0;
        entry->player_reserved_98 = 0.0f;
        entry->hot_tempered_timer = 0.0f;
        entry->reload_active = 0;
        entry->shield_timer = 0.0f;
        entry->turn_speed = 0.0f;
        entry->experience = 0;
        entry->level = 1;
        entry->shot_cooldown = 0.0f;
        entry->reset_reserved_zero = 0;
        entry->clip_size = 30.0f;
        entry->muzzle_flash_alpha = 0.0f;
        ++entry;
    } while (--remaining != 0);
}
