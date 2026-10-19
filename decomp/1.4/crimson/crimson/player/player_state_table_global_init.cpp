typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"

struct player_vec2_t {
    float x;
    float y;

    player_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

#if CL_BUILD < 10300
struct player_state_native_t {
    unsigned char entity_active;
    unsigned char entity_ai_mode;
    unsigned char _pad0[2];
    float entity_hit_flash_timer;
    unsigned char _pad1[0x5c];
    int entity_reserved_74;
    int experience;
    int level;
    float shot_cooldown;
    unsigned char _pad2[0x84];
    int auto_target;
    int reload_active;
    int reset_reserved_zero;
    float clip_size;
    float muzzle_flash_alpha;

    void construct_entity(void)
    {
        entity_active = 0;
        entity_reserved_74 = 0;
        entity_ai_mode = 0;
        entity_hit_flash_timer = 0.0f;
    }
};
#elif CL_BUILD == 10300
struct player_state_native_t {
    unsigned char entity_active;
    unsigned char entity_ai_mode;
    unsigned char _pad0[6];
    float entity_hit_flash_timer;
    unsigned char entity_state_flag;
    unsigned char _pad1[3];
    float move_phase;
    unsigned char _pad2[0x68];
    int entity_reserved_74;
    int experience;
    unsigned char _pad3[4];
    int level;
    float shot_cooldown;
    unsigned char _pad4[0x8c];
    int reload_active;
    int reset_reserved_zero;
    float clip_size;
    float muzzle_flash_alpha;
    unsigned char _pad5[4];
    float hot_tempered_timer;
    unsigned char _pad6[4];
    float fire_bullets_timer;
    unsigned char _pad7[0x0c];

    void construct_entity(void)
    {
        entity_active = 0;
        entity_ai_mode = 0;
        entity_reserved_74 = 0;
        entity_state_flag = 0;
        move_phase = 0.0f;
        entity_hit_flash_timer = -1.0f;
    }
};
#else
struct player_state_native_t {
    unsigned char entity_active;
    unsigned char entity_ai_mode;
    unsigned char _pad0[6];
    float entity_hit_flash_timer;
    unsigned char entity_state_flag;
    unsigned char _pad1[3];
    float move_phase;
    unsigned char _pad2[0x68];
    int entity_reserved_74;
    int experience;
    unsigned char _pad3[4];
    int level;
    float shot_cooldown;
    unsigned char _pad4[0xcc];
    int reload_active;
    int reset_reserved_zero;
    float clip_size;
    float muzzle_flash_alpha;
    unsigned char _pad5[4];
    float hot_tempered_timer;
    unsigned char _pad6[4];
    float fire_bullets_timer;
    unsigned char _pad7[0x0c];

    void construct_entity(void)
    {
        entity_active = 0;
        entity_ai_mode = 0;
        entity_reserved_74 = 0;
        entity_state_flag = 0;
        move_phase = 0.0f;
        entity_hit_flash_timer = -1.0f;
    }
};
#endif

extern "C" player_state_native_t player_state_table[2];

extern "C" void player_state_table_global_init(void)
{
    int remaining = 2;
    player_state_native_t *entry = player_state_table;

    do {
        entry->construct_entity();

#if CL_BUILD < 10300
        entry->experience = 0;
        entry->level = 1;
        entry->shot_cooldown = 0.0f;
        entry->auto_target = 1;
        entry->reload_active = 2;
        entry->reset_reserved_zero = 0;
        entry->clip_size = 30.0f;
        entry->muzzle_flash_alpha = 0.0f;
#else
        entry->fire_bullets_timer = 0.0f;
        entry->hot_tempered_timer = 0.0f;
        entry->experience = 0;
        entry->level = 1;
        entry->shot_cooldown = 0.0f;
        entry->reload_active = 2;
        entry->reset_reserved_zero = 0;
        entry->clip_size = 30.0f;
        entry->muzzle_flash_alpha = 0.0f;
#endif
        ++entry;
    } while (--remaining != 0);
}
