#include <string.h>

class weapon_native_entry_cpp_t {
public:
    weapon_native_entry_cpp_t(void)
    {
        hud_icon_id = 0;
        damage_scale = 1.0f;
        travel_budget = 45.0f;
        flags = 0;
        shot_sfx_variant_count = 1;
        strcpy(name, "Unknown");
        ammo_class = 0;
        unlocked = 0;
        clip_size = 0;
        shot_cooldown = 1.0f;
        reload_time = 1.0f;
        spread_heat = 0.0f;
    }

    int ammo_class;
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
    int flags;
    float travel_budget;
    float damage_scale;
    int pellet_count;
};

weapon_native_entry_cpp_t weapon_ammo_class[0x40];
