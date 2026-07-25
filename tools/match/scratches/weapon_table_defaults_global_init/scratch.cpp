#include <string.h>

#include "crimsonland_gameplay.h"

class weapon_storage_entry_cpp_t : public weapon_storage_entry_t {
public:
    weapon_storage_entry_cpp_t(void)
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

};

weapon_storage_entry_cpp_t weapon_ammo_class[0x40];
