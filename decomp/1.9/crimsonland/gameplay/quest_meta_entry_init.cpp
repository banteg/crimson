#include "crimsonland_metadata.h"

quest_meta_cpp_t::quest_meta_cpp_t(void)
{
    builder = 0;
    start_weapon_id = 1;
    name = 0;
    unlock_weapon_id = 0;
    unlock_perk_id = 0;
    terrain_id = 0;
    terrain_id_b = 1;
    terrain_id_c = 2;
    time_limit_ms = 120000;
}
