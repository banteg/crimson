#include "crimsonland_gameplay.h"

extern "C" char *weapon_name_get(int weapon_id)
{
    return weapon_table[weapon_id].name;
}
