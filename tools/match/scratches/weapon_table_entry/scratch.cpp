#include "crimsonland_gameplay.h"

extern "C" char *weapon_table_entry(int weapon_id)
{
    return weapon_table[weapon_id].name;
}
