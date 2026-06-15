#include "crimsonland_gameplay.h"

int perk_count_get(int perk_id)
{
    return player_state_table[0].perk_counts[perk_id];
}
