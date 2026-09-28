#include "crimsonland_gameplay.h"

extern "C" char *bonus_label_for_entry(bonus_entry_t *bonus_entry)
{
    bonus_id_t bonus_id = bonus_entry->bonus_id;
    if (bonus_id == BONUS_ID_WEAPON) {
        char *weapon_label = weapon_table_entry(bonus_entry->time.amount);
        crt_sprintf(bonus_label_format_buffer, "%s", weapon_label);
        return bonus_label_format_buffer;
    } else if (bonus_id == BONUS_ID_POINTS) {
        crt_sprintf(bonus_label_format_buffer, "%s: %d", bonus_label_points, bonus_entry->time.amount);
        return bonus_label_format_buffer;
    } else {
        return bonus_meta_table[bonus_id].label;
    }
}
