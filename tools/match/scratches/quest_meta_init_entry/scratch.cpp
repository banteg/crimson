#include "crimsonland_gameplay.h"

extern "C" void quest_meta_init_entry(
    quest_meta_t *meta,
    int tier,
    int index,
    char *name)
{
    if (meta->name != 0) {
        crt_free(meta->name);
        console_printf(&console_log_queue, "Quest overwritten!\n");
    }

    meta->name = strdup_malloc(name);
    meta->unlock_perk_id = perk_id_antiperk;
    meta->unlock_weapon_id = 0;
    meta->tier = tier;
    meta->index = index;
    meta->terrain_id = tier * 2 - 2;

    if (index > 5) {
        meta->terrain_id_b = tier * 2 - 2;
        meta->terrain_id_c = tier * 2 - 1;
    } else {
        meta->terrain_id_b = tier * 2 - 1;
        meta->terrain_id_c = tier * 2 - 2;
    }

    if (tier >= 5) {
        meta->terrain_id = index % 4;
        meta->terrain_id_b = 1;
        meta->terrain_id_c = 3;
        meta->builder = (quest_builder_fn_t)5;
    }

    quest_meta_cursor = meta;
}
