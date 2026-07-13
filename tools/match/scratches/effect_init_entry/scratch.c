#include "crimsonland_gameplay.h"

void effect_init_entry(effect_entry_t *entry)
{
    entry->flags = 0;
    entry->age = 0.0f;
    entry->rotation = 0.0f;
    entry->scale = 1.0f;
    {
        effect_color_t white = {1.0f, 1.0f, 1.0f, 1.0f};
        entry->color = white;
    }
    {
        effect_vec2_t zrhw = {0.5f, 1.0f};
        int i;
        for (i = 0; i < 4; ++i) {
            entry->vertices[i].color = 0xffffffff;
            entry->vertices[i].zrhw = zrhw;
        }
    }
}
