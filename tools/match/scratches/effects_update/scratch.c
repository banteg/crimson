#include "crimsonland_gameplay.h"

void effects_update(void)
{
    int index;

    for (index = 0; index < 512; ++index) {
        effect_entry_t *entry = &effect_pool[index];
        int flags = entry->flags;

        if (flags != 0) {
            entry->age += frame_dt;

            if (entry->age >= entry->lifetime) {
                if ((flags & 0x80) != 0) {
                    if ((flags & 0x100) != 0) {
                        entry->color.a = 0.35f;
                    } else {
                        entry->color.a = 0.8f;
                    }
                    fx_queue_add(
                        entry->effect_id,
                        &entry->position,
                        entry->half_width + entry->half_width,
                        entry->half_height + entry->half_height,
                        entry->rotation,
                        &entry->color
                    );
                }
                effect_free(entry);
            } else if (entry->age >= 0.0f) {
                float dt = frame_dt;
                effect_vec2_t movement = {
                    dt * entry->velocity.x,
                    dt * entry->velocity.y,
                };
                entry->position.x += movement.x;
                entry->position.y += movement.y;
                if ((flags & 4) != 0) {
                    entry->rotation += frame_dt * entry->rotation_step;
                }
                if ((flags & 8) != 0) {
                    entry->scale += frame_dt * entry->scale_step;
                }
                if ((flags & 0x10) != 0) {
                    entry->color.a = 1.0f - entry->age / entry->lifetime;
                }
            }
        }
    }
}
