#include "crimsonland_gameplay.h"

extern effect_vec2_t effect_template_position;
extern int effect_defaults_reserved_zero;
extern effect_entry_t effect_pool_pos_x[512];
extern int effect_pool_reserved_zero;

void effect_defaults_reset(void)
{
    {
        effect_color_t white = {1.0f, 1.0f, 1.0f, 1.0f};
        effect_template.color = white;
    }
    effect_template.flags = 1;
    effect_template.rotation = 0.0f;
    effect_template.scale = 1.0f;
    effect_template.age = 0.0f;
    effect_template.lifetime = 0.5f;
    effect_template.half_height = 32.0f;
    effect_template.half_width = 32.0f;
    {
        effect_vec2_t zero = {0.0f, 0.0f};
        effect_template_position = zero;
    }
    effect_template.rotation_step = 1.0f;
    effect_template.scale_step = 1.0f;
    {
        vec2f_t zero = {0.0f, 0.0f};
        effect_template.velocity = zero;
    }
    effect_defaults_reserved_zero = 0;

    effect_pool_pos_x[0].next_free = &effect_pool_pos_x[1];
    effect_init_entry(&effect_pool_pos_x[0]);
    {
        int index;
        for (index = 1; index < 511; ++index) {
            effect_pool_pos_x[index].next_free = &effect_pool_pos_x[index + 1];
            effect_init_entry(&effect_pool_pos_x[index]);
        }
    }
    effect_pool_pos_x[510].next_free = &effect_pool_pos_x[511];
    effect_init_entry(&effect_pool_pos_x[510]);
    effect_free_list_head = &effect_pool_pos_x[0];
    effect_pool_reserved_zero = 0;
}
