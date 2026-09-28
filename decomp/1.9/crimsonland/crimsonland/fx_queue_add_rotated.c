#include "crimsonland_gameplay.h"

unsigned char fx_queue_add_rotated(
    vec2f_t *pos,
    effect_color_t *color,
    float rotation,
    float scale,
    int effect_id)
{
    cvar_float_t *transparency;

    if (terrain_texture_failed == 0) {
        if (fx_queue_rotated == 0x3f) {
            return 0;
        }

        fx_rotated_color_r[fx_queue_rotated] = *color;
        transparency = cv_terrainBodiesTransparency;
        if (transparency->value == 0.0f) {
            fx_rotated_color_r[fx_queue_rotated].a *= 0.8f;
        } else {
            fx_rotated_color_r[fx_queue_rotated].a *= 1.0f / transparency->value;
        }
        fx_rotated_rotation[fx_queue_rotated] = rotation;
        fx_rotated_effect_id[fx_queue_rotated] = effect_id;
        fx_rotated_scale[fx_queue_rotated] = scale;
        fx_rotated_pos_x[fx_queue_rotated] = *pos;

        ++fx_queue_rotated;
        if (fx_queue_rotated >= 0x40) {
            fx_queue_rotated = 0x3f;
        }
    }
    return 1;
}
