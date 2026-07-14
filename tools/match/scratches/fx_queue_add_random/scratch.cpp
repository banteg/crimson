#include "crimsonland_gameplay.h"

struct FxRandomColor {
    float r;
    float g;
    float b;
    float a;

    FxRandomColor(float red, float green, float blue, float alpha)
        : r(red), g(green), b(blue), a(alpha)
    {
    }

    ~FxRandomColor() {}
};

struct FxRandomVec2 {
    float x;
    float y;

    FxRandomVec2(float x_value, float y_value) : x(x_value), y(y_value) {}

    FxRandomVec2 *vec2_sub(
        FxRandomVec2 *dst,
        const FxRandomVec2 *rhs) const
    {
        float result_y = y - rhs->y;
        dst->x = x - rhs->x;
        dst->y = result_y;
        return dst;
    }
};

extern "C" void fx_queue_add_random(vec2f_t *pos)
{
    if (config_violence_disabled != 0) {
        return;
    }

    static FxRandomColor color(0.9f, 0.9f, 0.9f, 0.78f);

    float gray = (float)(crt_rand() & 0xf) * 0.01f + 0.84f;
    color.r = color.g = color.b = gray;

    float width = (float)(crt_rand() % 24 - 12) + 30.0f;
    float rotation = (float)(crt_rand() % 628) * 0.01f;
    FxRandomVec2 top_left(width * 0.5f, width * 0.5f);
    ((FxRandomVec2 *)pos)->vec2_sub(&top_left, &top_left);
    fx_queue_add(
        crt_rand() % 5 + 3,
        (vec2f_t *)&top_left,
        width,
        width,
        rotation,
        (effect_color_t *)&color
    );
}
