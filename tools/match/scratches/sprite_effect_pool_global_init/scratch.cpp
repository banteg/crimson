struct sprite_color_t {
    float r;
    float g;
    float b;
    float a;

    sprite_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

struct sprite_effect_native_t {
    unsigned char active;
    unsigned char padding[3];
    sprite_color_t color;
    float rotation;
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    float scale;
};

extern "C" sprite_effect_native_t sprite_effect_pool[0x180];

extern "C" void sprite_effect_pool_global_init(void)
{
    int remaining = 0x180;
    sprite_effect_native_t *entry = sprite_effect_pool;

    do {
        entry->active = 0;
        entry->color = sprite_color_t(1.0f, 1.0f, 1.0f, 1.0f);
        ++entry;
    } while (--remaining != 0);
}
