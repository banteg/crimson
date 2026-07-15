struct fx_vec2_t {
    float x;
    float y;

    fx_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct fx_color_t {
    float r;
    float g;
    float b;
    float a;

    fx_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

struct fx_queue_native_entry_t {
    int effect_id;
    float rotation;
    fx_vec2_t position;
    float height;
    float width;
    fx_color_t color;
};

extern "C" fx_queue_native_entry_t fx_queue[128];

extern "C" void fx_queue_global_init(void)
{
    int remaining = 128;
    fx_queue_native_entry_t *entry = fx_queue;

    do {
        entry->effect_id = 0;
        entry->rotation = 0.0f;
        entry->position = fx_vec2_t(0.0f, 0.0f);
        entry->height = 0.0f;
        entry->width = 0.0f;
        entry->color = fx_color_t(1.0f, 1.0f, 1.0f, 1.0f);
        ++entry;
    } while (--remaining != 0);
}
