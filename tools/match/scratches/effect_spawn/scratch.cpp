struct vec2f_t {
    float x;
    float y;

    vec2f_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    vec2f_t operator+(const vec2f_t &other) const
    {
        return vec2f_t(x + other.x, y + other.y);
    }
};

struct effect_color_t {
    float r;
    float g;
    float b;
    float a;
};

struct effect_id_entry_t {
    int size_code;
    int frame;
};

struct effect_vertex_t {
    vec2f_t pos;
    vec2f_t zrhw;
    unsigned int color;
    vec2f_t tex;
};

struct effect_entry_t {
    float pos_x;
    float pos_y;
    unsigned char effect_id;
    unsigned char pad[3];
    float vel_x;
    float vel_y;
    float rotation;
    float scale;
    float half_width;
    float half_height;
    float age;
    float lifetime;
    int flags;
    effect_color_t color;
    float rotation_step;
    float scale_step;
    effect_vertex_t vertices[4];
    effect_entry_t *next_free;
};

struct effect_template_t {
    float vel_x;
    float vel_y;
    float rotation;
    float scale;
    float half_width;
    float half_height;
    float age;
    float lifetime;
    int flags;
    effect_color_t color;
    float rotation_step;
    float scale_step;
};

extern "C" {
extern int effect_spawn_detail_skip_counter;
extern int config_detail_preset;
extern effect_entry_t effect_discard_entry;
extern effect_entry_t *effect_free_list_head;
extern effect_id_entry_t effect_id_table[];
extern effect_template_t effect_template;
extern vec2f_t effect_uv2[];
extern vec2f_t effect_uv4[];
extern vec2f_t effect_uv8[];
extern vec2f_t effect_uv16[];
extern float effect_uv_step_2;
extern float effect_uv_step_4;
extern float effect_uv_step_8;
extern float effect_uv_step_16;
}

#define EFFECT_BUILD_QUAD(uv_table, uv_step)                                \
    do {                                                                    \
        entry->vertices[0].tex = (uv_table)[frame];                         \
        entry->vertices[0].pos = vec2f_t(                                  \
            -effect_template.half_width, -effect_template.half_height);     \
        entry->vertices[1].tex = (uv_table)[frame]                          \
                + vec2f_t((uv_step), 0.0f);                                \
        entry->vertices[1].pos = vec2f_t(                                  \
            effect_template.half_width, -effect_template.half_height);      \
        entry->vertices[2].tex = (uv_table)[frame]                          \
                + vec2f_t((uv_step), (uv_step));                           \
        entry->vertices[2].pos = vec2f_t(                                  \
            effect_template.half_width, effect_template.half_height);       \
        entry->vertices[3].tex = (uv_table)[frame]                          \
                + vec2f_t(0.0f, (uv_step));                                \
        entry->vertices[3].pos = vec2f_t(                                  \
            -effect_template.half_width, effect_template.half_height);      \
    } while (0)

extern "C" effect_entry_t *effect_spawn(
    int effect_id,
    const vec2f_t *pos)
{
    if (config_detail_preset <= 2) {
        if ((effect_spawn_detail_skip_counter++ & 1) != 0) {
            return &effect_discard_entry;
        }
    }

    effect_entry_t *entry = effect_free_list_head;
    int size_code = effect_id_table[effect_id].size_code;
    int frame = effect_id_table[effect_id].frame;
    if (entry->next_free != 0) {
        effect_free_list_head = entry->next_free;
    } else {
        entry = &effect_discard_entry;
    }

    *(effect_template_t *)&entry->vel_x = effect_template;
    entry->pos_x = pos->x;
    entry->pos_y = pos->y;
    entry->effect_id = (unsigned char)effect_id;

    if (size_code == 0x10) {
        EFFECT_BUILD_QUAD(effect_uv16, effect_uv_step_16);
    } else if (size_code == 0x20) {
        EFFECT_BUILD_QUAD(effect_uv8, effect_uv_step_8);
    } else if (size_code == 0x40) {
        EFFECT_BUILD_QUAD(effect_uv4, effect_uv_step_4);
    } else if (size_code == 0x80) {
        EFFECT_BUILD_QUAD(effect_uv2, effect_uv_step_2);
    }
    return entry;
}
