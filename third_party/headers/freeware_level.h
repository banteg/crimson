#ifndef FREEWARE_LEVEL_H
#define FREEWARE_LEVEL_H
#include "crimsonland_types.h"

struct freeware_level_object {
    vec2f_t position;
    float rotation, width, height;
    int texture;
    unsigned char flags, reserved[7];
    effect_color_t color;
};
struct freeware_level_trigger {
    int type;
    unsigned char enabled, padding[3];
    vec2f_t position;
    float heading;
    vec2f_t velocity;
    float radius;
    int weapon, reserved;
};
template <class T> struct freeware_level_list {
    int allocator;
    T **begin, **end, **capacity;
    int size() const { return begin ? (int)(end - begin) : 0; }
};
struct freeware_level_map {
    vec2f_t start;
    float start_heading;
    unsigned char flag, reserved[3];
    int texture;
    freeware_level_list<freeware_level_object> layers[3];
    freeware_level_list<freeware_level_trigger> triggers;
    int move_with_collision(vec2f_t *pos, const vec2f_t *delta, float radius);
    void clear();
    void add_object(int layer, freeware_level_object *object);
    void add_trigger(freeware_level_trigger *trigger);
    bool save(const char *path);
    bool load(const char *path);
    void update_triggers();
    void arm_triggers();
    void render_layer(int layer, int preview);
    void render_triggers(unsigned char game);
};
extern "C" freeware_level_map *freeware_current_map;
#endif
