#include "freeware_level.h"
#include <stdio.h>
#include <string.h>

namespace {
struct level_point {
    float x, y;
    level_point(float x, float y) : x(x), y(y) {}
    operator vec2f_t() const {
        vec2f_t point = {x, y};
        return point;
    }
};

struct loaded_trigger : freeware_level_trigger {
    loaded_trigger() {
        type = 0;
        position = level_point(0, 0);
        heading = 0;
        velocity = level_point(0, 0);
        radius = 128;
    }
};

struct loaded_object : freeware_level_object {
    loaded_object() {
        flags = 0;
        width = height = 128;
        rotation = 0;
        color.r = color.g = color.b = color.a = 1;
        texture = -1;
    }
};
} // namespace

bool freeware_level_map::load(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file)
        return false;

    clear();
    char header[28];
    fread(header, sizeof(header), 1, file);
    header[sizeof(header) - 1] = 0;
    if (strcmp(header, "Crimsonland level v.0.0.2b")) {
        fclose(file);
        return false;
    }

    fread(&start, sizeof(start), 1, file);
    fread(&start_heading, sizeof(start_heading), 1, file);
    fread(&flag, sizeof(flag), 1, file);
    int trigger_count, counts[3];
    fread(&trigger_count, sizeof(trigger_count), 1, file);
    int layer;
    for (layer = 0; layer < 3; ++layer)
        fread(&counts[layer], sizeof(counts[layer]), 1, file);

    freeware_level_trigger *trigger;
    for (int i = 0; i < trigger_count; ++i) {
        freeware_level_trigger *&record = trigger;
        record = new loaded_trigger;
        fread(record, sizeof(*record), 1, file);
        triggers.push_back(trigger);
    }
    for (layer = 0; layer < 3; ++layer) {
        for (int j = 0; j < counts[layer]; ++j) {
            freeware_level_object *object = new loaded_object;
            fread(object, sizeof(*object), 1, file);
            vec2f_t &position = object->position;
            position.x = (float)(int)position.x;
            position.y = (float)(int)position.y;
            layers[layer].push_back(object);
        }
    }
    fclose(file);
    return true;
}
