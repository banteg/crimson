#include "freeware_level.h"

void freeware_level_map::add_object(int layer, freeware_level_object *object) {
    layers[layer].push_back(object);
}
