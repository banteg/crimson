#include "freeware_level.h"

void freeware_level_map::add_trigger(freeware_level_trigger *trigger) {
    triggers.push_back(trigger);
}
