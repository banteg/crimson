#include "freeware_level.h"

void freeware_level_map::clear() {
    flag = 0;
    for (int i = 0; i < 3; ++i) {
        std::vector<freeware_level_object *> &layer = layers[i];
        while (layers[i].size() > 0) {
            std::vector<freeware_level_object *>::iterator first = layer.begin();
            freeware_level_object *object = *first;
            layers[i].erase(first);
            delete object;
        }
    }
    while (triggers.size() > 0) {
        freeware_level_trigger *trigger = triggers.front();
        triggers.erase(triggers.begin());
        delete trigger;
    }
}
