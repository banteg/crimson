#include "freeware_level.h"
#include <vector>

extern "C" {
std::vector<freeware_level_object *> freeware_brushes;

void freeware_brush_clear()
{
    while (freeware_brushes.size() > 0) {
        freeware_level_object *brush = freeware_brushes.front();
        freeware_brushes.erase(freeware_brushes.begin());
        delete brush;
    }
}
}
