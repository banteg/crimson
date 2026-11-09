#include "freeware_level.h"
#include <stdio.h>

bool freeware_level_map::save(const char *path) {
    FILE *file = fopen(path, "wb");
    if (!file)
        return false;

    const char *signature = "Crimsonland level v.0.0.2b\0";
    fwrite(signature, 28, 1, file);
    fwrite(&start, sizeof(start), 1, file);
    fwrite(&start_heading, sizeof(start_heading), 1, file);
    fwrite(&flag, sizeof(flag), 1, file);
    int count = triggers.size();
    fwrite(&count, sizeof(count), 1, file);
    int layer;
    for (layer = 0; layer < 3; ++layer) {
        count = layers[layer].size();
        fwrite(&count, sizeof(count), 1, file);
    }
    for (unsigned i = 0; i < (unsigned)triggers.size(); ++i)
        fwrite(triggers[i], sizeof(freeware_level_trigger), 1, file);
    for (layer = 0; layer < 3; ++layer) {
        for (unsigned i = 0; i < (unsigned)layers[layer].size(); ++i)
            fwrite(layers[layer][i], sizeof(freeware_level_object), 1, file);
    }
    fclose(file);
    return true;
}
