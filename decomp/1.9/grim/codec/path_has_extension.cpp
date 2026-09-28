#include <string.h>

extern "C" bool grim_path_has_extension(char *path, char *extension)
{
    int path_offset = strlen(path);
    int extension_offset = strlen(extension);
    path_offset -= 3;
    extension_offset -= 3;

    if (path_offset >= 0 && extension_offset >= 0 &&
        path[path_offset++] == extension[extension_offset++] &&
        path[path_offset] == extension[extension_offset]) {
        bool result = path[path_offset + 1] == extension[extension_offset + 1];
        return result;
    }
    return false;
}
