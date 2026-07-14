#include "crimsonland_gameplay.h"

extern "C" char game_base_path[];
extern "C" char game_path_buf[];

extern "C" char *game_build_path(char *filename)
{
    crt_sprintf(game_path_buf, "%s\\%s", game_base_path, filename);
    return game_path_buf;
}
