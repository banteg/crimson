#include "crimsonland_gameplay.h"

struct FILE;

extern "C" char *game_build_path(char *filename);
extern "C" FILE *crt_fopen(char *path, char *mode);
extern "C" int crt_fclose(FILE *fp);
extern "C" unsigned int crt_fwrite(
    void *ptr, unsigned int size, unsigned int count, FILE *fp);

extern "C" void config_ensure_file(void)
{
    FILE *fp = crt_fopen(game_build_path("crimson.cfg"), "rb");
    if (fp != 0) {
        crt_fclose(fp);
        return;
    }

    config_violence_disabled = 1;
    fp = crt_fopen(game_build_path("crimson.cfg"), "wb");
    if (fp != 0) {
        crt_fwrite(&config_blob, 0x480, 1, fp);
        crt_fclose(fp);
    }
}
