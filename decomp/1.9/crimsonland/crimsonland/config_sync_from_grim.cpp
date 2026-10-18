#include <string.h>

#include "crimson_config_defaults_impl.h"
#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct FILE;

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" int player_name_length;
extern "C" unsigned char grim_config_invoked;

extern "C" char *game_build_path(char *filename);
extern "C" FILE *crt_fopen(char *path, char *mode);
extern "C" int crt_fseek(FILE *fp, long offset, int origin);
extern "C" long crt_ftell(FILE *fp);
extern "C" unsigned int crt_fread(
    void *ptr, unsigned int size, unsigned int count, FILE *fp);
extern "C" unsigned int crt_fwrite(
    void *ptr, unsigned int size, unsigned int count, FILE *fp);
extern "C" int crt_fclose(FILE *fp);

extern "C" bool config_sync_from_grim(void)
{
    crimson_cfg_t defaults;
    FILE *fp;

    config_blob.windowed = grim_interface_ptr->grim_get_config_var(8);
    config_blob.display_bpp =
        grim_interface_ptr->grim_get_config_var(0x2b).words[0];
    config_blob.screen_width =
        grim_interface_ptr->grim_get_config_var(0x29).words[0];
    config_blob.screen_height =
        grim_interface_ptr->grim_get_config_var(0x2a).words[0];
    *(unsigned int *)&config_blob.texture_scale =
        grim_interface_ptr->grim_get_config_var(0x59).words[0];
    config_blob.safe_mode_backend_enabled =
        grim_interface_ptr->grim_get_config_var(0x54);

    strcpy(config_blob.player_name, highscore_active_record.player_name);
    config_blob.player_name_length = player_name_length;

    if (grim_config_invoked) {
        ((crimson_cfg_cpp_t *)&defaults)->set_defaults();

        fp = crt_fopen(game_build_path("crimson.cfg"), "rb");
        if (fp != 0) {
            crt_fseek(fp, 0, 2);
            if (crt_ftell(fp) == sizeof(defaults)) {
                crt_fseek(fp, 0, 0);
                crt_fread(&defaults, sizeof(defaults), 1, fp);
                config_blob.violence_disabled = defaults.violence_disabled;
                strcpy(config_blob.player_name_buf, defaults.player_name_buf);
            }
            crt_fclose(fp);
        }
    }

    fp = crt_fopen(game_build_path("crimson.cfg"), "wb");
    if (fp != 0) {
        crt_fwrite(&config_blob, sizeof(config_blob), 1, fp);
        crt_fclose(fp);
    }
    return true;
}
