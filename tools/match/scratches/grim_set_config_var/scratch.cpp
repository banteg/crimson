#include <string.h>

#include "grim2d_cpp.h"
#include "grim_d3d8.h"

enum { D3DSGR_NO_CALIBRATION = 1 };

extern grim_config_value_t grim_config_values[128];

extern IDirect3DDevice8 *grim_d3d_device;
extern void (*grim_on_device_lost)(void);
extern void (*grim_on_device_restore)(void);
extern void (*grim_frame_callback)(void);
extern char *grim_window_title;
extern char grim_empty_string;
extern unsigned char grim_lookup_blob_loaded;
extern int grim_backbuffer_width;
extern int grim_backbuffer_height;
extern int grim_texture_format;
extern unsigned char grim_input_cached;
extern bool grim_mouse_enabled;
extern HWND grim_device_window_override;
extern unsigned char grim_render_disabled;

bool grim_lookup_blob_load(char *path);
unsigned char grim_set_texture_stage_ops(unsigned int mode);

void IGrim2D_cpp::grim_set_config_var(
    unsigned int id, grim_config_value_t value)
{
    switch (id) {
    case 26:
        if (!grim_set_texture_stage_ops(value.words[0])) {
            return;
        }
        break;

    case 27: {
        grim_config_values[id] = value;
        unsigned char color[4];
        color[3] = 0;
        color[2] =
            (unsigned char)(*(float *)&value.words[0] * 127.0f + 128.0f);
        color[1] =
            (unsigned char)(*(float *)&value.words[1] * 127.0f + 128.0f);
        color[0] =
            (unsigned char)(*(float *)&value.words[2] * 127.0f + 128.0f);
        grim_d3d_device->SetRenderState(
            D3DRS_TEXTUREFACTOR, *(unsigned int *)color);
        return;
    }

    case 28: {
        D3DGAMMARAMP ramp;
        float gamma = *(float *)&value.words[0];
        for (int i = 0; i < 256; ++i) {
            int level = (int)((float)i * gamma * 257.0f);
            if (level > 65535) {
                level = 65535;
            } else if (level < 0) {
                level = 0;
            }
            ramp.red[i] = (unsigned short)level;
            ramp.green[i] = (unsigned short)level;
            ramp.blue[i] = (unsigned short)level;
        }
        grim_d3d_device->SetGammaRamp(
            D3DSGR_NO_CALIBRATION, &ramp);
        grim_config_values[id] = value;
        return;
    }

    case 41:
        grim_backbuffer_width = value.words[0];
        grim_config_values[id].words[0] = value.words[0];
        return;

    case 42:
        grim_backbuffer_height = value.words[0];
        grim_config_values[id].words[0] = value.words[0];
        return;

    case 43:
        grim_config_values[id].words[0] = value.words[0];
        grim_texture_format = value.words[0] == 32 ? 22 : 23;
        return;

    case 7: {
        if (grim_window_title != 0) {
            delete grim_window_title;
        }
        char *title = (char *)value.words[3];
        grim_window_title = new char[strlen(title) + 1];
        strcpy(grim_window_title, title);
        grim_config_values[id].words[3] =
            (unsigned int)grim_window_title;
        return;
    }

    case 45:
        grim_frame_callback = (void (*)(void))value.words[3];
        return;

    case 6:
        grim_on_device_restore = (void (*)(void))value.words[3];
        return;

    case 5:
        grim_on_device_lost = (void (*)(void))value.words[3];
        return;

    case 16: {
        char *path = (char *)value.words[3];
        if (strcmp(path, &grim_empty_string) == 0) {
            char *stored =
                (char *)grim_config_values[id].words[3];
            if (stored != 0) {
                delete stored;
            }
            grim_config_values[id].words[3] =
                (unsigned int)strdup(&grim_empty_string);
            grim_lookup_blob_loaded = 0;
        }

        grim_lookup_blob_loaded = grim_lookup_blob_load(path);

        char *stored = (char *)grim_config_values[id].words[3];
        if (stored != 0) {
            delete stored;
        }
        grim_config_values[id].words[3] = (unsigned int)strdup(path);
        *(unsigned char *)grim_config_values[id].words =
            grim_lookup_blob_loaded;
        return;
    }

    case 18: {
        unsigned int enabled = value.words[0];
        if (*(unsigned char *)grim_config_values[id].words ==
            (unsigned char)enabled) {
            return;
        }
        grim_d3d_device->SetRenderState(
            D3DRS_ALPHABLENDENABLE, enabled & 0xff);
        *(unsigned char *)grim_config_values[id].words =
            (unsigned char)enabled;
        return;
    }

    case 19: {
        unsigned int state = value.words[0];
        if (grim_config_values[id].words[0] == state) {
            return;
        }
        grim_d3d_device->SetRenderState(D3DRS_SRCBLEND, state);
        grim_config_values[id].words[0] = state;
        return;
    }

    case 20: {
        unsigned int state = value.words[0];
        if (grim_config_values[id].words[0] == state) {
            return;
        }
        grim_d3d_device->SetRenderState(D3DRS_DESTBLEND, state);
        grim_config_values[id].words[0] = state;
        return;
    }

    case 52:
        *(unsigned char *)grim_config_values[id].words =
            (unsigned char)value.words[0];
        return;

    case 54:
        grim_d3d_device->Present(0, 0, 0, 0);
        return;

    case 11:
    case 12:
    case 14:
    case 66:
        *(unsigned char *)grim_config_values[id].words =
            (unsigned char)value.words[0];
        return;

    case 13:
        *(unsigned char *)grim_config_values[id].words =
            (unsigned char)value.words[0];
        if (grim_input_cached) {
            grim_mouse_enabled = true;
        }
        return;

    case 21: {
        int filter = value.words[0];
        if (filter <= 0) {
            return;
        }
        if (filter > 2) {
            if (filter != 3) {
                return;
            }
            if (grim_config_values[id].words[0] != filter) {
                grim_d3d_device->SetTextureStageState(
                    0, D3DTSS_MAXANISOTROPY, filter);
            }
        }
        unsigned int current = grim_config_values[id].words[0];
        grim_config_value_t *config = &grim_config_values[id];
        if (current == 3) {
            grim_d3d_device->SetTextureStageState(
                0, D3DTSS_MAXANISOTROPY, 1);
        }
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_MINFILTER, filter);
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_MAGFILTER, filter);
        config->words[0] = filter;
        return;
    }

    case 82:
        grim_config_values[id] = value;
        grim_device_window_override = *(HWND *)value.words[3];
        return;

    case 85:
        grim_render_disabled = (unsigned char)value.words[0];
        return;

    default:
        break;
    }

    grim_config_value_t *config = &grim_config_values[id];
    config->words[0] = value.words[0];
    config->words[1] = value.words[1];
    config->words[2] = value.words[2];
    config->words[3] = value.words[3];
}
