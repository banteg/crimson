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
extern unsigned int grim_backbuffer_width;
extern unsigned int grim_backbuffer_height;
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
#if CL_BUILD == 10002
    enum { frame = 1, title_id = 2, windowed = 3, width = 4, height = 5, bpp = 6 };
#elif CL_BUILD < 10900
    enum { frame = 1, lost = 2, restore = 3, title_id = 5, windowed = 6,
           width = 7, height = 8, bpp = 9 };
#else
    enum { lost = 5, restore = 6, title_id = 7, width = 41, height = 42,
           bpp = 43, frame = 45 };
#endif
#if CL_BUILD == 10002
    enum { mouse = 9, resource_paq = 11, alpha_blend = 12, src_blend = 13,
           dest_blend = 14, texture_filter = 15 };
#else
    enum { mouse = 13, resource_paq = 16, alpha_blend = 18, src_blend = 19,
           dest_blend = 20, texture_filter = 21 };
#endif
    enum { bool_word = CL_BUILD < 10400 ? 2 : 0,
           callback_word = CL_BUILD < 10400 ? 5 : 3 };

    switch (id) {
#if CL_BUILD >= 10400
    case 26:
        if (!grim_set_texture_stage_ops(value.words[0])) {
            return;
        }
        grim_config_values[id] = value;
        return;

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
#endif

#if CL_BUILD < 10900
    case windowed:
        grim_config_values[id] = value;
        return;

#if CL_BUILD == 10002
    case 7:
    case 8:
    case 10:
#else
    case 11:
    case 12:
    case 14:
#endif
        *(unsigned char *)&grim_config_values[id].words[bool_word] =
            (unsigned char)value.words[bool_word];
        return;
#else
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
#endif

    case width:
#if CL_BUILD < 10400
        grim_config_values[id].words[0] = value.words[0];
        grim_backbuffer_width = value.words[0];
#else
        grim_backbuffer_width = value.words[0];
        grim_config_values[id].words[0] = value.words[0];
#endif
        return;

    case height:
#if CL_BUILD < 10400
        grim_config_values[id].words[0] = value.words[0];
        grim_backbuffer_height = value.words[0];
#else
        grim_backbuffer_height = value.words[0];
        grim_config_values[id].words[0] = value.words[0];
#endif
        return;

    case bpp:
        grim_config_values[id].words[0] = value.words[0];
        grim_texture_format = value.words[0] == 32 ? 22 : 23;
        return;

    case title_id: {
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

    case frame:
        grim_frame_callback = (void (*)(void))value.words[callback_word];
        return;

#if CL_BUILD >= 10300
    case restore:
        grim_on_device_restore = (void (*)(void))value.words[callback_word];
        return;

    case lost:
        grim_on_device_lost = (void (*)(void))value.words[callback_word];
        return;
#endif

    case resource_paq: {
        char *path = (char *)value.words[3];
        if (strcmp(path, &grim_empty_string) == 0) {
#if CL_BUILD >= 10400
            char *stored =
                (char *)grim_config_values[id].words[3];
            if (stored != 0) {
                delete stored;
            }
            grim_config_values[16].words[3] =
                (unsigned int)strdup(&grim_empty_string);
#endif
            grim_lookup_blob_loaded = 0;
        }

        grim_lookup_blob_loaded = grim_lookup_blob_load(path);

#if CL_BUILD >= 10400
        char *stored = (char *)grim_config_values[id].words[3];
        if (stored != 0) {
            delete stored;
        }
        grim_config_values[id].words[3] = (unsigned int)strdup(path);
#else
        grim_config_values[id].words[3] = (unsigned int)path;
#endif
        *(unsigned char *)&grim_config_values[id].words[bool_word] =
            grim_lookup_blob_loaded;
        return;
    }

    case alpha_blend: {
        unsigned int enabled = value.words[bool_word];
        if (*(unsigned char *)&grim_config_values[id].words[bool_word] ==
            (unsigned char)enabled) {
            return;
        }
        grim_d3d_device->SetRenderState(
            D3DRS_ALPHABLENDENABLE, enabled & 0xff);
        *(unsigned char *)&grim_config_values[id].words[bool_word] =
            (unsigned char)enabled;
        return;
    }

    case src_blend: {
        unsigned int state = value.words[0];
        if (grim_config_values[id].words[0] == state) {
            return;
        }
        grim_d3d_device->SetRenderState(D3DRS_SRCBLEND, state);
        grim_config_values[id].words[0] = state;
        return;
    }

    case dest_blend: {
        unsigned int state = value.words[0];
        if (grim_config_values[id].words[0] == state) {
            return;
        }
        grim_d3d_device->SetRenderState(D3DRS_DESTBLEND, state);
        grim_config_values[id].words[0] = state;
        return;
    }

    case 52:
        *(unsigned char *)&grim_config_values[id].words[bool_word] =
            (unsigned char)value.words[bool_word];
        return;

    case 54:
        grim_d3d_device->Present(0, 0, 0, 0);
        return;

#if CL_BUILD >= 10900
    case 11:
    case 12:
    case 14:
#endif
    case 66:
        *(unsigned char *)&grim_config_values[id].words[bool_word] =
            (unsigned char)value.words[bool_word];
        return;

    case mouse:
        *(unsigned char *)&grim_config_values[id].words[bool_word] =
            (unsigned char)value.words[bool_word];
        if (grim_input_cached) {
            grim_mouse_enabled = true;
        }
        return;

    case texture_filter: {
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
        if (grim_config_values[id].words[0] == 3) {
            grim_d3d_device->SetTextureStageState(
                0, D3DTSS_MAXANISOTROPY, 1);
        }
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_MINFILTER, filter);
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_MAGFILTER, filter);
        grim_config_values[id].words[0] = filter;
        return;
    }

#if CL_BUILD >= 10400
    case 82:
        grim_config_values[id] = value;
        grim_device_window_override = *(HWND *)value.words[3];
        return;

    case 85:
        grim_render_disabled = (unsigned char)value.words[0];
        return;
#endif

    default:
        break;
    }

    grim_config_values[id] = value;
}
