#include "grim_texture.h"

#include <string.h>

extern unsigned char grim_device_ready;
extern char grim_use_ref_device;
extern D3DDEVTYPE grim_d3d_device_type;
extern unsigned int grim_selected_adapter_index;
extern D3DCAPS8 grim_device_caps;
extern int grim_config_backbuffer_count;
extern char grim_windowed_mode_enabled;
extern int grim_backbuffer_width;
extern int grim_backbuffer_height;
extern char grim_enable_auto_depth_stencil;
extern HWND grim_device_window_override;
extern HWND grim_main_window_hwnd;
extern HINSTANCE grim_module_handle;
extern IDirect3D8 *grim_active_d3d8;
extern IDirect3DDevice8 *grim_active_d3d_device;

bool grim_window_create(void);
BOOL grim_window_destroy(void);
void grim_d3d_shutdown(void);
bool grim_create_geometry_buffers(void);
bool grim_select_texture_format(void);
void grim_apply_render_state(void);

bool grim_d3d_init(void)
{
    D3DDISPLAYMODE display_mode;
    D3DADAPTER_IDENTIFIER8 adapter_identifier;

    grim_device_ready = false;
    grim_d3d8 = 0;
    grim_d3d_device = 0;
    grim_d3d_device_type = D3DDEVTYPE_HAL;
    if (grim_use_ref_device == 1) {
        grim_d3d_device_type = D3DDEVTYPE_REF;
    }

    grim_d3d8 = Direct3DCreate8(D3D_SDK_VERSION);
    if (grim_d3d8 == 0) {
        grim_error_text =
            "D3D: Could not init DirectX 8.1, (re)install it.";
        return false;
    }

    grim_d3d8->GetDeviceCaps(
        grim_selected_adapter_index,
        grim_d3d_device_type,
        &grim_device_caps);
    char is_voodoo3 = false;
    grim_d3d8->GetAdapterIdentifier(
        grim_selected_adapter_index,
        D3DENUM_NO_WHQL_LEVEL,
        &adapter_identifier);

    char *description =
        strchr(adapter_identifier.Description, 'V');
    if (description != 0 &&
        description[1] == 'o' &&
        description[2] == 'o' &&
        description[3] == 'd' &&
        description[4] == 'o' &&
        description[5] == 'o' &&
        description[6] == '3') {
        is_voodoo3 = true;
    }

    if (grim_d3d8->GetAdapterDisplayMode(0, &display_mode) < 0) {
        grim_error_text = "D3D: Error getting adapter display mode.";
        if (grim_d3d8 != 0 && grim_d3d8->Release() <= 0) {
            grim_d3d8 = 0;
        }
        return false;
    }

    if (!grim_window_create()) {
        return false;
    }

    memset(
        &grim_present_parameters,
        0,
        sizeof(grim_present_parameters));
    grim_present_parameters.BackBufferCount =
        grim_config_backbuffer_count;

    if (grim_windowed_mode_enabled == 1) {
        grim_present_parameters.Windowed = true;
        grim_present_parameters.SwapEffect = D3DSWAPEFFECT_DISCARD;
        grim_texture_format = display_mode.Format;
    } else {
        grim_present_parameters.Windowed = false;
        grim_present_parameters.SwapEffect =
            (D3DSWAPEFFECT)((is_voodoo3 != 0) + 1);
        grim_present_parameters.FullScreen_RefreshRateInHz = 0;
        grim_present_parameters.FullScreen_PresentationInterval =
            D3DPRESENT_INTERVAL_IMMEDIATE;
    }

    grim_present_parameters.BackBufferWidth = grim_backbuffer_width;
    grim_present_parameters.BackBufferHeight = grim_backbuffer_height;
    grim_present_parameters.BackBufferFormat = grim_texture_format;
    grim_present_parameters.MultiSampleType = D3DMULTISAMPLE_NONE;
    grim_present_parameters.Flags = D3DPRESENTFLAG_LOCKABLE_BACKBUFFER;
    grim_present_parameters.EnableAutoDepthStencil = false;
    if (grim_enable_auto_depth_stencil != 0) {
        grim_present_parameters.EnableAutoDepthStencil = true;
    }
    grim_present_parameters.AutoDepthStencilFormat = D3DFMT_D16;
    grim_present_parameters.hDeviceWindow = grim_device_window_override;
    if (grim_present_parameters.hDeviceWindow == 0) {
        grim_present_parameters.hDeviceWindow = grim_main_window_hwnd;
    }

    if (grim_d3d8->CreateDevice(
            grim_selected_adapter_index,
            grim_d3d_device_type,
            grim_main_window_hwnd,
            0x20,
            &grim_present_parameters,
            &grim_d3d_device) < 0) {
        grim_error_text =
            "D3D: Could not set the requested screenmode.";
        MessageBoxA(
            0,
            "D3D: Could not set the requested screenmode.",
            "Grim",
            MB_OK);
        grim_d3d_shutdown();
        grim_window_destroy();
        return false;
    }

    grim_d3d8->GetDeviceCaps(
        grim_selected_adapter_index,
        grim_d3d_device_type,
        &grim_device_caps);
    if (!grim_create_geometry_buffers()) {
        grim_d3d_shutdown();
        grim_window_destroy();
        return false;
    }

    memset(grim_texture_slots, 0, sizeof(grim_texture_slots));
    if (grim_preferred_texture_format != D3DFMT_UNKNOWN) {
        if (!grim_is_texture_format_supported(
                grim_preferred_texture_format)) {
            grim_preferred_texture_format = D3DFMT_UNKNOWN;
        }
    }
    if (grim_preferred_texture_format == D3DFMT_UNKNOWN) {
        if (!grim_select_texture_format()) {
            grim_error_text =
                "D3D: Could not find any compatible texture formats.";
            grim_d3d_shutdown();
            grim_window_destroy();
        }
    }

    grim_apply_render_state();

    HRSRC resource = FindResourceA(
        grim_module_handle, MAKEINTRESOURCEA(0x6f), RT_RCDATA);
    void *resource_data = LockResource(
        LoadResource(grim_module_handle, resource));
    unsigned int resource_size =
        SizeofResource(grim_module_handle, resource);
    if (D3DXCreateTextureFromFileInMemoryEx(
            grim_d3d_device,
            resource_data,
            resource_size,
            0xffffffff,
            0xffffffff,
            1,
            0,
            grim_preferred_texture_format,
            D3DPOOL_MANAGED,
            0xffffffff,
            0xffffffff,
            0,
            0,
            0,
            &grim_font_texture) < 0) {
        grim_error_text = "D3D: Unable to load default font texture.";
        return false;
    }

    resource = FindResourceA(
        grim_module_handle, MAKEINTRESOURCEA(0x71), RT_RCDATA);
    resource_data = LockResource(
        LoadResource(grim_module_handle, resource));
    resource_size = SizeofResource(grim_module_handle, resource);
    if (D3DXCreateTextureFromFileInMemoryEx(
            grim_d3d_device,
            resource_data,
            resource_size,
            0xffffffff,
            0xffffffff,
            1,
            0,
            grim_preferred_texture_format,
            D3DPOOL_MANAGED,
            0xffffffff,
            0xffffffff,
            0,
            0,
            0,
            &grim_splash_texture) < 0) {
        grim_error_text = "D3D: Unable to load grim splash texture.";
        return false;
    }

    grim_backbuffer_surface = 0;
    grim_render_target_surface = 0;
    grim_active_d3d8 = grim_d3d8;
    grim_active_d3d_device = grim_d3d_device;
    grim_device_ready = true;
    return true;
}
