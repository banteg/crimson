#include "grim_d3d8.h"

extern IDirect3D8 *grim_d3d8_probe;
extern char *grim_error_text;
extern void *grim_interface_vtable;

struct GrimInterface {
    void *vtable;

    GrimInterface(void) { vtable = &grim_interface_vtable; }
};

extern void grim_state_init(void);
extern GrimInterface *grim_interface_instance;

extern "C" GrimInterface *GRIM__GetInterface(void)
{
    IDirect3D8 *probe = Direct3DCreate8(D3D_SDK_VERSION);
    grim_d3d8_probe = probe;
    if (probe == 0) {
        grim_error_text =
            "D3D: Could not init DirectX 8.1, (re)install it.";
        MessageBoxA(
            0,
            "D3D: Could not init DirectX 8.1, (re)install it.",
            "Grim",
            MB_OK);
        return 0;
    }

    probe->Release();
    grim_state_init();

    grim_interface_instance = new GrimInterface;
    return grim_interface_instance;
}
