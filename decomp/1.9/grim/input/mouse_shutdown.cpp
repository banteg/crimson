typedef unsigned long ULONG;

struct GrimDirectInput;
struct GrimMouseDevice;

struct GrimDirectInputVtable {
    void *QueryInterface;
    void *AddRef;
    ULONG (__stdcall *Release)(GrimDirectInput *self);
};

struct GrimMouseDeviceVtable {
    void *QueryInterface;
    void *AddRef;
    ULONG (__stdcall *Release)(GrimMouseDevice *self);
    void *slots[5];
    long (__stdcall *Unacquire)(GrimMouseDevice *self);
};

struct GrimDirectInput {
    GrimDirectInputVtable *vtable;
};

struct GrimMouseDevice {
    GrimMouseDeviceVtable *vtable;
};

extern GrimDirectInput *grim_dinput_mouse;
extern GrimMouseDevice *grim_mouse_device;

void grim_mouse_shutdown(void)
{
    if (grim_mouse_device != 0) {
        grim_mouse_device->vtable->Unacquire(grim_mouse_device);
        grim_mouse_device->vtable->Release(grim_mouse_device);
        grim_mouse_device = 0;
    }
    if (grim_dinput_mouse != 0) {
        grim_dinput_mouse->vtable->Release(grim_dinput_mouse);
        grim_dinput_mouse = 0;
    }
}
