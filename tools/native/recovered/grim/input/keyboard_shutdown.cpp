typedef unsigned long ULONG;

struct GrimDirectInput;
struct GrimKeyboardDevice;

struct GrimDirectInputVtable {
    void *QueryInterface;
    void *AddRef;
    ULONG (__stdcall *Release)(GrimDirectInput *self);
};

struct GrimKeyboardDeviceVtable {
    void *QueryInterface;
    void *AddRef;
    ULONG (__stdcall *Release)(GrimKeyboardDevice *self);
    void *slots[5];
    long (__stdcall *Unacquire)(GrimKeyboardDevice *self);
};

struct GrimDirectInput {
    GrimDirectInputVtable *vtable;
};

struct GrimKeyboardDevice {
    GrimKeyboardDeviceVtable *vtable;
};

extern GrimDirectInput *grim_dinput_keyboard;
extern GrimKeyboardDevice *grim_keyboard_device;

void grim_keyboard_shutdown(void)
{
    if (grim_keyboard_device != 0) {
        grim_keyboard_device->vtable->Unacquire(grim_keyboard_device);
        grim_keyboard_device->vtable->Release(grim_keyboard_device);
        grim_keyboard_device = 0;
    }
    if (grim_dinput_keyboard != 0) {
        grim_dinput_keyboard->vtable->Release(grim_dinput_keyboard);
        grim_dinput_keyboard = 0;
    }
}
