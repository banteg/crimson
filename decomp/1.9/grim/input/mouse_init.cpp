#include <windows.h>

struct GrimGuid {
    unsigned long data1;
    unsigned short data2;
    unsigned short data3;
    unsigned char data4[8];
};

struct GrimDataFormat;
struct GrimDirectInput;
struct GrimMouseDevice;

struct GrimDirectInputVtable {
    void *QueryInterface;
    void *AddRef;
    void *Release;
    long (__stdcall *CreateDevice)(
        GrimDirectInput *self,
        const GrimGuid *guid,
        GrimMouseDevice **device,
        void *outer);
};

struct GrimMouseDeviceVtable {
    void *slots0[7];
    long (__stdcall *Acquire)(GrimMouseDevice *self);
    void *slots1[3];
    long (__stdcall *SetDataFormat)(
        GrimMouseDevice *self, const GrimDataFormat *format);
    void *SetEventNotification;
    long (__stdcall *SetCooperativeLevel)(
        GrimMouseDevice *self, HWND hwnd, unsigned long flags);
};

struct GrimDirectInput {
    GrimDirectInputVtable *vtable;
};

struct GrimMouseDevice {
    GrimMouseDeviceVtable *vtable;
};

extern "C" const GrimGuid IID_IDirectInput8A;
extern "C" const GrimGuid GUID_SysMouse;
extern "C" const GrimDataFormat c_dfDIMouse2;
extern "C" long __stdcall DirectInput8Create(
    HINSTANCE instance,
    unsigned long version,
    const GrimGuid *iid,
    void **output,
    void *outer);

extern HWND grim_main_window_hwnd;
extern GrimDirectInput *grim_dinput_mouse;
extern GrimMouseDevice *grim_mouse_device;
extern bool grim_mouse_poll(void);

bool grim_mouse_init(HWND)
{
    HWND hwnd = grim_main_window_hwnd;
    if (hwnd == 0 && GetForegroundWindow() == 0) {
        GetDesktopWindow();
    }

    if (grim_dinput_mouse == 0) {
        HRESULT result = DirectInput8Create(
            GetModuleHandleA(0),
            0x800,
            &IID_IDirectInput8A,
            (void **)&grim_dinput_mouse,
            0);
        if (result < 0) {
            grim_dinput_mouse = 0;
            return 0;
        }
    }

    if (grim_mouse_device == 0) {
        HRESULT result = grim_dinput_mouse->vtable->CreateDevice(
            grim_dinput_mouse, &GUID_SysMouse, &grim_mouse_device, 0);
        if (result < 0) {
            return 0;
        }
        result = grim_mouse_device->vtable->SetDataFormat(
            grim_mouse_device, &c_dfDIMouse2);
        if (result < 0) {
            return 0;
        }
        result = grim_mouse_device->vtable->SetCooperativeLevel(
            grim_mouse_device, hwnd, 5);
        if (result < 0) {
            return 0;
        }
        if (grim_mouse_device != 0) {
            grim_mouse_device->vtable->Acquire(grim_mouse_device);
        }
    }

    grim_mouse_poll();
    return 1;
}
