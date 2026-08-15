#include <windows.h>

struct GrimGuid {
    unsigned long data1;
    unsigned short data2;
    unsigned short data3;
    unsigned char data4[8];
};

struct GrimDataFormat;
struct GrimDirectInput;
struct GrimKeyboardDevice;

struct GrimDirectInputVtable {
    void *QueryInterface;
    void *AddRef;
    void *Release;
    long (__stdcall *CreateDevice)(
        GrimDirectInput *self,
        const GrimGuid *guid,
        GrimKeyboardDevice **device,
        void *outer);
};

struct GrimKeyboardDeviceVtable {
    void *slots0[6];
    long (__stdcall *SetProperty)(
        GrimKeyboardDevice *self,
        const GrimGuid *property,
        const void *header);
    long (__stdcall *Acquire)(GrimKeyboardDevice *self);
    void *slots1[3];
    long (__stdcall *SetDataFormat)(
        GrimKeyboardDevice *self, const GrimDataFormat *format);
    void *SetEventNotification;
    long (__stdcall *SetCooperativeLevel)(
        GrimKeyboardDevice *self, HWND hwnd, unsigned long flags);
};

struct GrimDirectInput {
    GrimDirectInputVtable *vtable;
};

struct GrimKeyboardDevice {
    GrimKeyboardDeviceVtable *vtable;
};

struct GrimPropertyHeader {
    unsigned long size;
    unsigned long header_size;
    unsigned long object;
    unsigned long how;
};

struct GrimPropertyDword {
    GrimPropertyHeader header;
    unsigned long data;
};

extern "C" const GrimGuid IID_IDirectInput8A;
extern "C" const GrimGuid GUID_SysKeyboard;
extern "C" const GrimDataFormat c_dfDIKeyboard;
extern "C" long __stdcall DirectInput8Create(
    HINSTANCE instance,
    unsigned long version,
    const GrimGuid *iid,
    void **output,
    void *outer);

extern GrimDirectInput *grim_dinput_keyboard;
extern GrimKeyboardDevice *grim_keyboard_device;
extern bool grim_keyboard_poll(void);

bool grim_keyboard_init(HWND hwnd)
{
    if (hwnd == 0 && GetForegroundWindow() == 0) {
        GetDesktopWindow();
    }

    if (grim_dinput_keyboard == 0) {
        HRESULT result = DirectInput8Create(
            GetModuleHandleA(0),
            0x800,
            &IID_IDirectInput8A,
            (void **)&grim_dinput_keyboard,
            0);
        if (result < 0) {
            grim_dinput_keyboard = 0;
            return 0;
        }
    }

    if (grim_keyboard_device == 0) {
        HRESULT result = grim_dinput_keyboard->vtable->CreateDevice(
            grim_dinput_keyboard, &GUID_SysKeyboard, &grim_keyboard_device, 0);
        if (result < 0) {
            return 0;
        }
        result = grim_keyboard_device->vtable->SetDataFormat(
            grim_keyboard_device, &c_dfDIKeyboard);
        if (result < 0) {
            return 0;
        }
        result = grim_keyboard_device->vtable->SetCooperativeLevel(
            grim_keyboard_device, hwnd, 0x16);
        if (result < 0) {
            return 0;
        }

        GrimPropertyDword property;
        property.header.size = sizeof(property);
        property.header.header_size = sizeof(property.header);
        property.header.object = 0;
        property.header.how = 0;
        property.data = 10;
        grim_keyboard_device->vtable->SetProperty(
            grim_keyboard_device, (const GrimGuid *)1, &property.header);

        if (grim_keyboard_device != 0) {
            grim_keyboard_device->vtable->Acquire(grim_keyboard_device);
        }
    }

    grim_keyboard_poll();
    return 1;
}
