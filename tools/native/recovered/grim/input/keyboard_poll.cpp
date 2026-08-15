#include <string.h>

typedef unsigned long DWORD;

#define DIERR_INPUTLOST 0x8007001eL
#define DIERR_NOTACQUIRED 0x80070005L

struct GrimKeyboardEvent {
    DWORD dwOfs;
    DWORD dwData;
    DWORD dwTimeStamp;
    DWORD dwSequence;
    unsigned long uAppData;
};

struct GrimKeyboardDevice;

struct GrimKeyboardDeviceVtable {
    void *slots[7];
    long (__stdcall *Acquire)(GrimKeyboardDevice *self);
    void *unacquire;
    long (__stdcall *GetDeviceState)(
        GrimKeyboardDevice *self, DWORD size, void *state);
    long (__stdcall *GetDeviceData)(
        GrimKeyboardDevice *self,
        DWORD object_size,
        GrimKeyboardEvent *events,
        int *count,
        DWORD flags);
};

struct GrimKeyboardDevice {
    GrimKeyboardDeviceVtable *vtable;
};

extern GrimKeyboardDevice *grim_keyboard_device;
extern GrimKeyboardEvent grim_keyboard_event_buffer[10];
extern unsigned char grim_keyboard_state[256];

bool grim_keyboard_poll(void)
{
    if (grim_keyboard_device != 0) {
        long result = grim_keyboard_device->vtable->Acquire(grim_keyboard_device);
        while (result == DIERR_INPUTLOST || result == DIERR_NOTACQUIRED) {
            result = grim_keyboard_device->vtable->Acquire(grim_keyboard_device);
        }
        if (result >= 0) {
            memset(grim_keyboard_state, 0, sizeof(grim_keyboard_state));
            grim_keyboard_device->vtable->GetDeviceState(
                grim_keyboard_device, 0x100, grim_keyboard_state);
            int count = 10;
            result = grim_keyboard_device->vtable->GetDeviceData(
                grim_keyboard_device,
                sizeof(GrimKeyboardEvent),
                grim_keyboard_event_buffer,
                &count,
                0);
            if (result >= 0 && count > 0) {
                for (int i = 0; i < count; ++i) {
                    grim_keyboard_state[grim_keyboard_event_buffer[i].dwOfs] =
                        (unsigned char)grim_keyboard_event_buffer[i].dwData;
                }
            }
            return 1;
        }
    }
    return 0;
}
