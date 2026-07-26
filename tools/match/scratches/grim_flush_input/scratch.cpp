#include <string.h>
#include "grim2d_cpp.h"

typedef unsigned long DWORD;

struct GrimKeyboardEvent {
    DWORD offset;
    DWORD data;
    DWORD timestamp;
    DWORD sequence;
    unsigned long app_data;
};

struct GrimKeyboardDevice;

struct GrimKeyboardDeviceVtable {
    void *slots[10];
    long (__stdcall *GetDeviceData)(
        GrimKeyboardDevice *self,
        DWORD object_size,
        GrimKeyboardEvent *events,
        DWORD *count,
        DWORD flags);
};

struct GrimKeyboardDevice {
    GrimKeyboardDeviceVtable *vtable;
};

extern GrimKeyboardDevice *grim_keyboard_device;
extern GrimKeyboardEvent grim_keyboard_event_buffer[10];
extern unsigned char grim_keyboard_state[256];
extern int grim_key_char_queue_count;

void IGrim2D_cpp::grim_flush_input(void)
{
    DWORD count = 10;

    memset(grim_keyboard_state, 0, sizeof(grim_keyboard_state));
    int tries = 0;
    do {
        grim_keyboard_device->vtable->GetDeviceData(
            grim_keyboard_device,
            sizeof(GrimKeyboardEvent),
            grim_keyboard_event_buffer,
            &count,
            0);
    } while (tries++ < 100 && count > 0);

    memset(grim_keyboard_state, 0, sizeof(grim_keyboard_state));
    grim_key_char_queue_count = 0;
}
