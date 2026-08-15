#include <string.h>

typedef unsigned long DWORD;

#define DIERR_INPUTLOST 0x8007001eL

struct GrimMouseState {
    long lX;
    long lY;
    long lZ;
    unsigned char rgbButtons[8];
};

struct GrimMouseDevice;

struct GrimMouseDeviceVtable {
    void *slots[7];
    long (__stdcall *Acquire)(GrimMouseDevice *self);
    void *Unacquire;
    long (__stdcall *GetDeviceState)(
        GrimMouseDevice *self, DWORD size, void *state);
};

struct GrimMouseDevice {
    GrimMouseDeviceVtable *vtable;
};

extern GrimMouseDevice *grim_mouse_device;
extern GrimMouseState grim_mouse_state;
extern float grim_mouse_x;
extern float grim_mouse_y;
extern float grim_mouse_wheel;
extern float grim_mouse_dx;
extern float grim_mouse_dy;
extern float grim_mouse_wheel_delta;

extern "C" void grim_noop(char *message, ...);

bool grim_mouse_poll(void)
{
    if (grim_mouse_device != 0) {
        int iterations = 0;
        grim_mouse_dx = grim_mouse_dy = grim_mouse_wheel_delta = 0.0f;
        memset(&grim_mouse_state, 0, sizeof(grim_mouse_state));

        long result = grim_mouse_device->vtable->GetDeviceState(
            grim_mouse_device, sizeof(grim_mouse_state), &grim_mouse_state);
        if (result < 0) {
            goto reacquire;
        }

        while (true) {
            grim_mouse_dx += (float)grim_mouse_state.lX;
            grim_mouse_dy += (float)grim_mouse_state.lY;
            grim_mouse_wheel_delta += (float)grim_mouse_state.lZ;

            if (iterations++ >= 100) {
                break;
            }
            if (grim_mouse_state.lX == 0 &&
                grim_mouse_state.lY == 0 &&
                grim_mouse_state.lZ == 0) {
                break;
            }

            memset(&grim_mouse_state, 0, sizeof(grim_mouse_state));
            result = grim_mouse_device->vtable->GetDeviceState(
                grim_mouse_device, sizeof(grim_mouse_state), &grim_mouse_state);
            if (result < 0) {
                goto reacquire;
            }
        }

        if (iterations > 2) {
            grim_noop("stall", iterations);
        }
        grim_mouse_x += grim_mouse_dx;
        grim_mouse_y += grim_mouse_dy;
        grim_mouse_wheel += grim_mouse_wheel_delta;
        return 1;

    reacquire:
        result = grim_mouse_device->vtable->Acquire(grim_mouse_device);
        while (result == DIERR_INPUTLOST) {
            result = grim_mouse_device->vtable->Acquire(grim_mouse_device);
        }
    }
    return 1;
}
