// DirectInput 8 keyboard and mouse devices over the state the host delivers
// before each frame (game_input). Keys are DirectInput scancodes.
#include "com_defaults.h"
#include "host_abi.h"
#include <string.h>

// Filled by the host; drained by the devices as Grim polls them.
struct HostInput {
  unsigned char keys[256]; // 0x80 while held
  int mouse_dx, mouse_dy, mouse_dz;
  unsigned char mouse_buttons[8];
  int key_event_count; // presses and releases since the last poll, oldest first
  struct {
    unsigned char key, down;
  } key_events[32];
};
static HostInput input;
extern "C" __attribute__((export_name("game_input"))) HostInput *game_input() { return &input; }

extern "C" const GUID GUID_SysKeyboard, GUID_SysMouse;

namespace {

struct Device : UnimplementedIDirectInputDevice8A {
  bool keyboard;
  explicit Device(bool k) : keyboard(k) {}
  STDMETHOD_(ULONG, AddRef)(THIS) override { return 1; }
  STDMETHOD_(ULONG, Release)(THIS) override { return 0; }
  STDMETHOD(SetDataFormat)(THIS_ LPCDIDATAFORMAT) override { return DI_OK; }
  STDMETHOD(SetCooperativeLevel)(THIS_ HWND, DWORD) override { return DI_OK; }
  STDMETHOD(SetProperty)(THIS_ REFGUID, LPCDIPROPHEADER) override { return DI_OK; }
  STDMETHOD(Acquire)(THIS) override { return DI_OK; }
  STDMETHOD(Unacquire)(THIS) override { return DI_OK; }
  STDMETHOD(Poll)(THIS) override { return DI_OK; }
  STDMETHOD(GetDeviceState)(THIS_ DWORD size, LPVOID data) override {
    memset(data, 0, size);
    if (keyboard) {
      memcpy(data, input.keys, size < 256 ? size : 256);
      return DI_OK;
    }
    // DIMOUSESTATE(2): the motion since the last poll, then nothing until the next frame.
    auto *state = (LONG *)data;
    state[0] = input.mouse_dx;
    state[1] = input.mouse_dy;
    state[2] = input.mouse_dz;
    input.mouse_dx = input.mouse_dy = input.mouse_dz = 0;
    if (size > 12)
      memcpy(state + 3, input.mouse_buttons, size - 12 < 8 ? size - 12 : 8);
    return DI_OK;
  }
  STDMETHOD(GetDeviceData)(THIS_ DWORD object_size, LPDIDEVICEOBJECTDATA events, LPDWORD count, DWORD) override {
    DWORD delivered = 0;
    if (keyboard)
      for (; delivered < *count && (int)delivered < input.key_event_count; ++delivered) {
        auto *event = (DIDEVICEOBJECTDATA *)((unsigned char *)events + delivered * object_size);
        memset(event, 0, object_size);
        event->dwOfs = input.key_events[delivered].key;
        event->dwData = input.key_events[delivered].down ? 0x80 : 0;
      }
    if (delivered) {
      input.key_event_count -= delivered;
      memmove(input.key_events, input.key_events + delivered, input.key_event_count * sizeof(input.key_events[0]));
    }
    *count = delivered;
    return DI_OK;
  }
};
Device keyboard(true), mouse(false);

struct DirectInput : UnimplementedIDirectInput8A {
  STDMETHOD_(ULONG, AddRef)(THIS) override { return 1; }
  STDMETHOD_(ULONG, Release)(THIS) override { return 0; }
  STDMETHOD(CreateDevice)(THIS_ REFGUID guid, LPDIRECTINPUTDEVICE8A *device, LPUNKNOWN) override {
    if (!memcmp(guid, &GUID_SysKeyboard, sizeof(GUID)))
      *device = &keyboard;
    else if (!memcmp(guid, &GUID_SysMouse, sizeof(GUID)))
      *device = &mouse;
    else
      return E_FAIL;
    return DI_OK;
  }
  // No joysticks yet.
  STDMETHOD(EnumDevices)(THIS_ DWORD, LPDIENUMDEVICESCALLBACKA, LPVOID, DWORD) override { return DI_OK; }
};
DirectInput direct_input;

} // namespace

extern "C" HRESULT WINAPI DirectInput8Create(HINSTANCE, DWORD, REFIID, LPVOID *output, LPUNKNOWN) {
  *output = &direct_input;
  return DI_OK;
}
