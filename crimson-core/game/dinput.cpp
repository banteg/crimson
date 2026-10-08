// DirectInput 8 keyboard, mouse and joystick devices over the state the host
// delivers before each frame (game_input). Keys are DirectInput scancodes.
#include "com_defaults.h"
#include "host_abi.h"
#include "host_input.h"
#include <string.h>

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

// Always attached, so a pad plugged in after startup works; with none it rests.
const GUID pad_guid = {0x6f1d2b70, 0xd5a0, 0x11cf, {0xbf, 0xc7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};
struct Joystick : UnimplementedIDirectInputDevice8A {
  STDMETHOD_(ULONG, AddRef)(THIS) override { return 1; }
  STDMETHOD_(ULONG, Release)(THIS) override { return 0; }
  STDMETHOD(SetDataFormat)(THIS_ LPCDIDATAFORMAT) override { return DI_OK; }
  STDMETHOD(SetCooperativeLevel)(THIS_ HWND, DWORD) override { return DI_OK; }
  STDMETHOD(SetProperty)(THIS_ REFGUID, LPCDIPROPHEADER) override { return DI_OK; }
  STDMETHOD(Acquire)(THIS) override { return DI_OK; }
  STDMETHOD(Unacquire)(THIS) override { return DI_OK; }
  STDMETHOD(Poll)(THIS) override { return DI_OK; }
  // The axes, which Grim ranges to -1000..1000 (grim_joystick_configure_axis).
  STDMETHOD(EnumObjects)(THIS_ LPDIENUMDEVICEOBJECTSCALLBACKA callback, LPVOID ref, DWORD) override {
    static const DWORD offsets[] = {offsetof(DIJOYSTATE2, lX), offsetof(DIJOYSTATE2, lY), offsetof(DIJOYSTATE2, lZ),
                                    offsetof(DIJOYSTATE2, lRz)};
    for (DWORD i = 0; i < 4; ++i) {
      DIDEVICEOBJECTINSTANCEA object = {};
      object.dwSize = sizeof object;
      object.dwOfs = offsets[i];
      object.dwType = DIDFT_ABSAXIS | DIDFT_MAKEINSTANCE(i);
      if (callback(&object, ref) == DIENUM_STOP)
        break;
    }
    return DI_OK;
  }
  STDMETHOD(GetDeviceState)(THIS_ DWORD size, LPVOID data) override {
    DIJOYSTATE2 state = {};
    state.lX = input.pad_axes[0];
    state.lY = input.pad_axes[1];
    state.lZ = input.pad_axes[2];
    state.lRz = input.pad_axes[3];
    memset(state.rgdwPOV, 0xff, sizeof state.rgdwPOV);
    state.rgdwPOV[0] = input.pad_hat;
    memcpy(state.rgbButtons, input.pad_buttons, sizeof input.pad_buttons);
    memcpy(data, &state, size < sizeof state ? size : sizeof state);
    return DI_OK;
  }
};
Joystick joystick;

struct DirectInput : UnimplementedIDirectInput8A {
  STDMETHOD_(ULONG, AddRef)(THIS) override { return 1; }
  STDMETHOD_(ULONG, Release)(THIS) override { return 0; }
  STDMETHOD(CreateDevice)(THIS_ REFGUID guid, LPDIRECTINPUTDEVICE8A *device, LPUNKNOWN) override {
    if (!memcmp(guid, &GUID_SysKeyboard, sizeof(GUID)))
      *device = &keyboard;
    else if (!memcmp(guid, &GUID_SysMouse, sizeof(GUID)))
      *device = &mouse;
    else if (!memcmp(guid, &pad_guid, sizeof(GUID)))
      *device = &joystick;
    else
      return E_FAIL;
    return DI_OK;
  }
  STDMETHOD(EnumDevices)(THIS_ DWORD type, LPDIENUMDEVICESCALLBACKA callback, LPVOID ref, DWORD) override {
    if (type == DI8DEVCLASS_GAMECTRL) {
      DIDEVICEINSTANCEA instance = {};
      instance.dwSize = sizeof instance;
      instance.guidInstance = instance.guidProduct = pad_guid;
      instance.dwDevType = DI8DEVTYPE_GAMEPAD;
      strcpy(instance.tszInstanceName, "Gamepad");
      strcpy(instance.tszProductName, "Gamepad");
      callback(&instance, ref);
    }
    return DI_OK;
  }
};
DirectInput direct_input;

} // namespace

extern "C" HRESULT WINAPI DirectInput8Create(HINSTANCE, DWORD, REFIID, LPVOID *output, LPUNKNOWN) {
  *output = &direct_input;
  return DI_OK;
}
