#pragma once
// The input the host delivers before each frame (game_input), which the
// module's DirectInput devices drain as Grim polls them (game/dinput.cpp). Keys
// are DirectInput scancodes. The Node checks write it by offset
// (checks/game_host.mjs).
#include <stddef.h>

struct HostInput {
  unsigned char keys[256]; // 0x80 while held
  int mouse_dx, mouse_dy, mouse_dz;
  unsigned char mouse_buttons[8];
  int key_event_count; // presses and releases since the last poll, oldest first
  struct {
    unsigned char key, down;
  } key_events[32];
  // A gamepad as the Logitech Dual Action the game's pad schemes are named for:
  // left stick X/Y, right stick Z/Rz (-1000 to 1000), buttons (0x80 while
  // held), and the d-pad as the hat (hundredths of a degree, or ~0 centred).
  int pad_axes[4];
  unsigned pad_hat;
  unsigned char pad_buttons[32];
};
static_assert(offsetof(HostInput, mouse_dx) == 256 && offsetof(HostInput, mouse_dy) == 260 &&
                  offsetof(HostInput, mouse_buttons) == 268 && offsetof(HostInput, key_event_count) == 276 &&
                  offsetof(HostInput, key_events) == 280,
              "checks/game_host.mjs writes HostInput by these offsets");
