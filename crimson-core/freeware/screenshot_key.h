#pragma once

namespace freeware {
// Grim samples F12 every frame. 1.3 waits for a release; 1.4 also repeats while held.
struct ScreenshotKey {
  bool released = false;
  float remaining = 0;

  bool poll(bool down, float elapsed) {
    if (!down) {
      released = true;
      remaining = 0;
      return false;
    }
    if constexpr (FREEWARE_EDITION == 10300) {
      bool pressed = released;
      released = false;
      return pressed;
    }
    remaining -= elapsed;
    if (remaining > 0)
      return false;
    remaining = released ? .5f : .1f;
    released = false;
    return true;
  }
};
} // namespace freeware
