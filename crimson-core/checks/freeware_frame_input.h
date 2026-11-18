#pragma once

#include "../freeware/game.h"
#include "../freeware/screenshot_key.h"
#include <cassert>
#include <cstdio>

inline void check_screenshot_input() {
  if (FREEWARE_EDITION == 10002)
    return;
  using namespace freeware;
  struct Sample {
    bool down;
    int elapsed_ms;
  };
  const Sample samples[] = {
      {true, 0}, {false, 0}, {true, 10}, {true, 250}, {true, 240}, {true, 10},
      {true, 100}, {true, 1000}, {false, 0}, {true, 10}, {false, 10}, {true, 450},
      {true, 500}, {true, 200}, {true, 220}, {false, 0}, {true, 0}, {true, 500}};
  for (bool console : {false, true}) {
    ScreenshotKey key;
    Game game;
    game.console_open = console;
    int tick = 0;
    for (const auto &sample : samples) {
      const float delta = float(sample.elapsed_ms * .001);
      Input input;
      input.screenshot = key.poll(sample.down, delta);
      input.quit_chord = tick + 1 == int(sizeof(samples) / sizeof(*samples));
      game.update(delta, input);
      assert(game.quit == input.quit_chord);
      std::printf("f12 %d %d %d %d %d\n", console, tick++, sample.down, sample.elapsed_ms,
                  game.screenshot_requested);
      game.screenshot_requested = false;
    }
  }
}
