#pragma once
#include "../freeware/game.h"
#include <cstdio>

inline void check_freeware_timing() {
  freeware::Game game;
  // Hit exactly 500 ms, cross it, then include a frame sharing the previous clock tick.
  for (int ms : {125, 125, 250, 125, 0, 100, 100, 100, 100, 100, 100}) {
    game.update(ms * .001f, {});
    std::printf("timing %d %.9g\n", ms, game.fps);
  }
}
