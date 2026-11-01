#include "../freeware/game.h"
#include <algorithm>
#include <cstdio>

int early_sample_count(int sample);

void check_early_menu() {
  using namespace freeware;
  enum Scenario { keyboard_begin, paused_end, option_boundary, volume, tips, option_enter, mouse_begin };
  constexpr int glow_y = FREEWARE_EDITION == 10002 ? 340 : 326;
  constexpr int option_height = FREEWARE_EDITION == 10002 ? 30 : 26;
  for (int scene = keyboard_begin; scene <= mouse_begin; ++scene) {
    Game game;
    game.effects = false;
    if (scene == paused_end) {
      game.paused = true;
      game.active_run = true;
    }
    if (scene == option_boundary || scene == volume || scene == option_enter)
      game.screen = Screen::Options;
    const int frames = scene == option_boundary ? 3 : scene == volume ? 2 : scene == tips ? 4 : 1;
    for (int tick = 0; tick < frames; ++tick) {
      Input input;
      input.x = 225;
      input.y = main_row_top + 5;
      switch (scene) {
      case keyboard_begin: input.accept = true; break;
      case paused_end:
        input.y += (main_row_count - 1) * 32;
        input.click = true;
        break;
      case option_boundary: {
        constexpr int offsets[] = {option_height - 1, option_height, 5};
        input.x = 185;
        input.y = glow_y + offsets[tick];
        input.click = true;
        break;
      }
      case volume:
        input.x = 185;
        input.y = 217;
        input.click = tick == 0;
        break;
      case tips: {
        constexpr int keys[] = {23, 12, 19, 22}; // SDL scancodes T I P S.
        input.x = 10;
        input.y = 100;
        input.ctrl = true;
        input.key = keys[tick];
        break;
      }
      case option_enter:
        input.x = 185;
        input.y = glow_y + 5;
        input.accept = true;
        break;
      case mouse_begin: input.click = true; break;
      }
      const int before = early_sample_count(17);
      game.update(1.f / 60, input);
      const bool default_label = std::any_of(game.frame_labels.begin(), game.frame_labels.end(),
          [](const auto &label) { return label.text == "Sound volume: default"; });
      std::printf("earlymenu %d %d %d %d %d %d %d %d %d\n", scene, tick, game.frame_state(),
                  game.screen == Screen::Options, game.active_run, game.quit, game.effects,
                  early_sample_count(17) - before, default_label);
    }
  }
}
