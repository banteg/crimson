#include "../freeware/game.h"
#include <algorithm>
#include <cstdio>

int early_sample_count(int sample);

static void check_calibration130() {
  using namespace freeware;
  for (int player = 0; player < 2; ++player) {
    Game game;
    game.screen = Screen::Options;
    game.configuring = player;
    game.calibration = 0;
    game.selected = game.perk_hover = -1;

    for (int tick = 0; tick < 7; ++tick) {
      Input input;
      input.x = input.y = 10;
      input.stick_x[0] = .125f;
      input.stick_y[0] = -.25f;
      input.stick_x[1] = .875f;
      input.stick_y[1] = .75f;
      input.pad_any[1] = tick == 0;
      input.pad_any[0] = tick == 1;
      input.previous = tick == 2;
      input.accept = tick >= 3 && tick <= 5;
      input.aim_x[0] = tick == 4 ? -1 : 1;
      input.aim_y[0] = -input.aim_x[0];
      input.aim_x[1] = -input.aim_x[0];
      input.aim_y[1] = -input.aim_y[0];
      game.update(1.f / 60, input);

      std::printf("calibration130 %d %d %d", player, tick, game.calibration);
      for (int i = 0; i < 2; ++i)
        std::printf(" %.0f %.0f %.0f %d %d", game.pad_center[i].x * 1000, game.pad_center[i].y * 1000,
                    game.pad_threshold[i] * 1000, game.pad_left_pov[i], game.pad_right_pov[i]);
      bool prompt = std::any_of(game.frame_labels.begin(), game.frame_labels.end(), [](const auto &label) {
        return label.text.find("joystic ") != std::string::npos;
      });
      std::printf(" %d\n", prompt);
    }
  }
}

void check_early_menu() {
  if (FREEWARE_EDITION == 10300)
    check_calibration130();
  using namespace freeware;
  enum Scenario { keyboard_begin, paused_end, option_boundary, volume, tips, option_enter, mouse_begin, done_click, done_enter, paused_mode,
                  options_escape, done_both, scores_click, credits_click, active_menu };
  constexpr int glow_y = FREEWARE_EDITION == 10002 ? 340 : 326;
  constexpr int option_height = FREEWARE_EDITION == 10002 ? 30 : 26;
  for (int scene = keyboard_begin; scene <= (FREEWARE_EDITION == 10002 ? active_menu : done_both); ++scene) {
    Game game;
    game.effects = false;
    if (FREEWARE_EDITION == 10002) {
      freeware_simulation_clock = 2.5f;
      game.state_since = scene % 2 ? 1.25f : 2.25f;
      game.menu_music_pending = scene == keyboard_begin;
    }
    if (scene == paused_end || scene == paused_mode) {
      game.paused = true;
      game.active_run = true;
    }
    if (scene == active_menu)
      game.active_run = true;
    if (scene == option_boundary || scene == volume || scene == option_enter || scene == done_click ||
        scene == done_enter || scene == options_escape || scene == done_both)
      game.screen = Screen::Options;
    const bool menu_pools = FREEWARE_EDITION == 10300 && scene == tips;
    if (menu_pools) {
      creature_pool[0] = {};
      creature_pool[0].active = 1;
      creature_pool[0].health = -1;
      creature_pool[0].death_timer = 12.f;
      projectile_pool[0] = {};
      projectile_pool[0].active = 1;
      projectile_pool[0].fields.type_id = PROJECTILE_TYPE_PISTOL;
      projectile_pool[0].fields.life_timer = .25f;
    }
    const bool keyboard_done = FREEWARE_EDITION == 10300 && scene == done_enter;
    const bool both_done = FREEWARE_EDITION == 10300 && scene == done_both;
    if (keyboard_done || both_done)
      game.selected = 10;
    const int frames = keyboard_done ? 5 : scene == option_boundary ? 3 : scene == tips ? 4 :
                       scene == volume || scene == scores_click || scene == credits_click || both_done ? 2 : 1;
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
      case done_click:
      case done_enter:
      case done_both:
        input.x = 185;
        input.y = FREEWARE_EDITION == 10002 ? 180 + 8 * 32 + 5 : 170 + 10 * 26 + 5;
        input.click = scene != done_enter && (!both_done || tick == 0);
        input.accept = scene != done_click && (!keyboard_done || tick == 0 || tick == 4) && (!both_done || tick == 0);
        input.previous = keyboard_done && tick == 1;
        input.accept_down = keyboard_done && tick <= 2;
        break;
      case options_escape: input.escape = true; break;
      case scores_click:
      case credits_click:
        input.y += (scene == scores_click ? 2 : 3) * 32;
        input.click = tick == 0;
        break;
      case active_menu: break;
      case paused_mode:
        input.y += 32;
        input.click = true;
        break;
      }
      const int before = early_sample_count(17);
      game.update(1.f / 60, input);
      if (menu_pools) {
        std::printf("menupools130 %d %.8g %.8g\n", tick, creature_pool[0].death_timer,
                    projectile_pool[0].fields.life_timer);
        if (tick + 1 == frames) {
          creature_pool[0].active = 0;
          projectile_pool[0].active = 0;
        }
      }
      if (FREEWARE_EDITION == 10002)
        for (const auto &label : game.frame_labels)
          if (label.x == 180 || label.x == 220)
            std::printf("menurow102 %d %d\t%s\t%.8g %.8g %.8g %.8g %.8g %.8g %.8g\n", scene, tick,
                        label.text.c_str(), label.x, label.y, label.scale, label.color.r, label.color.g, label.color.b,
                        label.color.a);
      if (FREEWARE_EDITION == 10002)
        for (const auto &s : game.frame_sprites)
          if (s.name == "crimsonland" || s.name == "part" || s.name == "aim32")
            std::printf("menusprite102 %d %d\t%s\t%.8g %.8g %.8g %.8g %.8g %.8g %.8g %.8g %.8g %u %u %u\n",
                        scene, tick, s.name.c_str(), s.x, s.y, s.width, s.height, s.angle, s.color.r, s.color.g,
                        s.color.b, s.color.a, s.filter, s.source_blend, s.destination_blend);
      if (FREEWARE_EDITION == 10300 && (scene == done_click || scene == done_enter)) {
        float done_scale = 0;
        for (const auto &label : game.frame_labels)
          if (label.text == "Done")
            done_scale = label.scale;
        std::printf("menudone130 %d %d %d %d %.8g\n", scene, tick, game.selected, game.perk_hover, done_scale);
      }
      if (scene == scores_click || scene == credits_click)
        std::printf("menufade102 %d %d %.8g\n", scene, tick, game.transition_alpha);
      const auto drew = [&](const char *text) {
        return std::any_of(game.frame_labels.begin(), game.frame_labels.end(),
                           [text](const auto &label) { return label.text == text; });
      };
      std::printf("earlymenu %d %d %d %d %d %d %d %d %d %d %d %d\n", scene, tick, game.frame_state(),
                  game.screen == Screen::Options, game.active_run, game.quit, game.effects,
                  early_sample_count(17) - before, drew("Sound volume: default"), game.survival, drew("Highscores:"),
                  drew("Project Crimsonland"));
    }
  }
}
