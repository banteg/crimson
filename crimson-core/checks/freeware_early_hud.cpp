// Emit the 1.0.2 HUD and name-entry screen in backend draw order.
#include "../freeware/game.h"
#include <cassert>
#include <cstdio>

extern "C" {
extern game_mode_id_t config_game_mode;
extern float frame_dt, freeware_elapsed_seconds, freeware_simulation_clock;
void gameplay_render_hud();
}

static void print_color(effect_color_t color) {
  std::printf(" %.8g %.8g %.8g %.8g\n", color.r, color.g, color.b, color.a);
}

static void print_draws(const freeware::Game &game, const char *tag, int sample, size_t first_sprite) {
  size_t label = 0;
  for (size_t sprite = 0; sprite <= game.frame_sprites.size(); ++sprite) {
    while (label < game.frame_labels.size() && game.frame_labels[label].preceding_sprites == sprite) {
      const auto &l = game.frame_labels[label++];
      if (sprite < first_sprite) continue;
      std::printf("%s %d text\t%s\t%.8g %.8g %.8g", tag, sample, l.text.c_str(), l.x, l.y, l.scale);
      print_color(l.color);
    }
    if (sprite >= first_sprite && sprite < game.frame_sprites.size()) {
      const auto &s = game.frame_sprites[sprite];
      std::printf("%s %d quad\t%s\t%.8g %.8g %.8g %.8g %.8g %.8g %.8g %.8g %.8g %u",
                  tag, sample, s.name.c_str(), s.x, s.y, s.width, s.height, s.angle,
                  s.uv.u, s.uv.v, s.uv.s, s.uv.t, s.filter);
      print_color(s.color);
    }
  }
  assert(label == game.frame_labels.size());
}

void check_early_hud() {
  for (int sample = 0; sample < 12; ++sample) {
    freeware::Game game;
    freeware::FrameGameScope scope(game);
    game.enter_state(3);
    config_game_mode = static_cast<game_mode_id_t>(1 + sample % 2);
    current_player_index = 0;
    game.run.health = sample == 5 ? 0.f : sample == 9 ? -3.f : 78.f + sample;
    game.run.experience = 1234 + sample;
    game.run.pending = sample % 3;
    game.run.seconds = freeware_elapsed_seconds = 17.625f;
    frame_dt = .125f;
    freeware_simulation_clock = 51.75f;
    auto &player = player_state_table[0].freeware;
    player.weapon = sample + 1;
    player.ammo = float(3 + sample % 4);
    player.clip_size = float(11 + sample % 3);
    gameplay_render_hud();

    print_draws(game, "hud102", sample, 0);
    std::printf("hud102 %d state\t-\t%d %.8g %.8g %.8g\n", sample, game.frame_state(), game.run.seconds,
                player.ammo, game.run.health);
  }
}

void check_early_name() {
  const int keys[] = {0xa7, 'A', 8, 8, 'X', 9};
  for (int mode = 1; mode <= 2; ++mode) {
    freeware::Game game;
    game.enter_state(freeware_rules::name_entry_state);
    game.survival = mode == 2;
    game.active_run = true;
    game.state_since = 2;
    game.transition_pending = false;
    game.name = game.survival ? "Arsenal" : "10tons";
    game.run.experience = 1234;
    game.run.seconds = 42.625f;
    current_player_index = 0;
    for (int step = 0; step < 6; ++step) {
      const int key = keys[step];
      freeware::Input input;
      input.x = 121.5f;
      input.y = 267.25f;
      input.backspace = key == 8;
      input.accept = key == 9;
      if (key == 'A' || key == 'X')
        input.text = char(key);
      const float dt = .125f;
      freeware_simulation_clock = 2.f + step * .31f - dt;
      game.update(dt, input);
      // Start after the preceding world and overlay backdrop draws.
      size_t first = 0;
      while (first < game.frame_sprites.size() && game.frame_sprites[first].name != "reaper")
        ++first;
      assert(first < game.frame_sprites.size());
      const int sample = (mode - 1) * 6 + step;
      print_draws(game, "name102", sample, first);
      std::printf("name102 %d state\t%s\t%d %d %d %.8g %.8g %zu\n", sample, game.name.c_str(), game.frame_state(),
                  game.name_cursor, game.active_run, game.state_since, game.death_clock, game.scores().size());
      if (!game.scores().empty())
        std::printf("name102 %d save\t%s\t%d\n", sample, game.last_score.name.c_str(),
                    game.survival ? game.last_score.seconds : game.last_score.experience);
    }
  }
}

// In 1.3.0, the insertion cursor resets while the last accepted name remains on screen.
void check_name_edit_130() {
  using namespace freeware;
  Game game;
  game.fps = 60;
  game.name = "Prior";
  for (int round = 0; round < 2; ++round) {
    game.start();
    game.enter_state(freeware_rules::name_entry_state);
    game.name_cursor = 4;
    game.run.cheated = true; // Only later releases discard this score.
    for (float &fps : game.fps_history) fps = 60;
    const int keys[] = {0xa7, 'A', 8, 'Z', 9};
    for (int key : keys) {
      if (round == 0 && key != 9) continue;
      Input input;
      input.accept = key == 9;
      input.backspace = key == 8;
      if (key == 'A' || key == 'Z') input.text = char(key);
      freeware_simulation_clock = 5;
      game.update(0.f, input);
      std::printf("name130 %d %d\t%s\t%d %d %d %d %zu\t%s\n", round, key, game.name.c_str(), game.name_cursor,
                  game.active_run, game.screen == Screen::Scores, game.transition_pending,
                  game.scores().size(), game.last_score.name.c_str());
    }
  }
}
