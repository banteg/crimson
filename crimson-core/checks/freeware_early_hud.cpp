// Emit the 1.0.2 HUD in backend draw order for comparison with the original frame.
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

    size_t label = 0;
    for (size_t sprite = 0; sprite <= game.frame_sprites.size(); ++sprite) {
      while (label < game.frame_labels.size() && game.frame_labels[label].preceding_sprites == sprite) {
        const auto &l = game.frame_labels[label++];
        std::printf("hud102 %d text\t%s\t%.8g %.8g %.8g", sample, l.text.c_str(), l.x, l.y, l.scale);
        print_color(l.color);
      }
      if (sprite < game.frame_sprites.size()) {
        const auto &s = game.frame_sprites[sprite];
        std::printf("hud102 %d quad\t%s\t%.8g %.8g %.8g %.8g %.8g %.8g %.8g %.8g %.8g %u",
                    sample, s.name.c_str(), s.x, s.y, s.width, s.height, s.angle,
                    s.uv.u, s.uv.v, s.uv.s, s.uv.t, s.filter);
        print_color(s.color);
      }
    }
    assert(label == game.frame_labels.size());
    std::printf("hud102 %d state\t-\t%d %.8g %.8g %.8g\n", sample, game.frame_state(), game.run.seconds,
                player.ammo, game.run.health);
  }
}
