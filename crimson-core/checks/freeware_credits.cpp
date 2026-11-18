#include "../freeware/game.h"
#include <cassert>
#include <cstdio>

extern "C" unsigned char game_credits_update();
extern "C" float freeware_simulation_clock, frame_dt;
extern const freeware::Input *freeware_frame_input;
extern float freeware_frame_delta;

void check_credits() {
  using namespace freeware;
  struct Sample {
    float age, alpha;
    bool pending, space_down, escape, enter, click;
  };
  const Sample samples[] = {
      {0, 1, true}, {.5f, 1}, {24, .5f}, {43, 1}, {77, 1}, {101, 1},
      {24, 1, false, true}, {24, .04f, false, false, true}, {24, 1, false, false, false, true},
      {24, 1, false, false, false, false, true},
  };
  for (const auto &s : samples) {
    Game game;
    Input input;
    FrameGameScope scope(game);
    game.screen = Screen::Credits;
    game.transition_pending = s.pending;
    game.transition_alpha = s.alpha;
    game.state_since = 4;
    input.space_down = s.space_down;
    input.escape = s.escape;
    input.accept = s.enter;
    input.click = s.click;
    freeware_frame_delta = .125f;
    freeware_frame_input = &input;
    freeware_simulation_clock = 4 + s.age;
    game.ui.source_blend = 2;
    game.ui.destination_blend = 2;
    for (int tick = 0; tick < (s.space_down ? 3 : 1); ++tick) {
      game.frame_sprites.clear();
      game.frame_labels.clear();
      game_credits_update();
      std::printf("credits %.8g %.8g %d %d %d %d %d %d %.8g %.8g %.8g %d %d\n", s.age, s.alpha, s.pending,
                  s.space_down, s.escape, s.enter, s.click, tick, frame_dt, game.state_since, game.transition_alpha,
                  game.transition_pending, game.screen == Screen::Credits);
      assert(game.frame_sprites.size() == 1);
      const auto &background = game.frame_sprites.front();
      const auto &tint = background.color;
      std::printf("creditbg %s %g %g %g %g %g %g %g %g %g %g %g %g %g %u %u %u\n", background.name.c_str(),
                  background.x, background.y, background.width, background.height, background.angle,
                  background.uv.u, background.uv.v, background.uv.s, background.uv.t,
                  tint.r, tint.g, tint.b, tint.a, background.filter, background.source_blend, background.destination_blend);
      for (const auto &line : game.frame_labels) {
        assert(line.preceding_sprites == 1);
        std::printf("credittext %.8g %.8g %.8g %.8g %.8g %.8g %.8g ", line.x, line.y, line.scale, line.color.r,
                    line.color.g, line.color.b, line.color.a);
        for (unsigned char c : line.text)
          std::printf("%02x", c);
        std::puts("");
      }
      freeware_simulation_clock += freeware_frame_delta;
    }
    freeware_frame_input = nullptr;
  }
}
