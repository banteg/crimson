// Drive the production 1.4.0 state machine exclusively through its normal inputs.
// The companion original-executable check consumes the row, hover and spawn output.
#include "../freeware/game.h"
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace freeware {
void play_sound(Sound) {}
} // namespace freeware
extern "C" {
extern float freeware_elapsed_seconds;
extern int creature_spawned_count;
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
}
int main() {
  using namespace freeware;
  Game game;
  Input in;
  auto step = [&] { game.update(1.f / 60, in); };
  auto click = [&](float x, float y) {
    in.x = x;
    in.y = y;
    in.click = true;
    step();
    in.click = false;
    step();
  };
  click(480, 278);
  assert(game.survival && game.screen == Screen::Menu);
  for (int i = 0; i < 8; ++i) {
    const auto row = menu_row(game, i);
    std::printf("row %.0f %.0f %s\n", row.x, row.y, row.label);
    for (float delta : {0.f, 1.f, float(std::strlen(row.label) * 16 - 1), float(std::strlen(row.label) * 16)}) {
      game.cursor_x = row.x + delta;
      game.cursor_y = row.y + 1;
      std::printf("hover %.0f %.0f %d\n", game.cursor_x, game.cursor_y, menu_hover(game));
    }
  }
  // Poison untouched fields, force slot 2 and check all 128 bytes against the PE.
  std::memset(creature_pool, 0x5a, sizeof(creature_pool));
  creature_pool[2].active = 0;
  freeware_elapsed_seconds = 1.25f;
  vec2f_t pos{1088, 643};
  effect_color_t tint{.4f, .8f, .6f, 1};
  assert(creature_spawn(&pos, &tint, 1) == 2);
  std::printf("spawn ");
  for (auto c : *reinterpret_cast<unsigned char (*)[sizeof(creature_t)]>(&creature_pool[2]))
    std::printf("%02x", c);
  std::puts("");
  click(460, 210);
  assert(game.screen == Screen::Playing && game.generation == 1);
  in.up = true;
  for (int i = 0; i < 18; ++i)
    step();
  in.up = false;
  assert(game.run.player.y < arena * .5f);
  for (int i = 0; i < 60 * 60 && game.screen == Screen::Playing; ++i) {
    const creature_t *closest = nullptr;
    float nearest = 1e10f;
    for (const auto &c : creature_pool) {
      if (!c.active || c.health <= 0)
        continue;
      float d = std::hypot(c.pos_x - game.run.player.x, c.pos_y - game.run.player.y);
      if (d < nearest) {
        closest = &c;
        nearest = d;
      }
    }
    in.fire = !game.run.kills && closest;
    if (in.fire) {
      in.x = closest->pos_x + camera_x(game);
      in.y = closest->pos_y + camera_y(game);
    }
    step();
  }
  assert(game.screen == Screen::Dying);
  in.fire = false;
  for (int i = 0; i < 181; ++i)
    step();
  assert(game.screen == Screen::Death && game.run.kills > 0 && game.run.health <= 0);
  in.fire = false;
  in.text = "Player";
  step();
  in.text.clear();
  in.accept = true;
  step();
  in.accept = false;
  assert(game.screen == Screen::Scores);
  in.escape = true;
  step();
  in.escape = false;
  assert(game.screen == Screen::Menu);
  click(460, 210);
  assert(game.screen == Screen::Playing && game.generation == 2 && game.run.health == 100);
  assert(game.run.kills == 0 && highscore_record_shots_fired == 0 && creature_spawned_count == 2);
}
