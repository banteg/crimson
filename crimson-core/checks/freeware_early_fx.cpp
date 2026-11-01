// Both old corpse writers keep overwriting the last slot once the draw count is capped.
#include "../freeware/game.h"
#include <cstdio>

extern "C" {
void fx_queue_add_random(const vec2f_t *);
void fx_queue_add_rotated(const vec2f_t *, const effect_color_t *, float, float, int);
extern unsigned freeware_rng_state;
}

void check_early_fx_writes() {
  freeware::Game game;
  freeware::FrameGameScope scope(game);
  freeware::seed_random(0x21357);
  for (int i = 0; i < 66; ++i) {
    float value = float(i);
    vec2f_t pos = {value + .5f, value - 5.f};
    effect_color_t color = {value / 128.f, .25f, .75f, 1.f};
    fx_queue_add_rotated(&pos, &color, value * .125f, value + 42.f, i % 2);
    fx_queue_add_random(&pos);
  }
  const auto &fx = game.fx;
  std::printf("fxcounts %d %d %u\n", fx.corpse_count, fx.blood_count, freeware_rng_state);
  for (int i = 0; i < 64; ++i) {
    const auto &color = fx.corpse_colors[i];
    std::printf("fxslot %d %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %d %.9g %.9g\n",
                i, fx.corpse_positions[i].x, fx.corpse_positions[i].y, color.r, color.g, color.b, color.a,
                fx.corpse_angles[i], fx.corpse_sizes[i], fx.corpse_species[i], fx.blood[i].x, fx.blood[i].y);
  }
}
