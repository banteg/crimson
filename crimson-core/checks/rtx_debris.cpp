// Exercise the production selector and game hooks without a graphics context.
#include "../game/rtx_debris.cpp"
#include <cassert>
#include <cstdio>
#include <cstring>

extern "C" {
effect_entry_t effect_pool[512]{};
vec2f_t camera_offset{};
crimson_cfg_t config_blob{};
int run_elapsed_ms;
}
GameEffectOverflow game_effect_overflow{};
bool drawing = true;
extern "C" bool rtx_drawing() { return drawing; }
int draws(const RtxDebrisBudget &b) {
  return std::count_if(b.states.begin(), b.states.end(), [](auto &s) { return s.alpha > 0; });
}
int main() {
  RtxDebrisBudget b;
  std::vector<RtxDebrisBudget::Candidate> c;
  for (int i = 0; i < 1400; ++i) c.push_back({i, float((i % 8) * 128 + 64), float((i % 6) * 128 + 64), 100});
  b.select(c, 1024, 768, 0);
  assert(draws(b) == 256);
  auto original = b.states;
  std::reverse(c.begin(), c.end());
  b.select(c, 1024, 768, 0);
  for (int i = 0; i < 2560; ++i) assert(b.alpha(i) == original[i].alpha);
  int cells[48]{};
  for (auto &v : c) if (b.alpha(v.slot) > 0) ++cells[int(v.y/128)*8+int(v.x/128)];
  // Every occupied tile gets a share, regardless of input/pool ordering.
  for (auto &v : c) assert(cells[int(v.y/128)*8+int(v.x/128)] > 0);

  // Retire one selected entry while the rest stay visible: no abrupt cutoff,
  // no advancement on paused redraws, and a replacement fades in.
  int retire = 0;
  while (!b.alpha(retire)) ++retire;
  for (auto &v : c) if (v.slot == retire) v.area = 1e9f;
  b.select(c, 1024, 768, .02f);
  assert(fabsf(b.alpha(retire) - .75f) < 1e-5f);
  b.select(c, 1024, 768, 0);
  assert(fabsf(b.alpha(retire) - .75f) < 1e-5f);
  b.select(c, 1024, 768, .08f);
  assert(b.alpha(retire) == 0);
  assert(draws(b) <= 256);

  // Large chunks exhaust projected area well before the count limit.
  b.reset();
  for (auto &v : c) v.area = 1024 * 768 / 16.f;
  b.select(c, 1024, 768, 0);
  assert(draws(b) == 8);
  // Rapid camera/density changes keep retiring quads inside the hard cap.
  for (int frame = 0; frame < 120; ++frame) {
    for (auto &v : c) {
      v.x = float((v.slot + frame) % 8 * 128 + 64);
      v.y = float((v.slot + frame / 2) % 6 * 128 + 64);
      v.area = ((v.slot + frame) % 3) ? 100 : 1e9f;
    }
    b.select(c, 1024, 768, .004f);
    assert(draws(b) <= 320);
  }
  b.reset();
  c.resize(12);
  for (auto &v : c) v.area = 100;
  b.select(c, 1024, 768, 0);
  for (auto &v : c) assert(b.alpha(v.slot) == 1);
  b.forget(c[0].slot);
  assert(!b.states[c[0].slot].seen && b.alpha(c[0].slot) == 0);

  config_blob.screen_width = 1024; config_blob.screen_height = 768;
  game_effect_overflow.extent = 900;
  for (int i = 0; i < game_effects_extent(); ++i) {
    auto *e = game_effects_entry(i);
    e->effect_id = i % 4 == 0 ? 14 : 8 + i % 3;
    e->flags = 0x5d; e->age = 0; e->color.a = .5f;
    e->position = {float(i % 8 * 128 + 64), float(i % 6 * 128 + 64)};
    e->half_extent = {10, 10}; e->scale = 1;
  }
  auto snapshot = game_effect_overflow;
  effect_entry_t original_pool[512];
  memcpy(original_pool, effect_pool, sizeof effect_pool);
  rtx_debris_prepare();
  int shown = 0;
  for (int i = 0; i < game_effects_extent(); ++i) {
    unsigned long color = 0x80785634;
    if (rtx_debris_color(game_effects_entry(i), &color)) { ++shown; assert(color == 0x80785634); }
    else assert(color == 0x00785634);
  }
  assert(shown == 256);
  assert(!memcmp(&snapshot, &game_effect_overflow, sizeof snapshot));
  assert(!memcmp(original_pool, effect_pool, sizeof effect_pool));
  // Normal sprites, classic mode, and non-pool frozen creature ice are untouched.
  effect_entry_t outside{}; outside.effect_id = 14;
  unsigned long color = 0x12345678;
  assert(rtx_debris_color(&outside, &color) && color == 0x12345678);
  effect_pool[0].effect_id = 0;
  assert(rtx_debris_color(&effect_pool[0], &color) && color == 0x12345678);
  drawing = false;
  assert(rtx_debris_color(&effect_pool[1], &color) && color == 0x12345678);
  drawing = true;
  budget.states[1].alpha = .5f;
  color = 0x80785634;
  assert(rtx_debris_color(&effect_pool[1], &color) && color == 0x40785634);
  // Reusing a live slot must not inherit its prior fade, even at the same age.
  int reuse = 1;
  while (!budget.alpha(reuse)) ++reuse;
  rtx_debris_spawn(game_effects_entry(reuse));
  assert(budget.alpha(reuse) == 0 && !budget.states[reuse].seen);
  // Offscreen/fully transparent debris costs no admission slots.
  for (int i = 0; i < game_effects_extent(); ++i) game_effects_entry(i)->position.x = -1000;
  effect_pool[1].position = {100,100}; effect_pool[1].color.a = 0;
  run_elapsed_ms += 16;
  rtx_debris_prepare();
  assert(draws(budget) == 0);
  effect_pool[1].color.a = .5f;
  rtx_debris_prepare();
  assert(budget.alpha(1) == 1);
  run_elapsed_ms -= 10;
  rtx_debris_prepare(); // rewind resets stale histories
  assert(draws(budget) == 1 && budget.alpha(1) == 1);
  rtx_debris_reset(); assert(draws(budget) == 0 && last_ms == -1);
  puts("RTX debris: limits, area, coverage, fades, pause, reuse, reset, and render-only hooks passed");
}
