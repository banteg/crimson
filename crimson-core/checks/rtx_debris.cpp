// Exercise the production selector and game hooks without a graphics context.
#include "../game/rtx_debris.cpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include "effects_render_adapted.cpp"

IGrim2D_cpp grim;
IGrim2D_cpp *grim_interface_ptr = &grim;
static std::vector<int> materials;
static std::vector<float> submitted;
static int material = -1, trig_calls;
unsigned char grim_render_disabled;
extern "C" {
int particles_texture, rtx_render_mode = 1;
float camera_offset_x, camera_offset_y;
double portable_sin(double x) { ++trig_calls; return sin(x); }
double portable_cos(double x) { ++trig_calls; return cos(x); }
bool rtx_smoke_active() { return false; }
int rtx_explosion_owns(const effect_entry_t *) { return 0; }
void rtx_explosions_draw() {}
void rtx_glint(bool) {}
bool rtx_effect_sprite(const effect_entry_t *, unsigned) { return false; }
void rtx_ice(int id) {
  if (!rtx_drawing() || material == id) return;
  materials.push_back(id); material = id;
}
}
void IGrim2D_cpp::grim_submit_vertices_transform_color(float *, int count, float *pos, float *, unsigned long *) {
  assert(count == 4); submitted.push_back(pos[0]);
}


extern "C" {
effect_entry_t effect_pool[512]{};
vec2f_t camera_offset{};
crimson_cfg_t config_blob{};
int run_elapsed_ms;
game_state_id_t game_state_id = GAME_STATE_GAMEPLAY;
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
  b.reset();
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
  for (auto &v : c) if (v.slot == retire) v.area = 400000.f;
  b.select(c, 1024, 768, .02f);
  assert(fabsf(b.alpha(retire) - .75f) < 1e-5f);
  int replacement = -1;
  for (int i = 0; i < 2560; ++i)
    if (!original[i].alpha && b.alpha(i) > 0) { assert(replacement < 0); replacement = i; }
  assert(replacement >= 0 && fabsf(b.alpha(replacement) - .25f) < 1e-5f);
  assert(draws(b) == 257);
  b.select(c, 1024, 768, 0);
  assert(fabsf(b.alpha(retire) - .75f) < 1e-5f);
  assert(fabsf(b.alpha(replacement) - .25f) < 1e-5f);
  for (int step = 2; step <= 4; ++step) {
    b.select(c, 1024, 768, .02f);
    assert(fabsf(b.alpha(replacement) - step * .25f) < 1e-5f);
    assert(fabsf(b.alpha(retire) - (1 - step * .25f)) < 1e-5f);
  }
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
  run_elapsed_ms = 10000;
  rtx_debris_prepare();
  budget.states[1].alpha = .5f;
  // Frozen results/perk/game-over redraws must ignore score-clock writes,
  // including small forward steps, rewinds, and negative quest scores.
  for (auto state : {GAME_STATE_QUEST_RESULTS, GAME_STATE_PERK_SELECTION, GAME_STATE_GAME_OVER}) {
    game_state_id = state;
    for (int score : {10100, 20000, 5000, -1000}) {
      run_elapsed_ms = score;
      rtx_debris_prepare();
      assert(budget.alpha(1) == .5f && last_ms == 10000);
    }
  }
  // A first frozen-world redraw has no gameplay history to advance.
  rtx_debris_reset(); rtx_debris_prepare();
  assert(budget.alpha(1) == 1 && last_ms == 0);
  game_state_id = GAME_STATE_GAMEPLAY;
  rtx_debris_reset(); assert(draws(budget) == 0 && last_ms == -1);
  // The adapted loop must cull before material changes and portable trig.
  // A hidden shard between two visible cubes must not split their batch.
  memset(effect_pool, 0, sizeof effect_pool);
  game_effect_overflow = {};
  for (int i = 0; i < 3; ++i) {
    auto &e = effect_pool[i];
    e.effect_id = i == 1 ? 8 : 14; e.flags = 0x5d;
    e.position = {float(100 + i * 100), 100};
    e.color = {1, 1, 1, .5f}; e.scale = 1;
    budget.states[i].alpha = i == 1 ? 0 : 1;
  }
  effects_render();
  assert((submitted == std::vector<float>{100, 300}));
  assert((materials == std::vector<int>{14, -1}));
  assert(trig_calls == 8);
  submitted.clear(); materials.clear(); trig_calls = 0;
  drawing = false; rtx_render_mode = 0;
  effects_render();
  assert((submitted == std::vector<float>{100, 200, 300}));
  assert(materials.empty() && trig_calls == 12);
  puts("RTX debris: limits, area, coverage, fades, pause, reuse, reset, and render-only hooks passed");
}
