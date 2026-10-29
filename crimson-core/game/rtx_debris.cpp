// A rendering budget for loose freeze debris; simulation and baked decals are
// unchanged. Living-creature ice never enters this effect-pool hook.
#include "effect_overflow.h"
#include "rtx_debris.h"
#include <cstdint>

extern "C" {
extern vec2f_t camera_offset;
extern crimson_cfg_t config_blob;
extern int run_elapsed_ms;
bool rtx_drawing();
}
namespace {
RtxDebrisBudget budget;
int last_ms = -1;
static_assert(RtxDebrisBudget::capacity == GAME_EFFECT_POOL_CAPACITY + GAME_EFFECT_OVERFLOW_CAPACITY);
int slot(const effect_entry_t *entry) {
  uintptr_t at = (uintptr_t)entry, base = (uintptr_t)effect_pool;
  if (at >= base && at < base + sizeof(effect_entry_t) * GAME_EFFECT_POOL_CAPACITY)
    return (at - base) / sizeof(effect_entry_t);
  base = (uintptr_t)game_effect_overflow.entries;
  if (at >= base && at < base + sizeof game_effect_overflow.entries)
    return GAME_EFFECT_POOL_CAPACITY + (at - base) / sizeof(effect_entry_t);
  return -1;
}
bool ice(const effect_entry_t *e) { return e->effect_id == 14 || (e->effect_id >= 8 && e->effect_id <= 10); }
}
extern "C" void rtx_debris_reset() { budget.reset(); last_ms = -1; }
// Reset at allocation, including slots reused between rendered frames. This
// sidecar never writes an entry or consumes random numbers.
extern "C" void rtx_debris_spawn(const effect_entry_t *entry) { budget.forget(slot(entry)); }
extern "C" void rtx_debris_prepare() {
  if (!rtx_drawing()) return;
  int now = run_elapsed_ms;
  if (last_ms < 0 || now < last_ms || now - last_ms > 250) budget.reset();
  float dt = last_ms < 0 ? 0.f : std::max(0, now - last_ms) * .001f;
  last_ms = now;
  float width = config_blob.screen_width, height = config_blob.screen_height;
  if (!(width > 0 && height > 0)) { budget.reset(); return; }
  std::vector<RtxDebrisBudget::Candidate> candidates;
  for (int i = 0; i < game_effects_extent(); ++i) {
    const auto *e = game_effects_entry(i);
    if (!e->flags || e->age < 0 || !ice(e) || e->color.a < 1.f / 255) continue;
    float x = e->position.x + camera_offset.x, y = e->position.y + camera_offset.y;
    float co = fabsf(cosf(e->rotation)), si = fabsf(sinf(e->rotation));
    float w = (co * e->half_extent.x + si * e->half_extent.y) * fabsf(e->scale);
    float h = (si * e->half_extent.x + co * e->half_extent.y) * fabsf(e->scale);
    float area = std::max(0.f, std::min(width, x + w) - std::max(0.f, x - w)) *
                 std::max(0.f, std::min(height, y + h) - std::max(0.f, y - h));
    if (area > 0) candidates.push_back({i, x, y, area});
  }
  budget.select(candidates, width, height, dt);
}
extern "C" bool rtx_debris_color(const effect_entry_t *entry, unsigned long *color) {
  if (!rtx_drawing() || !ice(entry)) return true;
  int index = slot(entry);
  if (index < 0) return true;
  unsigned a = (unsigned)(((*color >> 24) & 255) * budget.alpha(index) + .5f);
  *color = (*color & 0xffffff) | (a << 24);
  return a != 0;
}
