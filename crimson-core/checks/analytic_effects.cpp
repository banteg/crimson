// Production effect hooks over a recording-only Grim/host boundary.
#include "../game/rtx_effects.cpp"
#include <cassert>
#include <cstdio>
#include <cstring>

projectile_t projectile_pool[96];
Config config_blob{true};
EffectAtlasEntry effect_id_table[19]{};
uv2f_t effect_uv2[4]{}, effect_uv4[16]{}, effect_uv8[64]{}, effect_uv16[256]{};
extern "C" {
float effect_uv_step_2 = .4921875f, effect_uv_step_4 = .25f;
float effect_uv_step_8 = .125f, effect_uv_step_16 = .0625f;
vec2f_t camera_offset{};
int particles_texture = 7, grim_bound_texture_handle = 7;
grim_config_value_t grim_config_values[128]{};
unsigned long grim_color_slot0[4] = {0xffffffff, 0xffffffff, 0xffffffff,
                                     0xffffffff};
float grim_uv_u0[8] = {.75f, 0, 1, 0, 1, .25f, .75f, .25f};
unsigned int grim_vertex_count;
unsigned char portable_preserve_bugs;
}
bool enabled = true, outputs = true, disabled = false;
int calls = 0, flushes = 0;
float captured[16];
std::vector<EffectVertex> captured_sprites;
std::vector<int> submissions;
std::vector<unsigned> blends;
std::vector<int> passes;
extern "C" void host_render_pass(int pass) { passes.push_back(pass); }
extern "C" bool rtx_drawing() { return enabled && outputs && !disabled; }
const effect_entry_t *explosion_ring;
extern "C" bool rtx_explosion_ring(const effect_entry_t *entry) { return entry == explosion_ring; }
void IGrim2D_cpp::grim_flush_batch() {
  ++flushes;
  rtx_effect_flush();
  if (grim_vertex_count)
    submissions.push_back(-1); // Original textured work.
  grim_vertex_count = 0;
}
// As patched: pending analytic sprites draw before the batch's own textured
// work, under the state the batch was built in.
void IGrim2D_cpp::grim_end_batch() {
  rtx_effect_flush();
  if (grim_vertex_count)
    submissions.push_back(-1);
  grim_vertex_count = 0;
}
IGrim2D_cpp grim;
IGrim2D_cpp *grim_interface_ptr = &grim;
extern "C" void host_effect(const float *corners, int, const float *,
                            unsigned) {
  ++calls;
  memcpy(captured, corners, sizeof captured);
}

extern "C" void host_effect_sprites(const void *data, int kind, int count) {
  ++calls;
  submissions.push_back(kind);
  blends.push_back(grim_config_values[0x14].words[0]);
  auto *v = (const EffectVertex *)data;
  captured_sprites.assign(v, v + count);
}

int main() {
  effect_id_table[13] = {64, 3};
  effect_id_table[16] = {64, 6};
  effect_id_table[1] = {128, 3};
  effect_id_table[0] = {128, 2};
  effect_uv4[3] = {.75f, 0};
  effect_uv4[6] = {.5f, .25f};
  effect_uv2[3] = {.5f, .5f};
  effect_uv2[2] = {0, .5f};
  projectile_pool[0].fields.type_id = PROJECTILE_TYPE_PLASMA_CANNON;
  projectile_pool[0].fields.life_timer = .4f;
  projectile_pool[0].fields.speed_scale = 1;
  projectile_pool[0].fields.pos_x = 200;
  rtx_effects_active = 1;
  for (int mode = 0; mode < 4; ++mode) {
    enabled = mode != 0;
    outputs = mode != 1;
    disabled = mode == 2;
    rtx_effects_active = mode != 3;
    calls = flushes = 0;
    rtx_plasma(0, .7f);
    rtx_ion_arc(10, 10, 50, 20, 2, .7f);
    assert(calls == 0 && flushes == 0);
  }
  enabled = outputs = true;
  disabled = false;
  rtx_effects_active = 1;
  rtx_plasma(0, .7f);
  rtx_ion_arc(10, 10, 50, 20, 2, .7f);
  assert(calls == 1);
  // Consecutive arcs batch: each corner carries its local position and the
  // length in strip scales, negative when the strips end in the native cut.
  portable_preserve_bugs = 1;
  rtx_ion_arc(10, 10, 50, 40, 2, .7f);
  portable_preserve_bugs = 0;
  rtx_effect_flush();
  assert(calls == 2 && submissions.back() == 4 && captured_sprites.size() == 12);
  assert(captured_sprites[0].z == sqrtf(1700) / 2 && captured_sprites[6].z == -sqrtf(2500) / 2);
  assert(captured_sprites[0].u == -16 && captured_sprites[2].u == sqrtf(1700) / 2 + 16);
  const float points[8] = {-12, 7, 23, -15, 45, 20, 10, 42};
  // Normal-alpha warm glows keep the original texture coverage.
  grim_config_values[0x12].words[0] = 1;
  grim_config_values[0x13].words[0] = 5;
  grim_config_values[0x14].words[0] = 6;
  assert(!rtx_effect_quad(points));
  EffectVertex vertices[4];
  for (int i = 0; i < 4; ++i)
    vertices[i] = {points[i * 2],     points[i * 2 + 1],    0, 1, 0xffffffff,
                   grim_uv_u0[i * 2], grim_uv_u0[i * 2 + 1]};
  assert(!rtx_effect_vertices(vertices, 4));
  grim_config_values[0x14].words[0] = 2;
  assert(rtx_effect_quad(points));
  rtx_effect_flush();
  const int order[4] = {0, 1, 2, 5};
  for (int i = 0; i < 4; ++i) {
    assert(captured_sprites[order[i]].x == points[i * 2]);
    assert(captured_sprites[order[i]].y == points[i * 2 + 1]);
  }
  calls = flushes = 0;
  for (int i = 0; i < 100; ++i) {
    for (auto &color : grim_color_slot0)
      color = 0x80000000u + i;
    assert(rtx_effect_quad(points));
  }
  assert(calls == 0 && flushes == 0);
  rtx_effect_flush();
  assert(calls == 1 && captured_sprites.size() == 600);
  for (int i = 0; i < 100; ++i)
    assert(captured_sprites[i * 6].color == 0x80000000u + i);
  // Interleaved textured work and shape changes retain original draw order.
  submissions.clear();
  assert(rtx_effect_quad(points));
  grim_vertex_count = 4;
  assert(rtx_effect_vertices(vertices, 4));
  const float aura_uv[8] = {.5f, .25f, .75f, .25f, .75f, .5f, .5f, .5f};
  memcpy(grim_uv_u0, aura_uv, sizeof aura_uv);
  assert(rtx_effect_quad(points));
  rtx_effect_flush();
  assert((submissions == std::vector<int>{0, -1, 0, 1}));
  // A pending batch is discarded when rendering becomes suppressed.
  assert(rtx_effect_quad(points));
  disabled = true;
  calls = 0;
  rtx_effect_flush();
  assert(calls == 0);
  disabled = false;
  rtx_effect_flush();
  assert(calls == 0);
  // Ending a batch submits its pending sprites before the blend changes for the
  // next one, as effects_render switches from normal alpha to additive.
  // Alpha-composited auras (including dark plague overlays) keep their artwork.
  grim_config_values[0x14].words[0] = 6;
  assert(!rtx_effect_quad(points));
  const float ring_full[8] = {.5f, .5f, 1, .5f, 1, 1, .5f, 1};
  memcpy(grim_uv_u0, ring_full, sizeof ring_full);
  submissions.clear();
  blends.clear();
  grim_config_values[0x14].words[0] = 6;
  assert(!rtx_effect_quad(points));
  rtx_pressure_ring(20, 30, 40, .5f);
  grim_vertex_count = 4;
  grim_interface_ptr->grim_end_batch();
  grim_config_values[0x14].words[0] = 2;
  assert(!rtx_effect_quad(points));
  rtx_pressure_ring(20, 30, 40, .5f);
  grim_interface_ptr->grim_end_batch();
  assert((submissions == std::vector<int>{2, -1, 2}));
  assert((blends == std::vector<unsigned>{6, 2}));
  // Full and inset atlas rings retain their artwork. Only an explicit owned
  // explosion shell gets the pressure profile.
  float lo = .5f, hi = lo + effect_uv_step_2;
  const float ring_uv[8] = {lo, lo, hi, lo, hi, hi, lo, hi};
  memcpy(grim_uv_u0, ring_uv, sizeof ring_uv);
  assert(!rtx_effect_quad(points));
  for (int i = 0; i < 4; ++i) {
    vertices[i].u = ring_uv[i * 2];
    vertices[i].v = ring_uv[i * 2 + 1];
  }
  assert(!rtx_effect_vertices(vertices, 4));
  const float shell_uv[8] = {.5f, .5f, 1, .5f, 1, 1, .5f, 1};
  memcpy(grim_uv_u0, shell_uv, sizeof shell_uv);
  assert(!rtx_effect_quad(points));
  rtx_pressure_ring(20, 30, 40, .5f);
  rtx_effect_flush();
  assert(submissions.back() == 2);
  effect_entry_t ring{};
  ring.effect_id = 1;
  ring.flags = 0x19;
  ring.position = {23, 45};
  ring.half_extent = {32, 32};
  ring.scale = 2;
  assert(!rtx_effect_sprite(&ring, 0x80123456));
  explosion_ring = &ring;
  assert(rtx_effect_sprite(&ring, 0x80123456));
  rtx_effect_flush();
  assert(submissions.back() == 2);
  assert(captured_sprites[0].color == 0x80123456);
  assert(captured_sprites[0].x == 23 - 64 && captured_sprites[0].y == 45 - 64);
  explosion_ring = nullptr; // A released/reused slot no longer gets the pressure profile.
  assert(!rtx_effect_sprite(&ring, 0x80123456));
  // Atlas matching alone cannot distinguish glints from explosion flashes.
  const float burst_uv[8] = {0, lo, effect_uv_step_2, lo, effect_uv_step_2, hi, 0, hi};
  memcpy(grim_uv_u0, burst_uv, sizeof burst_uv);
  grim_config_values[0x14].words[0] = 6;
  assert(!rtx_effect_quad(points));
  grim_config_values[0x14].words[0] = 2;
  assert(!rtx_effect_quad(points));
  effect_entry_t flash{};
  flash.effect_id = 0;
  flash.flags = 0x19;
  flash.position = {23, 45};
  flash.half_extent = {32, 32};
  flash.scale = 2;
  assert(rtx_effect_sprite(&flash, 0x80123456));
  rtx_effect_flush();
  assert(submissions.back() == 6);
  assert(captured_sprites[0].color == 0x80123456);
  assert(captured_sprites[0].x == 23 - 64 && captured_sprites[0].y == 45 - 64);
  // Bonus glints retain their original textured rays, even at zero velocity.
  flash.flags = 0x1d;
  assert(!rtx_effect_sprite(&flash, 0x80123456));
  flushes = 0;
  rtx_glint(true);
  rtx_glint(true);
  rtx_glint(false);
  assert(flushes == 2);
  assert((passes == std::vector<int>{HOST_PASS_GLINT, HOST_PASS_SPRITES}));
  flash.flags = 0x59;
  assert(!rtx_effect_sprite(&flash, 0x80123456));
  flash.flags = 0x19;
  enabled = false;
  assert(!rtx_effect_sprite(&flash, 0x80123456));
  enabled = true;
  grim_config_values[0x14].words[0] = 6;
  assert(!rtx_effect_sprite(&flash, 0x80123456));
  puts("analytic hooks: output suppression, alpha coverage, original corners, "
       "batch-end submission and 100-to-1 sprite batching passed");
}
