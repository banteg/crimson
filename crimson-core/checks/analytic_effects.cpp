// Production effect hooks over a recording-only Grim/host boundary.
#include "../game/rtx_effects.cpp"
#include <cassert>
#include <cstdio>
#include <cstring>

projectile_t projectile_pool[96];
Config config_blob{true};
EffectAtlasEntry effect_id_table[19]{};
extern "C" {
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
extern "C" bool rtx_drawing() { return enabled && outputs && !disabled; }
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
  assert(calls == 2);
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
  submissions.clear();
  blends.clear();
  grim_config_values[0x14].words[0] = 6;
  assert(rtx_effect_quad(points));
  grim_vertex_count = 4;
  grim_interface_ptr->grim_end_batch();
  grim_config_values[0x14].words[0] = 2;
  assert(rtx_effect_quad(points));
  grim_interface_ptr->grim_end_batch();
  assert((submissions == std::vector<int>{1, -1, 1}));
  assert((blends == std::vector<unsigned>{6, 2}));
  puts("analytic hooks: output suppression, alpha coverage, original corners, "
       "batch-end submission and 100-to-1 sprite batching passed");
}
