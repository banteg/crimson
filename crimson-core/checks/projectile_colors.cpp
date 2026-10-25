// Supply texture handles individually; only draw submission is under test.
#define CRIMSONLAND_TEXTURES_OWNER_H
#include "projectile-under-test.cpp"
#include "../game/ion_arcs.cpp"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>

crimson_cfg_t config_blob;
player_state_t player_state_table[2];
projectile_pool_t projectile_pool;
secondary_projectile_pool_t secondary_projectile_pool;
creature_t creature_pool[385];
int arc_first = -1, arc_last = -1, plasma_calls = 0, arc_calls = 0;
extern "C" {
IGrim2D_cpp *grim_interface_ptr;
projectile_render_vec2_t camera_offset;
int bullet_trail_texture = 101, particles_texture = 102, projectile_texture = 103, projectile_bullet_texture = 104;
int perk_id_sharpshooter, perk_id_ion_gun_master, quest_spawn_timeline;
int run_elapsed_ms, current_player_index;
unsigned char portable_preserve_bugs;
double portable_sin(double x) { return sin(x); }
double portable_cos(double x) { return cos(x); }
float portable_sinf(float x) { return sinf(x); }
float portable_cosf(float x) { return cosf(x); }
void effect_select_texture(int) { grim_interface_ptr->grim_bind_texture(102, 0); }
int creature_find_in_radius(float *, float, int start) {
  return start <= arc_last ? std::max(start, arc_first) : -1;
}
// Record the dispatch boundary; production primitive guards are exercised
// separately.
int rtx_render_mode;
void rtx_beam_body(float, float, float, float, float, float, float, float, float, float, float, float) {
  assert(rtx_render_mode);
}
void rtx_beam_head(float, float, float, float, bool) {
  assert(rtx_render_mode);
}
void rtx_plasma(int slot, float alpha) {
  assert(slot == 0 && alpha == .75f);
  ++plasma_calls;
}
void rtx_ion_arc(float, float, float, float, float, float) { ++arc_calls; }
vec2f_t *D3DXVec2Normalize(vec2f_t *dst, const vec2f_t *src) {
  float length = sqrtf(src->x * src->x + src->y * src->y);
  *dst = length ? vec2f_t{src->x / length, src->y / length} : vec2f_t{};
  return dst;
}
}
int perk_count_get(int) { return 0; }

int main() {
  IGrim2D_cpp draws;
  grim_interface_ptr = &draws;
  int cases = 0;
  for (bool preserve : {false, true})
    for (auto type : {PROJECTILE_TYPE_ION_RIFLE, PROJECTILE_TYPE_ION_MINIGUN,
                      PROJECTILE_TYPE_ION_CANNON, PROJECTILE_TYPE_FIRE_BULLETS})
      for (float life : {0.4f, 0.2f})
        for (float distance : {0.0f, 200.0f}) {
          portable_preserve_bugs = preserve;
          memset(&projectile_pool, 0, sizeof(projectile_pool));
          auto &shot = projectile_pool[0];
          shot.active = 1;
          shot.pos.tail.vy.type_id = type;
          shot.pos.tail.vy.life_timer = life;
          shot.pos_x = shot.pos.origin_x = 100;
          shot.pos.pos_y = 100;
          shot.pos.tail.origin_y = 100 + distance;
          draws.projectile_colors.clear();
          projectile_render(0.75f);
          assert(!draws.projectile_colors.empty());
          auto head = draws.projectile_colors.back();
          std::array<float, 4> expected = type == PROJECTILE_TYPE_FIRE_BULLETS
            ? std::array<float, 4>{1.0f, 0.6f, 0.1f, life * 2.5f * 0.75f}
            : std::array<float, 4>{0.5f, 0.6f, 1.0f, life * 2.5f * 0.75f};
          if (preserve && life == 0.4f) expected = {1.0f, 1.0f, 0.7f, 0.75f};
          if (preserve && life < 0.4f) expected = {0.5f, 0.6f, 1.0f, life * 2.5f * 0.75f};
          for (int channel = 0; channel < 4; ++channel)
            assert(fabsf(head[channel] - expected[channel]) < 1e-6f);
          ++cases;
        }
  printf("projectile head colors: %d weapon/phase/trail/bug-policy cases passed\n", cases);
  rtx_render_mode = 1;
  for (auto type :
       {PROJECTILE_TYPE_PLASMA_RIFLE, PROJECTILE_TYPE_PLASMA_MINIGUN,
        PROJECTILE_TYPE_PLASMA_CANNON, PROJECTILE_TYPE_SPIDER_PLASMA,
        PROJECTILE_TYPE_SHRINKIFIER})
    for (float life : {.4f, .2f}) {
      memset(&projectile_pool, 0, sizeof projectile_pool);
      auto &shot = projectile_pool[0];
      shot.active = 1;
      shot.pos.tail.vy.type_id = type;
      shot.pos.tail.vy.life_timer = life;
      shot.pos.tail.vy.speed_scale = 1;
      int previous = plasma_calls;
      projectile_render(.75f);
      assert(plasma_calls == previous + 1);
    }
  memset(&projectile_pool, 0, sizeof projectile_pool);
  auto &shot = projectile_pool[0];
  shot.active = 1;
  shot.pos.tail.vy.type_id = PROJECTILE_TYPE_ION_RIFLE;
  shot.pos.tail.vy.life_timer = .2f;
  // Three creatures piled in one cell take two arcs; one apart takes its own.
  arc_first = 1;
  arc_last = 4;
  for (int i = 1; i <= 3; ++i)
    creature_pool[i].pos_x = 20;
  creature_pool[4].pos_x = 60;
  projectile_render(.75f);
  assert(arc_calls == 3);
  puts("projectile RTX dispatch: plasma phases and ion contacts passed");
}
