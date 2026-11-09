#include "../freeware/game.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
extern unsigned freeware_rng_state;
extern int perk_id_fastloader, perk_id_sharpshooter, perk_id_fastshot, perk_id_ammo_maniac;
void player_reset_all();
}
namespace {
std::vector<int> samples;
}
namespace freeware {
void play_sound(Sound s) { samples.push_back(static_cast<int>(s)); }
void play_original_sample(int id) { samples.push_back(id); }
}
int early_sample_count(int sample) { return int(std::count(samples.begin(), samples.end(), sample)); }
void check_arsenal() {
  using namespace freeware;
  constexpr bool early = FREEWARE_EDITION == 10002;
  for (int id = 1; id <= 17; ++id) {
    if (early && id > 8 && id != 17)
      continue;
    for (int variant = 0; variant < 3; ++variant) {
      Game g;
      g.two_players = !early && variant == 2;
      const int actor = g.two_players ? 1 : 0;
      g.aiming[actor] = 0;
      player_reset_all();
      auto &p = player_state_table[actor].freeware;
      auto &fighter = g.actor(actor);
      fighter.player = {512, 512};
      fighter.cooldown = 0;
      fighter.spread = 1;
      fighter.health = 100;
      p.muzzle_flash = 0;
      p.reload = 0;
      weapon_assign_player(actor, id);
      std::printf("arm %d %d %g %s\n", id, actor, p.clip_size, weapon_name_get(id));
      p.ammo = variant == 1 ? .04f : 10;
      if (variant == 1) {
        p.perks[perk_id_fastloader] = p.perks[perk_id_fastshot] = p.perks[perk_id_sharpshooter] = 1;
        if (!early)
          p.perks[perk_id_ammo_maniac] = 1;
      }
      std::memset(projectile_pool, 0, sizeof(projectile_pool));
      std::memset(secondary_projectile_pool, 0, sizeof(secondary_projectile_pool));
      std::memset(particle_pool, 0, sizeof(particle_pool));
      std::memset(sprite_effect_pool, 0, sizeof(sprite_effect_pool));
      Input in{};
      in.mouse_fire = true;
      in.x = 712;
      in.y = 512;
      samples.clear();
      const unsigned seed = variant == 1 ? 7654 : 42;
      seed_random(seed);
      g.step_player(actor, 1.f / 60, in, {712, 512});
      std::printf("fire %d %d %u %.9g %.9g %.9g %.9g %.9g %u", id, variant, seed, p.ammo, p.cooldown, p.reload,
                  p.spread, p.muzzle_flash, freeware_rng_state);
      for (int s : samples)
        std::printf(" %d", s);
      std::puts("");
      for (auto &b : projectile_pool)
        if (b.active)
          std::printf("round b %d %.9g %.9g %.9g %.9g\n", int(b.fields.type_id), b.pos_x, b.position.y, b.angle,
                      b.fields.speed_scale);
      for (auto &b : secondary_projectile_pool)
        if (b.active)
          std::printf("round r %d %.9g %.9g %.9g %.9g\n", int(b.fields.type_id), b.pos_x, b.position.y, b.angle,
                      b.life_timer);
      for (auto &b : particle_pool)
        if (b.active)
          std::printf("round f %d %.9g %.9g %.9g %.9g\n", early ? b.in_flight : b.style_id, b.pos_x, b.pos_y, b.angle, b.intensity);
    }
  }
}

extern "C" game_mode_id_t config_game_mode;
void check_weapon_hits() {
  using namespace freeware;
  constexpr bool early = FREEWARE_EDITION == 10002;
  Game g;
  FrameGameScope scope(g);
  for (int type : {1, 2, 4, 6, 7, 8, 9, 10, 17}) {
    if (early ? (type == 7 || type == 9 || type == 10 || type == 17) : (type == 6 || type == 8))
      continue;
    const int modes = early && type == 4 ? 7 : 5;
    for (int mode = 0; mode < modes; ++mode) {
      const bool survival = mode >= 5;
      config_game_mode = static_cast<game_mode_id_t>(survival ? 1 : 2);
      std::memset(creature_pool, 0, sizeof(creature_pool));
      std::memset(projectile_pool, 0, sizeof(projectile_pool));
      std::memset(particle_pool, 0, sizeof(particle_pool));
      std::memset(secondary_projectile_pool, 0, sizeof(secondary_projectile_pool));
      std::memset(player_state_table, 0, sizeof(player_state_table));
      auto &c = creature_pool[0];
      c.active = mode != 0;
      c.position = {110, 100};
      c.health = mode < 3 ? 1000 : 5;
      c.freeware.reward = 121;
      creature_spawned_count = mode != 0;
      g.run.experience = survival ? 31 : 0;
      g.run.pickup = {};
      if (survival) {
        player_state_table[0].freeware.weapon = 1;
        if (mode == 6)
          g.run.pickup = {{79, 81}, Bonus::Fire, 3.5f, 0};
      }
      c.death_timer = 16;
      c.freeware.size = 42;
      current_player_index = 0;
      bonus_fire_bullets_timer = mode == 2 ? 2 : 0;
      freeware_hit_sound_timer = 1;
      bonus_freeze_timer = mode == 4 ? 1 : 0;
      g.run.freeze = bonus_freeze_timer;
      seed_random(survival ? 3 : 87);
      vec2f_t start = {100, 100};
      auto &b = projectile_pool[projectile_spawn(&start, 1.57079637f, type)];
      b.fields.origin.x = 13;
      frame_dt = 1.f / 60;
      projectile_update();
      const auto &pickup = g.run.pickup;
      std::printf("impact %d %d %.9g %.9g %.9g %.9g %d %u %.9g %d %d %d %.9g %.9g %.9g\n", type, mode, b.pos_x,
                  b.position.y, b.fields.life_timer, c.health, c.plague_infected, freeware_rng_state, c.death_timer,
                  creature_spawned_count, g.run.experience, int(pickup.kind), pickup.pos.x, pickup.pos.y, pickup.time);
    }
  }
}

extern "C" int fx_spawn_secondary_projectile(const vec2f_t *, float, secondary_projectile_type_id_t);
void check_flames_and_rockets() {
  using namespace freeware;
  Game g;
  FrameGameScope scope(g);
  const bool early = FREEWARE_EDITION == 10002;
  // Both early allocators reuse the last slot. 1.4.0 rolls a random slot for excess flames.
  for (auto &b : projectile_pool) b.active = 1;
  for (auto &f : particle_pool) f.active = 1;
  seed_random(77);
  vec2f_t pool_pos = {200, 250}, pool_vel = {0, 0};
  int bullet_slot = projectile_spawn(&pool_pos, .5f, 4);
  int flame_slot = fx_spawn_particle(&pool_pos, .5f, &pool_vel, 1);
  std::printf("overflow %d %d %u\n", bullet_slot, flame_slot, freeware_rng_state);
  for (int kind : {4, 15, 11, 12}) {
    if (early && kind != 4) continue;
    for (bool hit : {false, true}) {
      std::memset(creature_pool, 0, sizeof(creature_pool));
      std::memset(projectile_pool, 0, sizeof(projectile_pool));
      std::memset(particle_pool, 0, sizeof(particle_pool));
      std::memset(sprite_effect_pool, 0, sizeof(sprite_effect_pool));
      std::memset(secondary_projectile_pool, 0, sizeof(secondary_projectile_pool));
      auto &c = creature_pool[0];
      c.active = 1;
      c.position = {hit ? 109.f : 420.f, 100};
      c.death_timer = 16;
      c.health = 3000;
      c.freeware.size = 42;
      c.freeware.color = {1, 1, 1, 1};
      frame_dt = 1.f / 60;
      freeware_hit_sound_timer = 1;
      bonus_freeze_timer = bonus_fire_bullets_timer = 0;
      seed_random(14);
      vec2f_t pos = {100, 100}, zero = {0, 0};
      auto &r = secondary_projectile_pool[0];
      auto &f = particle_pool[0];
      bool rocket = kind == 11 || kind == 12;
      if (rocket)
        fx_spawn_secondary_projectile(&pos, 1.57079637f, static_cast<secondary_projectile_type_id_t>(kind - 10));
      else {
        fx_spawn_particle(&pos, 0, &zero, 1);
        f.style_id = kind == 15;
      }
      for (int i = 0; i < 8; ++i) {
        projectile_update();
        std::printf("flight %d %d %d %d %.9g %.9g %.9g %.9g %.9g %.9g %u\n", kind, int(hit), i,
                    rocket ? int(r.fields.type_id) : f.in_flight, rocket ? r.pos_x : f.pos_x,
                    rocket ? r.position.y : f.pos_y, rocket ? r.angle : f.angle, rocket ? r.life_timer : f.intensity,
                    c.health, c.pos_x, freeware_rng_state);
      }
    }
  }
}
