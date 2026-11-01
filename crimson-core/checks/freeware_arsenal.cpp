#include "../freeware/game.h"
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

void check_weapon_hits() {
  using namespace freeware;
  constexpr bool early = FREEWARE_EDITION == 10002;
  Game g;
  FrameGameScope scope(g);
  for (int type : {1, 2, 4, 6, 7, 8, 9, 10, 17}) {
    if (early ? (type == 7 || type == 9 || type == 10 || type == 17) : (type == 6 || type == 8))
      continue;
    for (int mode = 0; mode < 3; ++mode) {
      std::memset(creature_pool, 0, sizeof(creature_pool));
      std::memset(projectile_pool, 0, sizeof(projectile_pool));
      std::memset(particle_pool, 0, sizeof(particle_pool));
      std::memset(secondary_projectile_pool, 0, sizeof(secondary_projectile_pool));
      std::memset(player_state_table, 0, sizeof(player_state_table));
      auto &c = creature_pool[0];
      c.active = mode != 0;
      c.position = {110, 100};
      c.health = 1000;
      c.death_timer = 16;
      c.freeware.size = 42;
      current_player_index = 0;
      bonus_fire_bullets_timer = mode == 2 ? 2 : 0;
      freeware_hit_sound_timer = 1;
      bonus_freeze_timer = 0;
      seed_random(87);
      vec2f_t start = {100, 100};
      auto &b = projectile_pool[projectile_spawn(&start, 1.57079637f, type)];
      b.fields.origin.x = 13;
      frame_dt = 1.f / 60;
      projectile_update();
      std::printf("impact %d %d %.9g %.9g %.9g %.9g %d %u\n", type, mode, b.pos_x, b.position.y,
                  b.fields.life_timer, c.health, c.plague_infected, freeware_rng_state);
    }
  }
}
