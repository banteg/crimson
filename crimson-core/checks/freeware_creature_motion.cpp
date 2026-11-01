#include "../freeware/game.h"
#include <cstdio>
#include <cstring>

extern "C" {
extern unsigned freeware_rng_state;
extern float freeware_simulation_clock, freeware_elapsed_seconds;
extern int config_player_count;
extern game_mode_id_t config_game_mode;
void player_reset_all();
}

namespace {
void record(int tick, int slot) {
  const auto &c = creature_pool[slot];
  const auto &f = c.freeware;
  std::printf("motionrow %d %d %u %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g"
              " %u %u %d %u %.9g %.9g %.9g\n",
              tick, slot, c.active, c.pos_x, c.pos_y, c.vel_x, c.vel_y, c.health, f.heading, f.size,
              f.contact_damage, f.move_speed, f.attack_cooldown, f.animation, c.death_timer, f.target.x, f.target.y,
              c.anim_phase, c.plague_infected, f.force_target, f.player, c.ai_mode, c.activation_radius,
              c.hit_flash_timer, f.target_heading);
}

void creature(int slot, float x, float y) {
  auto &c = creature_pool[slot];
  c.active = 1;
  c.position = {x, y};
  c.health = 60;
  c.freeware.heading = 1.57f;
  c.freeware.size = 48;
  c.freeware.move_speed = 2;
  c.freeware.contact_damage = 7;
  c.freeware.animation = 30;
  c.freeware.reward = 133;
  c.death_timer = 16;
  c.ai_mode = 1;
  c.activation_radius = 40;
  c.hit_flash_timer = -1;
}

enum Case { pursuit, contact, negative_berserk, full_berserk, small, corpse, frozen, overlap, shielded, retarget,
            both_dead, dormant, wall, breeder_hatch, reserved_perk };
}

void check_creature_motion() {
  using namespace freeware;
  const bool early = FREEWARE_EDITION == 10002;
  for (int scenario = pursuit; scenario <= (early ? overlap : reserved_perk); ++scenario) {
    Game g;
    // The two extra slots exercise the pool boundary, its first overlapping peer, and offspring allocated in slot zero.
    const int last = early ? 127 : 511;
    g.active_run = scenario != breeder_hatch;
    g.two_players = scenario == shielded || scenario == retarget || scenario == both_dead;
    g.run.player = {512, 512};
    g.run.partner.player = {544, 512};
    g.run.health = scenario == retarget || scenario == both_dead ? 0 : 6;
    g.run.partner.health = scenario == both_dead ? 0 : 21;
    g.run.shield = scenario == shielded ? 2 : 0;
    g.run.freeze = scenario == frozen ? 1 : 0;
    g.run.berserk = scenario == full_berserk ? 12 : scenario == negative_berserk ? -1 : 0;
    config_game_mode = static_cast<game_mode_id_t>(scenario == dormant || scenario == wall ? 3 : 1);
    config_player_count = g.players();
    player_reset_all();
    current_player_index = 0;
    std::memset(creature_pool, 0, sizeof(creature_pool));
    creature(5, 518, 519);
    auto &c = creature_pool[5];
    if (scenario == pursuit || scenario == frozen || scenario == overlap) {
      c.position = {647, 590};
      creature(last, scenario == overlap ? 651 : 750, 590);
    } else if (scenario == small) {
      c.freeware.size = 28;
    } else if (scenario == corpse) {
      c.health = -1;
      creature(last, 604, 615);
      creature_pool[last].death_timer = 14;
    } else if (scenario == shielded) {
      c.freeware.player = 1;
      c.position = {541, 515};
    } else if (scenario == dormant) {
      c.ai_mode = 0;
      c.position = {605, 512};
    } else if (scenario == wall) {
      auto *object = new freeware_level_object{};
      object->position = {522, 480};
      object->width = 12;
      object->height = 90;
      freeware_current_map->add_object(1, object);
      g.run.player = {610, 512};
      c.position = {507, 512};
    } else if (scenario == breeder_hatch) {
      c.hit_flash_timer = 3.99f;
      c.position = {680, 520};
    } else if (scenario == reserved_perk) {
      // 1.3.0 registers this slot beyond the accessible picker range.
      player_state_table[0].freeware.perks[22] = 1;
    }
    creature_spawned_count = 1 + creature_pool[last].active;
    freeware_elapsed_seconds = 0;
    seed_random(76);
    std::printf("motioncase %d %d %d %d %.9g %.9g %d %d %d\n", scenario, int(config_game_mode), config_player_count,
                g.active_run, g.run.berserk, g.run.freeze, player_state_table[0].freeware.perks[22],
                creature_spawned_count, scenario == wall);
    for (int i = 0; i < 2; ++i) {
      auto &p = g.actor(i);
      std::printf("motionplayer %d %.9g %.9g %.9g %.9g\n", i, p.player.x, p.player.y, p.health, p.shield);
    }
    for (int slot : {0, 5, last}) record(-1, slot);
    for (int tick = 0; tick < 10; ++tick) {
      if (scenario == dormant && tick == 3)
        g.run.player = {576, 512}; // The Level Test creature wakes when the player enters its activation radius.
      float dt = tick == 0 ? .03125f : .125f;
      freeware_simulation_clock = 1 + tick * .125f;
      g.update_creatures(dt);
      std::printf("motionstep %d %.9g %.9g %.9g %.9g %.9g %d %d %u\n", tick, dt, g.run.player.x, g.run.player.y,
                  g.run.health, g.run.partner.health, g.fx.blood_count, creature_spawned_count, freeware_rng_state);
      for (int i = 0; i < g.fx.blood_count; ++i)
        std::printf("motionmark %d %.9g %.9g\n", i, g.fx.blood[i].x, g.fx.blood[i].y);
      for (int slot : {0, 5, last}) record(tick, slot);
    }
    freeware_current_map->clear();
  }
}
