#include "../freeware/game.h"
#include <cstdio>

extern "C" {
extern unsigned freeware_rng_state;
extern unsigned char freeware_spawn_enabled;
extern int config_player_count;
}
int early_sample_count(int sample);

void check_early_frames(const char *assets) {
  using namespace freeware;
  enum Scenario { career, survival, coop, death, impact, first_map, escape_during_death = first_map + 4, reserved_perk };
  for (int scene = career; scene <= reserved_perk; ++scene) {
    const bool level = scene >= first_map && scene < escape_during_death;
    if ((scene == coop || level || scene == reserved_perk) && FREEWARE_EDITION == 10002)
      continue;
    Game game;
    game.survival = scene == survival || scene == coop;
    game.two_players = scene == coop;
    game.asset_dir = assets;
    if (level)
      game.level_mode = 3;
    config_player_count = game.players();
    freeware_current_map->clear();
    game.start();
    if (level) {
      game.load_level_brushes();
      game.level_number = scene - first_map;
      FrameGameScope scope(game);
      game.load_next_level();
      // Reproduce the final encounter after all starting triggers have already fired.
      for (auto it = freeware_current_map->triggers.begin; it != freeware_current_map->triggers.end; ++it)
        (*it)->enabled = false;
    }
    freeware_simulation_clock = 0;
    game.camera = {0, 0};
    game.run.player = {scene == career ? 200.f : 512.f, scene == career ? 180.f : 512.f};
    game.run.partner.player = {592, 512};
    game.run.health = scene == death || scene == escape_during_death ? -1 : 100;
    if (scene == escape_during_death) {
      game.run.cooldown = 0;
      game.run.exp_clock = .125f;
    }
    if (scene == reserved_perk) {
      game.run.perks[22] = 1;
      game.run.pending = 1;
      game.run.slow = .015625f;
      player_state_table[0].freeware.move_phase = .125f;
      player_state_table[0].freeware.control_reserved = 5.f;
    }
    if (scene >= death)
      game.run.next_spawn = 100;
    freeware_spawn_enabled = scene == career || game.survival;
    if (scene == impact || level) {
      // One final round is already in flight when the original callback begins.
      auto &c = creature_pool[0];
      c.active = 1;
      c.ai_mode = 1;
      c.hit_flash_timer = -1;
      c.health = 5;
      c.position = {110, 100};
      c.freeware.size = 42;
      c.freeware.reward = 121;
      c.death_timer = 16;
      creature_spawned_count = 1;
      vec2f_t start = {100, 100};
      projectile_spawn(&start, 1.57079637f, 4);
    }
    seed_random(42);
    const int frames = scene == escape_during_death ? 2 : scene == death ? 34 : level ? 64 : scene == impact ? 42 : 12;
    for (int tick = 0; tick < frames; ++tick) {
      Input input{};
      input.relative = true;
      if (scene == reserved_perk)
        input.perk_button = tick == 0;
      if (scene == escape_during_death) {
        input.right = input.fire = tick == 0;
        input.escape = tick == 1;
      }
      input.dx = tick == 0 ? -800.f : tick == 2 ? 1000.f : 0.f;
      input.dy = tick == 0 ? 700.f : tick == 2 ? -1000.f : 0.f;
      if (scene == death) {
        if (tick >= 26 && tick <= 28)
          game.low_fps_frames = (tick - 25) * 500;
        if (tick == 29 || tick == 32)
          input.text = "A";
        input.backspace = tick == 30 || tick == 31;
        input.accept = tick == 33;
      }
      int menu_sounds = early_sample_count(17);
      game.update(scene >= death ? .0625f : .03125f, input);
      if (scene == escape_during_death)
        std::printf("deathxpclock %d %.9g\n", tick, game.run.exp_clock);
      if (scene == death)
        std::printf("deathoverlay %d %d %d %d %d %d\n", tick, game.low_fps_frames, game.smoke, game.effects,
                    game.shadows, early_sample_count(17) - menu_sounds);
      if (scene == reserved_perk)
        std::printf("reservedperk %d %.9g %.9g %.9g\n", tick, game.run.slow,
                    player_state_table[0].freeware.move_phase, player_state_table[0].freeware.control_reserved);
      bool name_prompt = false, frag_stats = false;
      for (const auto &label : game.frame_labels) {
        name_prompt |= label.text == "Who were you:";
        frag_stats |= label.text.find("Frags:") != std::string::npos;
      }
      const auto &p = player_state_table[0].freeware;
      std::printf("earlyframe %d %d %d %d %u %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %d %d %.9g %d %d %d %.9g %.9g %d %d %d\n",
                  scene, tick, game.frame_state(), int(game.active_run), freeware_rng_state,
                  frame_dt, freeware_simulation_clock, game.run.seconds, game.camera.x, game.camera.y,
                  game.cursor_x, game.cursor_y, game.run.player.x, game.run.player.y,
                  game.run.health, game.run.experience, p.weapon, p.ammo, creature_spawned_count,
                  creature_pool[0].active, projectile_pool[0].active, game.terrain_sprites.at(0).x, game.terrain_sprites.at(0).y,
                  name_prompt, frag_stats, game.level_number);
    }
  }
}
