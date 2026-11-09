#include "../freeware/game.h"
#include <cassert>
#include <cstdio>
#include <cstring>

extern "C" {
extern int perk_id_count;
extern unsigned freeware_rng_state;
extern unsigned char perk_choice_flags[48], freeware_spawn_enabled;
extern game_mode_id_t config_game_mode;
}

static void string_hex(const char *s) {
  for (; *s; ++s)
    std::printf("%02x", static_cast<unsigned char>(*s));
}

static unsigned flags(const int *stacks) {
  unsigned mask = 0;
  for (int i = 0; i <= perk_id_count; ++i)
    if (stacks[i])
      mask |= 1u << i;
  return mask;
}

void check_early_perks() {
  using namespace freeware;
  const bool early = FREEWARE_EDITION == 10002;
  for (int id = 0; id <= perk_id_count; ++id) {
    std::printf("meta %d ", id);
    string_hex(perk_name(id));
    std::putchar(' ');
    string_hex(perk_description(id));
    std::puts("");
    for (int coop = 0; coop <= int(!early); ++coop) {
      Game g;
      g.two_players = coop != 0;
      g.run.pending = 2;
      g.run.level = 4;
      g.run.experience = 800;
      g.run.health = 60;
      g.screen = Screen::Perks;
      g.run.choices.push_back(id);
      std::memset(player_state_table, 0, sizeof(player_state_table));
      std::memset(perk_choice_flags, 0, 48);
      perk_choice_flags[id] = 1;
      Input in;
      in.click = true;
      in.x = 60;
      in.y = 90;
      g.update(1.f / 60, in);
      std::printf("grant %d %d %d %d %d %.9g %d %u %u %d\n", id, coop, g.screen == Screen::Playing, g.run.level,
                  g.run.experience, g.run.health, g.run.pending, flags(g.run.perks.data()), flags(player_state_table[1].freeware.perks),
                  player_state_table[0].freeware.plaguebearer);
    }
  }
  for (unsigned seed : {1u, 11u, 42u, 163u, 7189u, 34953u}) {
    for (int coop = 0; coop <= int(!early); ++coop) {
      for (int mix = 0; mix < 3; ++mix) {
        Game g;
        g.two_players = coop != 0;
        g.run.pending = 1;
        for (int i = 0; i <= perk_id_count; ++i)
          if (mix && i % 3 == 1)
            g.run.perks[i] = 1;
        if (!early)
          g.run.perks[freeware_rules::perk_expert] = mix;
        seed_random(seed);
        g.open_perks();
        unsigned choices = 0;
        for (int id : g.run.choices)
          choices |= 1u << id;
        std::printf("choice %u %d %d %u %u %u\n", seed, coop, mix, flags(g.run.perks.data()), choices,
                    freeware_rng_state);
      }
    }
  }
  for (int level : {2, 3, 5, 8, 13, 17}) {
    for (int above : {0, 1}) {
      Game g;
      g.run.level = level - 1;
      g.run.experience = g.next_level_xp() + above;
      config_game_mode = static_cast<game_mode_id_t>(1);
      freeware_spawn_enabled = 1;
      memset(creature_pool, 0, sizeof(creature_pool));
      memset(perk_choice_flags, 0, 48);
      seed_random(123);
      g.check_level();
      const auto &c = creature_pool[0];
      unsigned choices = 0;
      for (int i = 0; i <= perk_id_count; ++i)
        if (perk_choice_flags[i]) choices |= 1u << i;
      std::printf("level %d %d %d %d %u %u %u %.9g %.9g\n", level - 1, g.run.experience, g.run.level,
                  g.run.pending, choices, freeware_rng_state, c.active, c.health, c.freeware.reward);
    }
  }
}

extern "C" { extern float freeware_simulation_clock; void player_reset_all(); }
void check_player_perks() {
  using namespace freeware;
  const bool early = FREEWARE_EDITION == 10002;
  for (int scenario = 0; scenario < 10; ++scenario) {
    if (!early && scenario >= 4 && scenario <= 8)
      continue;
    Game g;
    g.movement[0] = 1;
    g.run.experience = scenario == 6 ? 0 : 1500;
    g.run.speed_scale = scenario == 4 ? .32f : .9f;
    g.run.cooldown = .5f;
    g.run.berserk = scenario == 9 ? 12 : 0;
    g.run.player = {512, 512};
    g.run.health = 80;
    config_game_mode = static_cast<game_mode_id_t>(scenario == 8 ? 2 : 1);
    player_reset_all();
    auto &p = player_state_table[0].freeware;
    p.aim = {712, 512};
    p.perks[freeware_rules::long_distance_runner] = scenario < 3;
    if (early) p.perks[freeware_rules::timebender] = scenario >= 4 && scenario <= 6;
    p.move_speed = scenario == 1 ? 1.98f : scenario == 2 ? 3.95f : 0.f;
    p.heading = .5f;
    if (scenario == 9) g.run.cooldown = 0;
    std::memset(creature_pool, 0, sizeof(creature_pool));
    std::memset(projectile_pool, 0, sizeof(projectile_pool));
    seed_random(123);
    freeware_simulation_clock = .75f;
    Input in{};
    in.up = scenario <= 3;
    in.bend_time = scenario >= 4 && scenario <= 8 && scenario != 5;
    in.x = 712;
    in.y = 512;
    g.step_player(0, .1f, in, {712, 512});
    std::printf("playerperk %d %d %.9g %.9g %.9g %.9g %.9g %.9g %u\n", scenario, g.run.experience, p.position.x, p.position.y,
                p.move_speed, p.heading, p.cooldown, g.run.speed_scale, freeware_rng_state);
  }
}

void check_creature_perks() {
  using namespace freeware;
  for (int n = 0; n < 7; ++n) {
    Game g;
    g.active_run = true;
    g.run.experience = 500;
    g.run.player = {512, 512};
    g.run.health = 100;
    player_reset_all();
    config_game_mode = static_cast<game_mode_id_t>(2);
    current_player_index = 0;
    plaguebearer_infection_count = 0;
    creature_spawned_count = 1;
    std::memset(creature_pool, 0, sizeof(creature_pool));
    auto &p = player_state_table[0].freeware;
    p.perks[freeware_rules::almost_invisible] = n == 1;
    p.perks[freeware_rules::radioactive] = n == 2;
    p.plaguebearer = n == 3 || n == 4;
    auto &c = creature_pool[0];
    c.active = 1;
    c.position = {p.plaguebearer ? 528.f : 575.f, 512};
    c.hit_flash_timer = -1;
    c.health = n == 4 ? 200.f : n == 6 ? 2.f : 80.f;
    c.death_timer = 16;
    c.plague_infected = n >= 5;
    c.freeware.size = 48;
    c.freeware.attack_cooldown = 1;
    c.freeware.reward = 121;
    seed_random(76);
    freeware_simulation_clock = .75f;
    g.update_creatures(.1f);
    std::printf("creatureperk %d %.9g %.9g %.9g %.9g %.9g %d %d %d %u\n", n, c.health, c.death_timer,
                c.anim_phase, c.freeware.target.x, c.freeware.target.y, c.plague_infected,
                plaguebearer_infection_count, g.run.experience, freeware_rng_state);
  }
}

// Outcomes of successive frames through 1.0.2 crimson.exe's perk prompt and grim.dll's key latch.
static void check_keypad_perk() {
  using namespace freeware;
  Game game;
  game.start();
  game.run.next_spawn = 100;
  auto frame = [&](bool pending, bool down) {
    game.screen = Screen::Playing;
    game.run.pending = pending;
    Input input;
    input.keypad_plus_down = down;
    game.update(.016f, input);
    return game.screen == Screen::Perks;
  };
  assert(!frame(false, true));
  assert(!frame(true, true));  // A first query with the key already held finds the native latch unarmed.
  assert(!frame(true, false));
  assert(!frame(false, true));
  assert(frame(true, true));  // The eligible frame observes the press, even after SDL_KEYDOWN.
  assert(!frame(true, true));
  assert(!frame(false, false));
  assert(!frame(true, true));  // An unobserved release and repress cannot rearm the latch.
  assert(!frame(true, false));
  assert(frame(true, true));
}

void check_live_picker() {
  using namespace freeware;
  if (FREEWARE_EDITION == 10002)
    check_keypad_perk();
  for (unsigned seed : {42u, 1043u, 87611u}) {
    Game g;
    g.safe_mode = true;
    g.start();
    g.run.pending = 1;
    g.run.next_spawn = 100;
    g.run.cooldown = .5f;
    g.camera_timer = 100;
    std::memset(particle_pool, 0, sizeof(particle_pool));
    std::memset(secondary_projectile_pool, 0, sizeof(secondary_projectile_pool));
    seed_random(seed);
    Input in{};
    in.level_up = true;
    g.update(1.f / 60, in);
    unsigned mask = 0;
    for (int id : g.run.choices) mask |= 1u << id;
    std::printf("livepick %u %d %u %u\n", seed, g.screen == Screen::Perks, mask, freeware_rng_state);
  }
}
