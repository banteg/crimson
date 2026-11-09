#include "../freeware/game.h"
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>

void check_arsenal();
void check_weapon_hits();
void check_early_perks();
void check_player_perks();
void check_creature_perks();
void check_live_picker();
void check_flames_and_rockets();
void check_random_spawns();
void check_player_motion();
void check_creature_motion();
void check_credits();
void check_early_frames(const char *assets);
void check_early_hud();
void check_early_name();
void check_name_edit_130();
void check_early_menu();
void check_early_fx_writes();
extern "C" {
extern float freeware_elapsed_seconds;
extern unsigned freeware_rng_state;
extern game_mode_id_t config_game_mode;
extern int freeware_pickup_id, freeware_pickup_weapon;
extern float freeware_pickup_time;
void player_render();
}

static void check_weapon_pickups() {
  using namespace freeware;
  Game game;
  game.two_players = true;
  game.start();
  FrameGameScope scope(game);
  auto collect = [&](unsigned seed, int who, int held) {
    current_player_index = who;
    weapon_assign_player(who, held);
    seed_random(seed);
    auto pos = game.actor(who).player;
    bonus_spawn_at(&pos);
    game.run.pickup = {pos, static_cast<Bonus>(freeware_pickup_id), freeware_pickup_time, freeware_pickup_weapon};
    player_render();
    const auto &p = player_state_table[who].freeware;
    std::printf("weaponpickup %u %d %d %d %g %g %u\n", seed, who, held, p.weapon, p.ammo, p.clip_size,
                freeware_rng_state);
  };
  for (unsigned seed = 1; seed <= 128; ++seed)
    collect(seed, seed % 2, 1);
  collect(12, 1, 2); // Seed 12 first rolls the held AutoRifle, then rerolls.
}

static void check_weapon_triggers(freeware::Game &game, int custom, int requested) {
  auto &map = *freeware_current_map;
  std::printf("mapweapons %d %d %d", custom, requested, game.level_number);
  for (auto it = map.triggers.begin; it != map.triggers.end; ++it)
    if ((*it)->type == 2) std::printf(" %d", (*it)->weapon);
  std::puts("");
  for (auto it = map.triggers.begin; it != map.triggers.end; ++it) {
    auto &trigger = **it;
    if (trigger.type != 2) continue;
    auto &p = player_state_table[0].freeware;
    for (int step = 0; step < 3; ++step) {
      game.run.player = {trigger.position.x + trigger.radius - (step != 0), trigger.position.y};
      if (step == 2) p.ammo -= .5f; // Staying inside a spent trigger must not refill it.
      game.update(0.f, {});
      std::printf("mapgrant %d %d %d %d %g %g %d\n", custom, requested, step, p.weapon, p.ammo, p.clip_size,
                  trigger.enabled);
    }
  }
}

static void check_deaths() {
  using namespace freeware;
  for (bool survival : {false, true}) {
    for (int xp : {6, 66, 666, 6666, 667}) {
      Game game;
      game.survival = survival;
      game.start();
      weapon_assign_player(0, survival ? 2 : 4);
      game.run.experience = xp;
      game.run.health = -1;
      game.update(1.f / 60, {});
      std::printf("deathcheck %d %d %d %g %d\n", survival ? 2 : 1, xp, game.frame_state(),
                  game.run.health, player_state_table[0].freeware.weapon);
    }
  }
}

// Use the same menu and frame entry points as SDL. Stop firing after the first kill.
static void play_cycle(bool survival) {
  using namespace freeware;
  Game game;
  Input input;
  // The 1.3.0 score writer averages 50 distinct consecutive FPS readings.
  unsigned tick = 0;
  auto step = [&] { game.update(1.f / (59 + (++tick & 1)), input); };
  auto click = [&](int row) {
    auto item = menu_row(game, row);
    input.x = item.x + 8;
    input.y = item.y + 8;
    input.click = true;
    step();
    input.click = false;
    step();
  };
  seed_random(42);
  if (survival)
    click(FREEWARE_EDITION == 10002 ? 1 : 2);
  click(0);
  assert(game.survival == survival && game.screen == Screen::Playing);
  if (survival)
    assert(creature_spawned_count == (FREEWARE_EDITION == 10002 ? 1 : 2));
  else
    assert(player_state_table[0].freeware.ammo == (FREEWARE_EDITION == 10002 ? 30 : 10));
  for (int frame = 0; frame < 120 * 60 && game.screen == Screen::Playing; ++frame) {
    float nearest = 1e10f;
    input.fire = false;
    if (!game.run.kills) {
      for (const auto &c : creature_pool) {
        float d = std::hypot(c.pos_x - game.run.player.x, c.pos_y - game.run.player.y);
        if (c.active && c.health > 0 && d < nearest) {
          nearest = d;
          input.x = c.pos_x + camera_x(game);
          input.y = c.pos_y + camera_y(game);
          input.fire = true;
        }
      }
    }
    step();
  }
  assert(game.run.kills > 0 && game.screen == (FREEWARE_EDITION == 10002 ? Screen::Death : Screen::Dying));
  input.fire = false;
  for (int n = 0; n < 240 && game.screen == Screen::Dying; ++n)
    step();
  assert(game.screen == Screen::Death);
  input.text = "Oracle";
  step();
  input.text.clear();
  input.accept = true;
  step();
  input.accept = false;
  assert(game.screen == (FREEWARE_EDITION == 10002 ? Screen::Menu : Screen::Scores) && !game.scores().empty());
  input.escape = true;
  step();
  input.escape = false;
  for (int n = 0; n < 60 && game.screen == Screen::Scores; ++n)
    step();
  assert(game.screen == Screen::Menu);
  click(0);
  assert(game.generation == 2 && !game.run.kills && game.run.health == 100);
}

int main(int argc, char **argv) {
  using namespace freeware;
  assert(argc == 2);
  check_arsenal();
  check_weapon_hits();
  check_early_perks();
  check_player_perks();
  check_creature_perks();
  check_live_picker();
  check_flames_and_rockets();
  check_deaths();
  check_random_spawns();
  check_early_fx_writes();
  check_player_motion();
  check_creature_motion();
  check_credits();
  check_early_frames(argv[1]);
  if (FREEWARE_EDITION == 10002) {
    check_early_hud();
    check_early_name();
  } else {
    check_name_edit_130();
  }
  check_early_menu();
  Game g;
  g.asset_dir = argv[1];
  g.load_level_brushes();
  const bool earliest = FREEWARE_EDITION == 10002;
  play_cycle(false);
  play_cycle(true);
  Input in;
  auto step = [&] { g.update(1.f / 60, in); };
  auto click = [&](int row) {
    auto item = menu_row(g, row);
    in.x = item.x + 8;
    in.y = item.y + 8;
    in.click = true;
    step();
    in.click = false;
    step();
  };
  assert(!std::strcmp(menu_row(g, main_row_count - 1).label, "End."));
  if (!earliest) {
    check_weapon_pickups();
    for (int key : {15, 8, 25, 8, 15, 22}) {
      in.ctrl = true;
      in.key = key;
      step();
    }
    in.ctrl = false;
    in.key = 0;
    click(2);
    click(2);
    assert(g.level_mode == 3);
    click(0);
    assert(g.screen == Screen::Playing);
    const int triggers[] = {3, 22, 7, 14};
    const int walls[] = {28, 51, 62, 0};
    for (int n = 0; n < 5; ++n) {
      int index = n % 4;
      assert(g.level_number == index + 1);
      assert(freeware_current_map->triggers.size() == triggers[index]);
      assert(freeware_current_map->layers[1].size() == walls[index]);
      assert(g.run.player.x == freeware_current_map->start.x);
      check_weapon_triggers(g, 0, n + 1);
      FrameGameScope scope(g);
      g.load_next_level();
    }
    for (int id : {16, 17}) {
      g.save_dir = "weapon-tests/" + std::to_string(id) + "/";
      g.level_number = 4;
      {
        FrameGameScope scope(g);
        g.load_next_level();
      }
      check_weapon_triggers(g, id, 5);
    }
  }

  if (!earliest) {
    FrameGameScope scope(g);
    freeware_current_map->clear();
    auto *wall = new freeware_level_object{};
    wall->position = {106, 90};
    wall->width = 10;
    wall->height = 20;
    freeware_current_map->add_object(1, wall);
    for (unsigned seed : {1u, 12u, 53u}) {
      std::memset(creature_pool, 0, sizeof(creature_pool));
      std::memset(projectile_pool, 0, sizeof(projectile_pool));
      seed_random(seed);
      vec2f_t start = {100, 100};
      projectile_spawn(&start, 1.57079637f, 1);
      frame_dt = 1.f / 60;
      projectile_update();
      for (int i = 0; i < 2; ++i) {
        const auto &p = projectile_pool[i];
        std::printf("wall %u %d %d %.9g %.9g %.9g %u\n", seed, i, p.active, p.pos_x, p.position.y,
                    p.fields.life_timer, freeware_rng_state);
      }
    }
    freeware_current_map->clear();
  }
  const vec2f_t positions[] = {{1024, 512}, {1024, 512}, {512, 512}, {550, 512}, {558, 512}};
  const effect_color_t tint = {.25f, .5f, .75f, 1};
  for (int mode : {2, 3}) {
    if (earliest && mode == 3)
      continue;
    for (unsigned seed : {1u, 43u, 12345u}) {
      std::memset(creature_pool, 0, sizeof(creature_pool));
      config_game_mode = static_cast<game_mode_id_t>(mode);
      creature_spawned_count = 0;
      freeware_elapsed_seconds = 12.5f;
      seed_random(seed);
      for (auto pos : positions) {
        int slot = creature_spawn(&pos, &tint, 1);
        std::printf("spawn %d %u %.0f %.0f %d %d %u", mode, seed, pos.x, pos.y, slot, creature_spawned_count,
                    freeware_rng_state);
        if (slot >= 0) {
          const auto &c = creature_pool[slot];
          std::printf(" %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g", c.pos_x, c.pos_y,
                      c.health, c.freeware.heading, c.freeware.move_speed, c.freeware.size, c.freeware.reward,
                      c.freeware.contact_damage, c.freeware.color.r, c.freeware.color.g, c.freeware.color.b,
                      c.freeware.color.a);
        }
        std::puts("");
      }
    }
  }
}
