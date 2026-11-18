// Drive the production 1.4.0 state machine exclusively through its normal inputs.
// The companion original-executable check consumes the row, hover and spawn output.
#include "../freeware/game.h"
#include "freeware_frame_input.h"
#include "freeware_timing.h"
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace freeware {
void play_sound(Sound) {}
void play_original_sample(int) {}
} // namespace freeware
extern "C" {
extern float freeware_elapsed_seconds;
extern unsigned char perk_choice_flags[48];
extern int creature_spawned_count;
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
}
int main() {
  using namespace freeware;
  Game game;
  Input in;
  auto step = [&] { game.update(1.f / 60, in); };
  auto click = [&](float x, float y) {
    in.x = x;
    in.y = y;
    in.click = true;
    step();
    in.click = false;
    step();
  };
  click(480, 278);
  assert(game.survival && game.screen == Screen::Menu);
  for (int i = 0; i < 8; ++i) {
    const auto row = menu_row(game, i);
    std::printf("row %.0f %.0f %s\n", row.x, row.y, row.label);
    for (float delta : {0.f, 1.f, float(std::strlen(row.label) * 16 - 1), float(std::strlen(row.label) * 16)}) {
      game.cursor_x = row.x + delta;
      game.cursor_y = row.y + 1;
      std::printf("hover %.0f %.0f %d\n", game.cursor_x, game.cursor_y, menu_hover(game));
    }
  }
  // Poison untouched fields, force slot 2 and check all 128 bytes against the PE.
  std::memset(creature_pool, 0x5a, sizeof(creature_pool));
  creature_pool[2].active = 0;
  seed_random(1);
  freeware_elapsed_seconds = 1.25f;
  vec2f_t pos{1088, 643};
  effect_color_t tint{.4f, .8f, .6f, 1};
  assert(creature_spawn(&pos, &tint, 1) == 2);
  std::printf("spawn ");
  for (auto c : *reinterpret_cast<unsigned char (*)[sizeof(creature_t)]>(&creature_pool[2]))
    std::printf("%02x", c);
  std::puts("");
  // The allocation probe poisons even the animation phase retained on slot reuse.
  std::memset(creature_pool, 0, sizeof(creature_pool));
  click(460, 210);
  assert(game.screen == Screen::Playing && game.generation == 1);
  in.up = true;
  for (int i = 0; i < 18; ++i)
    step();
  in.up = false;
  assert(game.run.player.y < arena * .5f);
  for (int i = 0; i < 60 * 60 && game.screen == Screen::Playing; ++i) {
    const creature_t *closest = nullptr;
    float nearest = 1e10f;
    for (const auto &c : creature_pool) {
      if (!c.active || c.health <= 0)
        continue;
      float d = std::hypot(c.pos_x - game.run.player.x, c.pos_y - game.run.player.y);
      if (d < nearest) {
        closest = &c;
        nearest = d;
      }
    }
    in.fire = !game.run.kills && closest;
    if (in.fire) {
      in.x = closest->pos_x + camera_x(game);
      in.y = closest->pos_y + camera_y(game);
    }
    step();
  }
  assert(game.screen == Screen::Dying);
  in.fire = false;
  for (int i = 0; i < 181; ++i)
    step();
  assert(game.screen == Screen::Death && game.run.kills > 0 && game.run.health <= 0);
  in.fire = false;
  in.text = "Player";
  step();
  in.text.clear();
  in.accept = true;
  step();
  in.accept = false;
  assert(game.screen == Screen::Scores);
  in.escape = true;
  step();
  in.escape = false;
  for (int n = 0; n < 30 && game.screen == Screen::Scores; ++n)
    step();
  assert(game.screen == Screen::Menu);
  click(460, 210);
  assert(game.screen == Screen::Playing && game.generation == 2 && game.run.health == 100);
  assert(game.run.kills == 0 && highscore_record_shots_fired == 0 && creature_spawned_count == 2);

  // Both player counts can start Career through Begin, with independent movement and firing.
  Game career;
  Input keys;
  keys.accept = true;
  career.update(1.f / 60, keys);
  keys.accept = false;
  assert(!career.survival && career.screen == Screen::Playing);
  assert(player_state_table[0].freeware.weapon == 1 && player_state_table[0].freeware.ammo == 10);
  for (unsigned seed : {1, 7, 39, 131, 219, 901, 1975, 4132, 6543}) {
    std::memset(creature_pool, 0, sizeof(creature_pool));
    seed_random(seed);
    career.run.experience = 1731;
    career.spawn_career();
    std::printf("career %u ", seed);
    auto &c = creature_pool[0];
    assert(c.active);
    for (auto b : *reinterpret_cast<unsigned char (*)[sizeof(c)]>(&c))
      std::printf("%02x", b);
    std::puts("");
  }
  for (int players : {1, 2}) {
    Game g;
    g.two_players = players == 2;
    g.start();
    keys = {};
    for (int i = 0; i < players; ++i) {
      auto &w = player_state_table[i].freeware;
      for (int id = 1; id <= 20; ++id) {
        freeware_secret_weapon_unlocked = 1;
        weapon_assign_player(i, id);
        std::printf("weapon %d %d %.0f %s\n", i, id, w.ammo, weapon_name_get(id));
      }
      weapon_assign_player(i, 1);
    }
    keys.right = true;
    keys.up2 = true;
    keys.fire = keys.fire2 = true;
    for (int i = 0; i < 180; ++i)
      g.update(1.f / 60, keys);
    assert(g.run.player.x > 512 && player_state_table[0].freeware.ammo < 15);
    if (players == 2)
      assert(g.run.partner.player.y < 512 && player_state_table[1].freeware.ammo < 15);
    keys = {};
    g.run.pickup = {g.run.player, Bonus::Weapon, 10, 12};
    g.update(1.f / 60, keys);
    assert(player_state_table[0].freeware.weapon == 12);
    auto &gun = player_state_table[0].freeware;
    gun.ammo = 1;
    g.run.cooldown = 0;
    keys.fire = true;
    g.update(1.f / 60, keys);
    keys.fire = false;
    assert(gun.reload > 0 && secondary_projectile_pool[0].active);
    for (int i = 0; i < 150; ++i)
      g.update(1.f / 60, keys);
    assert(gun.reload == 0 && gun.ammo == gun.clip_size);
    g.run.experience = g.next_level_xp() + 1;
    g.update(1.f / 60, keys);
    assert(g.run.pending && g.run.level == 2);
    keys.level_up = true;
    g.update(1.f / 60, keys);
    keys.level_up = false;
    assert(g.screen == Screen::Perks && g.run.choices.size() == 5);
    int picked = g.run.choices[0];
    keys.accept = true;
    g.update(1.f / 60, keys);
    keys.accept = false;
    assert(g.screen == Screen::Playing && g.run.perks[picked]);
    if (g.two_players) {
      g.run.health = 0;
      g.update(1.f / 60, keys);
      assert(g.screen == Screen::Playing);
      g.run.partner.health = 0;
    } else
      g.run.health = 0;
    g.update(1.f / 60, keys);
    assert(g.screen == Screen::Dying);
  }
  std::vector<Score> table;
  for (int i = 0; i < 6; ++i)
    table.push_back({"Oracle " + std::to_string(i), 130 - i, 0, 5000 - i, 29, 59.75f, 120, 1.4f});
  for (int i = 0; i < 4; ++i) {
    auto bytes = encode_scores(table, i);
    std::printf("scores %d ", i);
    for (auto b : bytes)
      std::printf("%02x", b);
    std::puts("");
    std::vector<Score> decoded;
    assert(decode_scores(bytes, i, decoded) && decoded.size() == table.size());
    assert(encode_scores(decoded, i) == bytes);
    bytes[7] ^= 1;
    assert(!decode_scores(bytes, i, decoded));
  }

  for (int level : {3, 5, 8, 13, 17}) {
    Game g;
    g.start();
    std::memset(creature_pool, 0, sizeof(creature_pool));
    creature_pool[0].ai_mode = 1;
    seed_random(1234);
    g.run.level = level - 1;
    g.run.experience = g.next_level_xp() + 2;
    g.check_level();
    assert(g.run.level == level && g.run.pending == 1 && creature_pool[0].active);
    std::printf("levelroll %d %d ", level, crt_rand());
    for (unsigned char flag : perk_choice_flags)
      std::printf("%02x", flag);
    std::puts("");
    std::printf("boss %d %d ", level, g.run.experience);
    for (auto c : *reinterpret_cast<unsigned char (*)[sizeof(creature_t)]>(&creature_pool[0]))
      std::printf("%02x", c);
    std::puts("");
  }
  // Compare the chooser's draws, including the next RNG value, for every eligibility policy.
  for (int mode = 0; mode < 8; ++mode)
    for (int seed : {1, 42, 431, 1987}) {
      Game g;
      g.two_players = mode & 1;
      g.secret_hints = mode & 2;
      g.start();
      g.run.pending = 1;
      g.run.perks[1] = g.run.perks[4] = 1;
      g.run.perks[25] = (mode & 4) != 0;
      seed_random(seed);
      g.open_perks();
      std::printf("choices %d %d %d", mode, seed, crt_rand());
      for (auto id : g.run.choices)
        std::printf(" %d", id);
      std::puts("");
    }
  for (int id = 1; id <= 20; ++id) {
    Game g;
    g.start();
    freeware_secret_weapon_unlocked = 1;
    weapon_assign_player(0, id);
    auto &w = player_state_table[0].freeware;
    g.run.health = 4;
    w.ammo = 10;
    g.run.aim_angle = 1.5707964f;
    g.run.cooldown = 0;
    seed_random(42);
    freeware_rainbow_enabled = freeware_rainbow_armed = 1;
    Input trigger;
    trigger.fire = true;
    g.step_player(0, 1.f / 60, trigger, {712, 512});
    std::printf("volley %d %.6f %.3f", id, g.run.cooldown, w.ammo);
    for (const auto &shot : projectile_pool)
      if (shot.active)
        std::printf(" b%d", int(shot.fields.type_id));
    for (const auto &r : secondary_projectile_pool)
      if (r.active)
        std::printf(" r%d", int(r.fields.type_id));
    for (const auto &part : particle_pool)
      if (part.active)
        std::printf(" p%d", int(part.style_id));
    std::puts("");
  }
  Game g;
  Input input;
  input.accept = true;
  g.update(1.f / 60, input);
  input = {};
  seed_random(42);
  bool picked = false, leveled = false;
  int gun = 1;
  for (int n = 0; n < 60 * 300 && g.screen == Screen::Playing; ++n) {
    const auto &p = g.run.player;
    const creature_t *closest = nullptr;
    float distance = 1.e9f;
    for (auto &c : creature_pool)
      if (c.active && c.health > 0) {
        float d = std::hypot(c.pos_x - p.x, c.pos_y - p.y);
        if (d < distance) {
          distance = d;
          closest = &c;
        }
      }
    input = {};
    if (closest) {
      input.x = closest->pos_x + camera_x(g);
      input.y = closest->pos_y + camera_y(g);
      input.fire = true;
    }
    vec2f_t target{512.f + 325.f * std::cos(n * .0034f), 512.f + 325.f * std::sin(n * .0034f)};
    if (g.run.pickup.time > 0 && distance > 85)
      target = g.run.pickup.pos;
    input.left = target.x < p.x - 5;
    input.right = target.x > p.x + 5;
    input.up = target.y < p.y - 5;
    input.down = target.y > p.y + 5;
    if (g.run.pending)
      input.level_up = true;
    g.update(1.f / 60, input);
    if (g.screen == Screen::Perks) {
      leveled = true;
      input = {};
      input.accept = true;
      g.update(1.f / 60, input);
    }
    if (player_state_table[0].freeware.weapon != gun) {
      gun = player_state_table[0].freeware.weapon;
      picked = true;
    }
    if (picked && leveled) {
      std::printf("Natural Career: %d kills, %d XP, level %d, %s at %.1fs\n", g.run.kills, g.run.experience,
                  g.run.level, weapon_name_get(gun), g.run.seconds);
      break;
    }
  }
  assert(picked && leveled);
  check_screenshot_input();
  for (bool console : {false, true}) {
    Game exit_game;
    exit_game.console_open = console;
    Input held;
    held.quit_chord = true;
    exit_game.update(1.f / 60, held);
    assert(exit_game.quit);
    std::printf("quit-chord %d %d\n", console, exit_game.quit);
    assert(exit_game.fps_count == 0);
  }


  check_freeware_timing();
}
