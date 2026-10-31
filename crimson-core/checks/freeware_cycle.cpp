// Drive the production 1.4.0 state machine exclusively through its normal inputs.
// The companion original-executable check consumes the row, hover and spawn output.
#include "../freeware/game.h"
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace freeware {
void play_sound(Sound) {}
} // namespace freeware
extern "C" {
extern float freeware_elapsed_seconds;
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
  freeware_elapsed_seconds = 1.25f;
  vec2f_t pos{1088, 643};
  effect_color_t tint{.4f, .8f, .6f, 1};
  assert(creature_spawn(&pos, &tint, 1) == 2);
  std::printf("spawn ");
  for (auto c : *reinterpret_cast<unsigned char (*)[sizeof(creature_t)]>(&creature_pool[2]))
    std::printf("%02x", c);
  std::puts("");
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
    table.push_back({"Oracle " + std::to_string(i), float(130 - i), 0, 5000 - i, 29, 59.75f, 120, 1.4f});
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
}
