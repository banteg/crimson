// Grim draw calls in the 1.4.0 HUD (0x416a00), including its separate player-count layouts.
#include "display.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
namespace freeware {
void Display::hud(const Game &g) {
  const SDL_FColor white{1, 1, 1, 1}, backing{.4f, .4f, .4f, .8f};
  char textbuf[64];
  auto label = [&](int row, float x, float y) {
    SDL_FRect source{0, float(row * 50), 256, 50}, dest{x, y, 256, 50};
    auto *t = textures.at("ui_text");
    SDL_RenderTexture(renderer, t, &source, &dest);
  };
  if (!g.two_players)
    sprite("bar", 0, 0, 640, 64, 0, 0, 1, {.7f, .7f, .7f, 1});
  for (int i = 0; i < g.players(); ++i) {
    const auto &gun = player_state_table[i].freeware;
    float health = std::clamp(g.actor(i).health / 100, 0.f, 1.f);
    float health_y = g.two_players ? 15 + i * 20 : 35;
    sprite("bullet", 10, health_y, 140, 15, 0, 0, 1, backing);
    sprite("bullet", 12, health_y + 2, 12 + 124 * health, 11, 0, 0, 1, {.38f, .04f, .04f, .9f});
    if (g.survival)
      continue;
    if (health > 0) {
      float bullets = gun.clip_size * (g.run.perks[11] ? 1.2f : 1.f);
      float stride = bullets > 30 ? 30 / bullets : 1;
      float y = g.two_players ? 10 + i * 20 : 16;
      for (int j = 0; j < int(bullets); ++j)
        sprite("bullet_real_16", 320 + j * 10 * stride, y, 16 * stride, g.two_players ? 18 : 22, 0, 0, 1,
               {1, 1, 1, j < int(gun.ammo) ? .7f : .3f});
    }
    float y = g.two_players ? 2 + i * 48 : 5;
    sprite("bullet", 320, y, 310, 6, 0, 0, 1, backing);
    if (gun.reload > 0 && gun.reload_duration > 0)
      sprite("bullet", 322, y + 2, 12 + 294 * std::clamp(gun.reload / gun.reload_duration, 0.f, 1.f), 2, 0, 0, 1,
             {.04f, .04f, .38f, .9f});
    text(weapon_name_get(gun.weapon), g.two_players ? 150 : 12, g.two_players ? 12 + i * 20 : 55,
         g.two_players ? .57f : .67f, white);
  }
  if (g.survival) {
    std::snprintf(textbuf, sizeof(textbuf), "Seconds survived: %d", int(g.run.seconds));
    text(textbuf, 3, 7, .7f, white);
  } else if (!g.two_players) {
    label(2, -3, -6);
    std::snprintf(textbuf, sizeof(textbuf), "%d", g.run.experience);
    text(textbuf, 220, 7, .7f, {0, 0, 0, 1});
    text(textbuf, 220, 7, .7f, {.8f, .1f, .1f, 1});
  } else {
    std::snprintf(textbuf, sizeof(textbuf), "xp: %d", g.run.experience);
    text(textbuf, 6, 55, .57f, white);
  }
  if (g.run.pending)
    label(0, width - 240, height - 50);
  if (g.run.perks[16]) {
    int id = creature_find_in_radius(&player_state_table[0].freeware.aim, 10);
    if (id >= 0) {
      std::snprintf(textbuf, sizeof(textbuf), "health %d", int(creature_pool[id].health));
      text(textbuf, g.cursor_x + 8, g.cursor_y + 8, .55f, white);
    }
  }
}

// The credits renderer at 0x41e330 uses fixed 18-pixel line spacing with intentional gaps.
void Display::credits(float clock) {
  struct Line {
    float y;
    const char *name;
  };
  static const Line lines[] = {
      {0, "Project Crimsonland"},
      {18, "----credits--------"},
      {72, "Game coded & designed by"},
      {90, "Tero Alatalo"},
      {144, "3D Art modelled by"},
      {162, "Timo Palonen"},
      {216, "Music performed by"},
      {234, "Valtteri Pihlajamaki"},
      {288, "2D Art drawn by"},
      {306, "Tero Alatalo"},
      {360, "Using Grim API & SFX API by"},
      {378, "Tero Alatalo"},
      {432, "Additional Perk coordinators"},
      {450, "Wille Mantyla"},
      {0, "Beta testers / thanks / greets"},
      {558, "                (alphabetical)"},
      {576, "Armas"},
      {594, "crud"},
      {612, "epaz"},
      {630, "exi"},
      {648, "Jayzon"},
      {666, "KySSe"},
      {684, "lore"},
      {702, "matricks"},
      {720, "milzer"},
      {738, "monotonic"},
      {756, "muzzy"},
      {774, "PornReindeer"},
      {792, "Outolintu"},
      {810, "Quarot"},
      {828, "Skele"},
      {846, "Strombo"},
      {882, "TeLa"},
      {900, "Tieom"},
      {918, "Ukuli"},
      {936, "Vulderi"},
      {954, "Wiltsu"},
      {972, "Womba!"},
      {990, "+ you guys at Pelit.fi and MuroPaketti.com"},
      {1008, "+ the ones I forgot :)"},
      {1062, "http://crimsonland.10tons.org"},
      {1134, "2002 (c) 10tons entertainment"},
      {1152, "    http://www.10tons.org"},
      {1170, "     (10tons logo by pHx)"},
  };
  SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
  SDL_RenderClear(renderer);
  float top = height - clock * 48;
  for (auto &line : lines)
    if (top + line.y >= -30 && top + line.y < height)
      text(line.name, 50, top + line.y, .76f, {1, 1, 1, .68f});
}
} // namespace freeware
