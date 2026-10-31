#include "display.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace freeware {
constexpr float degrees = 57.2957795f;
Display::~Display() {
  for (auto &entry : textures)
    SDL_DestroyTexture(entry.second);
  SDL_DestroyTexture(ground);
  SDL_DestroyTexture(stains);
}
bool Display::load(const std::string &folder) {
  for (const char *name :
       {"font",           "grass1",       "mud1",       "ground_tile",    "crimsonland", "borg_t", "eiliens",
        "bullet_real_16", "blood",        "aim32",      "aim64",          "part64",      "reaper", "panel",
        "ui_text",        "rocket",       "flame",      "bubble",         "glow64",      "bar",    "bonus_fire",
        "bonus_freeze",   "bonus_weapon", "bonus_bomb", "bonus_timebend", "shockwave",   "icemold"}) {
    size_t bytes;
    auto *data = static_cast<unsigned char *>(SDL_LoadFile((folder + "/" + name + ".rgba").c_str(), &bytes));
    if (!data)
      return false;
    Uint32 w = 0, h = 0;
    if (bytes >= 8) {
      std::memcpy(&w, data, 4);
      std::memcpy(&h, data + 4, 4);
    }
    if (w == 0 || h == 0 || w > 2048 || h > 2048 || bytes != 8 + w * h * 4) {
      SDL_free(data);
      return SDL_SetError("Bad 1.4.0 texture %s", name);
    }
    SDL_Surface *s = SDL_CreateSurfaceFrom(w, h, SDL_PIXELFORMAT_RGBA32, data + 8, w * 4);
    SDL_Texture *texture = s ? SDL_CreateTextureFromSurface(renderer, s) : nullptr;
    SDL_DestroySurface(s);
    SDL_free(data);
    if (!texture)
      return false;
    textures.emplace(name, texture);
    SDL_SetTextureBlendMode(texture, std::strcmp(name, "part64") == 0 ? SDL_BLENDMODE_ADD : SDL_BLENDMODE_BLEND);
    SDL_SetTextureScaleMode(texture, SDL_SCALEMODE_LINEAR);
  }
  ground = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_TARGET, arena, arena);
  stains = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_TARGET, arena, arena);
  if (!stains || !ground || !SDL_SetRenderTarget(renderer, ground))
    return false;
  SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
  SDL_RenderClear(renderer);
  // Ground target build at 0x40e060 stamps rotated 128-pixel grass and mud quads.
  unsigned seed = 1;
  auto roll = [&]() {
    seed = seed * 214013u + 2531011u;
    return (seed >> 16) & 0x7fffu;
  };
  for (const char *name : {"grass1", "mud1"}) {
    const int count = arena * arena / 524288 * (name[0] == 'g' ? 700 : 35);
    for (int i = 0; i < count; ++i) {
      float rotation = (roll() % 314) * .01f;
      float x = float(roll() % (arena + 128)) - 64, y = float(roll() % (arena + 128)) - 64;
      sprite(name, x, y, 128, 128, rotation);
    }
  }
  SDL_SetTextureBlendMode(stains, SDL_BLENDMODE_BLEND);
  return SDL_SetRenderTarget(renderer, nullptr);
}
void Display::sprite(const char *name, float x, float y, float w, float h, float angle, int frame, int columns,
                     SDL_FColor tint) {
  auto *t = textures.at(name);
  float tw, th;
  SDL_GetTextureSize(t, &tw, &th);
  float cw = tw / columns, ch = th / columns;
  SDL_FRect src{(frame % columns) * cw, (frame / columns) * ch, cw, ch}, dst{x, y, w, h};
  SDL_SetTextureColorModFloat(t, tint.r, tint.g, tint.b);
  SDL_SetTextureAlphaModFloat(t, tint.a);
  SDL_RenderTextureRotated(renderer, t, &src, &dst, angle * degrees, nullptr, SDL_FLIP_NONE);
}
void Display::text(const std::string &value, float x, float y, float scale, SDL_FColor tint) {
  // Grim's pre-1.9 mono path pre-advances even the first glyph.
  float pen = x;
  for (unsigned char c : value) {
    pen += 16 * scale;
    if (c == '\n') {
      pen = x;
      y += 28 * scale;
    } else
      sprite("font", pen, y, 32 * scale, 32 * scale, 0, c, 16, tint);
  }
}
void Display::draw(const Game &g) {
  if (g.generation != ground_generation || !g.decals.empty()) {
    SDL_SetRenderTarget(renderer, stains);
    if (g.generation != ground_generation) {
      SDL_SetRenderDrawColor(renderer, 0, 0, 0, 0);
      SDL_RenderClear(renderer);
      ground_generation = g.generation;
    }
    for (const auto &c : g.decals) {
      sprite("blood", c.position.x - 16, c.position.y - 16, 32, 32, c.heading);
      sprite("eiliens", c.position.x - c.size / 2, c.position.y - c.size / 2, c.size, c.size, c.heading, 63, 8,
             {c.color.r, c.color.g, c.color.b, c.color.a});
    }
    SDL_SetRenderTarget(renderer, nullptr);
  }
  SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
  SDL_RenderClear(renderer);
  const float cx = camera_x(g), cy = camera_y(g);
  SDL_FRect field{cx, cy, arena, arena};
  SDL_SetTextureScaleMode(ground, g.smooth ? SDL_SCALEMODE_LINEAR : SDL_SCALEMODE_NEAREST);
  SDL_RenderTexture(renderer, ground, nullptr, &field);
  SDL_RenderTexture(renderer, stains, nullptr, &field);
  if (g.screen == Screen::Playing || g.screen == Screen::Dying || g.screen == Screen::Death ||
      g.screen == Screen::Perks || g.paused) {
    for (const auto &c : creature_pool) {
      if (!c.active)
        continue;
      const auto &s = c.freeware;
      const float x = cx + c.pos_x - s.size / 2, y = cy + c.pos_y - s.size / 2;
      // 0x41010d: the type-1 sheet starts at cell 32 and walks its sixteen frames in both directions.
      int cell = int(s.animation + .5f);
      if (cell > 15)
        cell = 31 - cell;
      if (c.death_timer < 16)
        cell = int(31 - c.death_timer);
      sprite("eiliens", x, y, s.size, s.size, s.heading - 1.5707964f,
             (s.type == 1 ? 32 : 0) + std::clamp(cell, 0, 31), 8, {s.color.r, s.color.g, s.color.b, s.color.a});
    }
    for (int i = 0; i < g.players(); ++i) {
      const auto &r = g.actor(i);
      if (r.health <= 0)
        continue;
      float x = cx + r.player.x - 24, y = cy + r.player.y - 24;
      SDL_FColor tint = i ? SDL_FColor{.6f, .8f, 1, 1} : SDL_FColor{1, 1, 1, 1};
      sprite("borg_t", x, y, 48, 48, r.body_angle, int(r.walk + .5f), 8, tint);
      sprite("borg_t", x + 1, y + 1, 48, 48, r.aim_angle, 16 + int(r.walk + .5f), 8, tint);
      if (r.shield > 0)
        sprite("bubble", x - 8, y - 8, 64, 64, 0, 0, 1, {.4f, .8f, 1, .6f});
    }
    for (const auto &r : secondary_projectile_pool)
      if (r.active)
        sprite("rocket", cx + r.position.x - 8, cy + r.position.y - 8, 16, 16, r.angle);
    if (g.run.pickup.time > 0) {
      auto &b = g.run.pickup;
      const char *icons[] = {"bonus_fire", "bonus_freeze", "bonus_weapon",
                             "bonus_bomb", "bubble",       "bonus_timebend"};
      float x = b.pos.x + cx, y = b.pos.y + cy;
      sprite(icons[int(b.kind)], x - 16, y - 16, 32, 32);
      if (b.kind == Bonus::Weapon)
        text(weapon_name_get(b.weapon), x + 8, y - 10, .5f, {1, 1, .7f, .9f});
    }
    if (g.run.bomb_age >= 0) {
      float size = g.run.bomb_age * 720;
      sprite("shockwave", cx + g.run.bomb_pos.x - size / 2, cy + g.run.bomb_pos.y - size / 2, size, size);
    }
    for (const auto &shot : projectile_pool) {
      if (shot.active && shot.fields.life_timer >= .4f) {
        SDL_SetRenderDrawColor(renderer, 233, 204, 137, 160);
        const float x = cx + shot.position.x, y = cy + shot.position.y;
        int kind = int(shot.fields.type_id);
        if (kind == 5 || kind == 15 || kind == 19 || kind == 7 || kind == 9 || kind == 17 || kind == 18) {
          const char *name = kind == 19 ? "bubble" : (kind == 5 || kind == 15) ? "flame" : "glow64";
          SDL_FColor color = kind == 17 ? SDL_FColor{.4f, 1, .2f, .9f} : SDL_FColor{.7f, .8f, 1, .9f};
          sprite(name, x - 9, y - 9, 18, 18, shot.angle, 0, 1, color);
          continue;
        }
        if (g.effects)
          SDL_RenderLine(renderer, x, y, x - std::sin(shot.angle) * 15, y + std::cos(shot.angle) * 15);
        sprite("bullet_real_16", x - 3, y - 3, 6, 6, shot.angle);
      }
    }
  }
  const SDL_FColor white{1, 1, 1, 1}, muted{1, 1, 1, .65f};
  char line[128];
  if (g.screen == Screen::Menu) {
    const float clock = g.menu_clock;
    sprite("crimsonland", width / 2 - 256 + std::cos(clock) * 5, 90 - 64 + std::sin(clock) * 5, 512, 512);
    for (int i = 0; i < 8; ++i) {
      const float alpha = menu_hover(g) == i ? .9f : g.selected == i ? .7f : .6f;
      const auto row = menu_row(g, i);
      text(row.label, row.x, row.y, .75435f, {1, 1, 1, alpha});
    }
    if (g.notice)
      text(g.notice, width / 2 - 220, 478, .65f, white);
    text("v1.4.0", 10, height - 25, .65435f, {1, 1, 1, .4f});
    text("2002 (c) 10tons entertainment", width - 330, height - 25, .65435f, {1, 1, 1, .4f});
  } else if (g.screen == Screen::Playing) {
    // The one-player Survival arm of 0x416a00 draws the time on the original panel.
    sprite("panel", 0, 0, 640, 64, 0, 0, 1, {.7f, .7f, .7f, 1});
    if (g.run.perks[16]) {
      int id = creature_find_in_radius(&player_state_table[0].freeware.aim, 10);
      if (id >= 0) {
        std::snprintf(line, sizeof(line), "health %d", int(creature_pool[id].health));
        text(line, g.cursor_x + 8, g.cursor_y + 8, .55f, white);
      }
    }
    if (g.survival) {
      std::snprintf(line, sizeof(line), "Seconds survived: %d", int(g.run.seconds));
      text(line, 3, 7, .7f, white);
    } else {
      for (int i = 0; i < g.players(); ++i) {
        const auto &w = player_state_table[i].freeware;
        float x = i * 490.f;
        std::snprintf(line, sizeof(line), "%s  %d/%d  %s", weapon_name_get(w.weapon), int(std::ceil(w.ammo)),
                      int(w.clip_size), w.reload > 0 ? "Reloading" : "");
        text(line, x + 4, 3, .58f, white);
        std::snprintf(line, sizeof(line), "Health %d   Experience %d   Level %d",
                      int(std::ceil(g.actor(i).health)), g.run.experience, g.run.level);
        text(line, x + 4, 24, .55f, white);
      }
      if (g.run.pending)
        text("+Level Up", width - 175, height - 50, .95f, {1, .8f, .1f, 1});
    }
  } else if (g.screen == Screen::Message) {
    text("Message:", 150, 40, .9f, white);
    std::string hint = g.message;
    size_t col = 0;
    for (char &c : hint) {
      if (c == ' ' && col > 25) {
        c = '\n';
        col = 0;
      } else
        ++col;
    }
    text(hint, 150, 90, .65f, white);
    text("(press space or left mouse button)", 150, 340, .65f, muted);
  } else if (g.screen == Screen::Perks) {
    SDL_SetRenderDrawBlendMode(renderer, SDL_BLENDMODE_BLEND);
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, 205);
    SDL_RenderFillRect(renderer, nullptr);
    text("Pick a perk!", 150, 40, 1, white);
    for (size_t i = 0; i < g.run.choices.size(); ++i)
      text(perk_name(g.run.choices[i]), 150, 94 + 27 * i, .7f, i == size_t(g.selected) ? white : muted);
    if (!g.run.choices.empty()) {
      std::string description = perk_description(g.run.choices[g.selected]);
      size_t col = 0;
      for (char &c : description) {
        if (c == ' ' && col > 32) {
          c = '\n';
          col = 0;
        } else
          ++col;
      }
      text(description, 520, 108, .68f, white);
    }
  } else if (g.screen == Screen::Dying) {
    const float fade = std::clamp(std::min(g.death_clock, 3.f - g.death_clock), 0.f, 1.f);
    sprite("reaper", width / 2 - 64, height / 2 - 64, 128, 128, 0, 0, 1, {1, 1, 1, fade});
  } else if (g.screen == Screen::Death) {
    // State 9 in 0x418190. Fade the field to black, then draw the name screen with Grim's mono font.
    const float fade = std::clamp(g.death_clock - 3.f, 0.f, 1.f);
    SDL_SetRenderDrawBlendMode(renderer, SDL_BLENDMODE_BLEND);
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, static_cast<Uint8>(255 * fade));
    SDL_RenderFillRect(renderer, nullptr);
    sprite("reaper", 10, 10, 128, 128, 0, 0, 1, {1, 1, 1, fade});
    for (int i = 0; i < 2; ++i)
      text("The Reaper got you.", 100, 50, .975435f, {.75f, .35f, .22f, .9f * fade});
    std::snprintf(line, sizeof(line), g.survival ? "Seconds survived: %d" : "Gained experience: %d",
                  g.survival ? int(g.run.seconds) : g.run.experience);
    text(line, 120, 90, .75435f, {.85f, .55f, .35f, .8f * fade});
    text("Who were you:", 10, 165, .75435f, {1, 1, 1, fade});
    text(g.name, 50, 190, 1, {1, 1, 1, fade});
    if (std::fmod(g.menu_clock, 1.f) < .5f)
      text("_", 50 + 16 * g.name.size(), 190, 1, {1, 1, 1, .4f});
    std::snprintf(line, sizeof(line), "Gained level: %d\nHit accuracy: %d%%\nFrags: %d\n", g.run.level,
                  highscore_record_shots_fired ? g.run.hits * 100 / highscore_record_shots_fired : 0, g.run.kills);
    text(line, 60, 320, .66f, white);
  } else {
    const char *heading = g.screen == Screen::Scores    ? "Highscores:"
                          : g.screen == Screen::Credits ? "Project Crimsonland"
                          : g.screen == Screen::Options ? "Game options."
                                                        : "Online options.";
    text(heading, 180, 120, 1, white);
    if (g.screen == Screen::Scores) {
      text(g.survival ? "-SURVIVAL--" : "-CAREER--", 180, 170, .75435f, white);
      for (size_t i = 0; i < std::min<size_t>(g.scores().size(), 10); ++i) {
        const auto &score = g.scores()[i];
        std::snprintf(line, sizeof(line), "%zu.  %-31s  %d", i + 1, score.name.c_str(),
                      g.survival ? int(score.seconds) : score.experience);
        text(line, 180, 210 + i * 23, .75435f, muted);
      }
    } else if (g.screen == Screen::Credits) {
      text(
          "Game coded & designed by\nTero Alatalo\n3D Art modelled by\nTimo Palonen\nMusic performed by\nValtteri "
          "Pihlajamaki",
          180, 170, .75435f, white);
    } else if (g.screen == Screen::Options) {
      if (g.rebind < 0) {
        for (int i = 0; i < 9; ++i)
          text(g.option(i), 180, 170 + i * 30, .72f, g.selected == i ? white : muted);
      } else {
        static const char *actions[] = {"forward", "backward", "left", "right", "fire"};
        std::snprintf(line, sizeof(line), "Player %d: press key for %s", g.rebind / 5 + 1, actions[g.rebind % 5]);
        text(line, 180, 200, .72f, white);
      }
    } else if (g.screen == Screen::Online) {
      text("Online highscores are offline.", 180, 170, .75435f, white);
    }
    if (g.screen != Screen::Options && g.screen != Screen::Scores)
      text("back to main menu", 180, 410, .75435f, muted);
  }
  if (g.screen == Screen::Playing) {
    sprite("aim64", g.cursor_x - 32, g.cursor_y - 32, 64, 64);
  } else if (g.screen != Screen::Dying) {
    // The menu and score cursor bind part64 additively, then the 32-pixel reticle at 64% opacity.
    const float speed = g.screen == Screen::Death ? 2.f : 1.f;
    const float light = std::cos(g.menu_clock);
    const float alpha = (light * light + 1) * .5f;
    sprite("part64", g.cursor_x - 32, g.cursor_y - 32, 64, 64);
    for (int i = 0; i < 3; ++i) {
      float angle = g.menu_clock * speed + i * 2.0943952f;
      sprite("part64", g.cursor_x - 32 + 16 * std::cos(angle), g.cursor_y - 32 + 16 * std::sin(angle), 64, 64, 0,
             0, 1, {1, 1, 1, alpha});
    }
    sprite("aim32", g.cursor_x - 16, g.cursor_y - 16, 32, 32, 0, 0, 1, {1, 1, 1, .64f});
  }
  if (g.show_fps) {
    std::snprintf(line, sizeof(line), "%.0f FPS", g.fps);
    text(line, width - 110, 4, .55f, white);
  }
  SDL_RenderPresent(renderer);
}
} // namespace freeware
