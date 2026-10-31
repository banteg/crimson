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
  for (const char *name : {"font", "grass1", "mud1", "ground_tile", "crimsonland", "borg_t", "eiliens",
                           "bullet_real_16", "blood", "aim32", "aim64", "part64", "reaper", "panel", "ui_text"}) {
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
  SDL_RenderTexture(renderer, ground, nullptr, &field);
  SDL_RenderTexture(renderer, stains, nullptr, &field);
  if (g.screen == Screen::Playing || g.screen == Screen::Dying || g.screen == Screen::Death || g.paused) {
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
      sprite("eiliens", x, y, s.size, s.size, s.heading - 1.5707964f, 32 + std::clamp(cell, 0, 31), 8,
             {s.color.r, s.color.g, s.color.b, s.color.a});
    }
    const auto &r = g.run;
    if (r.health > 0) {
      float x = cx + r.player.x - 24, y = cy + r.player.y - 24;
      sprite("borg_t", x, y, 48, 48, r.body_angle, int(r.walk + .5f), 8);
      sprite("borg_t", x + 1, y + 1, 48, 48, r.aim_angle, 16 + int(r.walk + .5f), 8);
    }
    for (const auto &shot : projectile_pool) {
      if (shot.active && shot.fields.life_timer >= .4f) {
        SDL_SetRenderDrawColor(renderer, 233, 204, 137, 160);
        const float x = cx + shot.position.x, y = cy + shot.position.y;
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
    std::snprintf(line, sizeof(line), "Seconds survived: %d", int(g.run.seconds));
    text(line, 3, 7, .7f, white);
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
    std::snprintf(line, sizeof(line), "Seconds survived: %d", int(g.run.seconds));
    text(line, 120, 90, .75435f, {.85f, .55f, .35f, .8f * fade});
    text("Who were you:", 10, 165, .75435f, {1, 1, 1, fade});
    text(g.name, 50, 190, 1, {1, 1, 1, fade});
    if (std::fmod(g.menu_clock, 1.f) < .5f)
      text("_", 50 + 16 * g.name.size(), 190, 1, {1, 1, 1, .4f});
    std::snprintf(line, sizeof(line), "Gained level: 1\nHit accuracy: %d%%\nFrags: %d\n",
                  highscore_record_shots_fired ? g.run.hits * 100 / highscore_record_shots_fired : 0, g.run.kills);
    text(line, 60, 320, .66f, white);
  } else {
    const char *heading = g.screen == Screen::Scores    ? "Highscores:"
                          : g.screen == Screen::Credits ? "Project Crimsonland"
                          : g.screen == Screen::Options ? "Game options."
                                                        : "Online options.";
    text(heading, 180, 120, 1, white);
    if (g.screen == Screen::Scores) {
      text("-SURVIVAL--", 180, 170, .75435f, white);
      for (size_t i = 0; i < std::min<size_t>(g.scores.size(), 7); ++i) {
        const auto &score = g.scores[i];
        std::snprintf(line, sizeof(line), "%zu.  %-31s  %d", i + 1, score.name.c_str(), int(score.seconds));
        text(line, 180, 210 + i * 23, .75435f, muted);
      }
    } else if (g.screen == Screen::Credits) {
      text("Game coded & designed by\nTero Alatalo\n3D Art modelled by\nTimo Palonen\nMusic performed by\nValtteri "
           "Pihlajamaki",
           180, 170, .75435f, white);
    } else if (g.screen == Screen::Options) {
      text(g.music_enabled ? "Music: on" : "Music: off", 180, 200, .75435f, g.selected == 0 ? white : muted);
      text("Done", 180, 238, .75435f, g.selected == 1 ? white : muted);
    } else if (g.screen == Screen::Online) {
      text("Online highscores are offline.", 180, 170, .75435f, white);
    }
    if (g.screen != Screen::Options)
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
      sprite("part64", g.cursor_x - 32 + 16 * std::cos(angle), g.cursor_y - 32 + 16 * std::sin(angle), 64, 64, 0, 0,
             1, {1, 1, 1, alpha});
    }
    sprite("aim32", g.cursor_x - 16, g.cursor_y - 16, 32, 32, 0, 0, 1, {1, 1, 1, .64f});
  }
  SDL_RenderPresent(renderer);
}
} // namespace freeware
