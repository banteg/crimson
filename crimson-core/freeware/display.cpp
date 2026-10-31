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
    SDL_SetTextureBlendMode(texture, SDL_BLENDMODE_BLEND);
    SDL_SetTextureScaleMode(texture, SDL_SCALEMODE_LINEAR);
  }
  ground = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_TARGET, arena, arena);
  if (!ground || !SDL_SetRenderTarget(renderer, ground))
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
  SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
  SDL_RenderClear(renderer);
  const float cx = camera_x(g), cy = camera_y(g);
  SDL_FRect field{cx, cy, arena, arena};
  SDL_RenderTexture(renderer, ground, nullptr, &field);
  if (g.screen == Screen::Playing || g.screen == Screen::Death || g.paused) {
    for (const auto &c : creature_pool) {
      if (!c.active)
        continue;
      const auto &s = c.freeware;
      const float x = cx + c.pos_x - s.size / 2, y = cy + c.pos_y - s.size / 2;
      if (c.death_timer < 16)
        sprite("blood", x, y, s.size, s.size, s.heading, 0, 1, {.65f, .2f, .2f, .8f});
      else
        sprite("eiliens", x, y, s.size, s.size, s.heading, int(s.animation) % 32, 8,
               {s.color.r, s.color.g, s.color.b, 1});
    }
    const auto &r = g.run;
    if (r.health > 0) {
      float x = cx + r.player.x - 24, y = cy + r.player.y - 24;
      sprite("borg_t", x, y, 48, 48, r.body_angle, int(r.walk), 8);
      sprite("borg_t", x + 1, y + 1, 48, 48, r.aim_angle, 16 + int(r.walk), 8);
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
    sprite("crimsonland", width / 2 - 256 + std::cos(clock) * 5, 82 - 64 + std::sin(clock) * 5, 512, 512);
    for (int i = 0; i < 8; ++i) {
      const float alpha = menu_hover(g) == i ? .9f : g.selected == i ? .7f : .6f;
      text(menu_label(g, i), width / 2 - 100, 200 + i * 32, .75435f, {1, 1, 1, alpha});
    }
    text("v1.4.0", 10, height - 25, .65435f, {1, 1, 1, .4f});
    text("2002 (c) 10tons entertainment", width - 330, height - 25, .65435f, {1, 1, 1, .4f});
  } else if (g.screen == Screen::Playing) {
    std::snprintf(line, sizeof(line), "health %d", int(std::max(0.f, g.run.health)));
    text(line, 8, 8, .75435f, white);
    std::snprintf(line, sizeof(line), "Seconds survived: %d", int(g.run.seconds));
    text(line, 8, 30, .65f, muted);
  } else if (g.screen == Screen::Death) {
    sprite("reaper", width - 280, 55, 180, 180);
    text("The Reaper got you.", 100, 50, 1.6f, {.75f, .35f, .22f, 1});
    std::snprintf(line, sizeof(line), "Seconds survived: %d", int(g.run.seconds));
    text(line, 100, 150, .75435f, white);
    text("Who were you:", 100, 220, .75435f, white);
    text(g.name + "_", 100, 250, .75435f, white);
    std::snprintf(line, sizeof(line), "Frags: %d   Hit accuracy: %d%%", g.run.kills,
                  highscore_record_shots_fired ? g.run.hits * 100 / highscore_record_shots_fired : 0);
    text(line, 100, 320, .75435f, muted);
  } else {
    const char *heading = g.screen == Screen::Scores    ? "Highscores:"
                          : g.screen == Screen::Credits ? "Project Crimsonland"
                          : g.screen == Screen::Options ? "Game options."
                                                        : "Online options.";
    text(heading, 180, 120, 1, white);
    if (g.screen == Screen::Scores) {
      text("-SURVIVAL--", 180, 170, .75435f, white);
      std::snprintf(line, sizeof(line), "%s   %.0f", g.name.c_str(), g.best_seconds);
      if (g.best_seconds > 0)
        text(line, 180, 210, .75435f, muted);
    } else if (g.screen == Screen::Credits)
      text("Game coded & designed by\nTero Alatalo", 180, 170, .75435f, white);
    text("back to main menu", 180, 350, .75435f, muted);
  }
  const bool aiming = g.screen == Screen::Playing;
  sprite(aiming ? "aim64" : "aim32", g.cursor_x - (aiming ? 32 : 16), g.cursor_y - (aiming ? 32 : 16),
         aiming ? 64 : 32, aiming ? 64 : 32);
  SDL_RenderPresent(renderer);
}
} // namespace freeware
