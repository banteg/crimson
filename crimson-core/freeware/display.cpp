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
       {"font",       "grass1",         "mud1",      "ground_tile", "crimsonland",  "borg_t",
        "eiliens",    "bullet_real_16", "blood",     "aim32",       "aim64",        "part64",
        "reaper",     "bullet",         "arrow",     "ui_text",     "rocket",       "flame",
        "bubble",     "glow64",         "bar",       "bonus_fire",  "bonus_freeze", "bonus_weapon",
        "bonus_bomb", "bonus_timebend", "shockwave", "icemold"}) {
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
  if (g.generation != ground_generation || !g.decals.empty() || !g.marks.empty() || !g.shells.empty()) {
    SDL_SetRenderTarget(renderer, stains);
    if (g.generation != ground_generation) {
      SDL_SetRenderDrawColor(renderer, 0, 0, 0, 0);
      SDL_RenderClear(renderer);
      ground_generation = g.generation;
    }
    for (const auto &m : g.marks)
      sprite(m.frozen ? "icemold" : "blood", m.pos.x - m.size / 2, m.pos.y - m.size / 2, m.size, m.size,
             m.rotation);
    for (auto &pos : g.shells)
      sprite("bullet_real_16", pos.x - 2, pos.y - 3, 4, 6, 0, 0, 1, {.55f, .45f, .25f, .75f});
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
      if (g.direction_arrow && (g.two_players || g.aiming[i] == 2)) {
        sprite("arrow", x + 16 + 32 * std::sin(r.body_angle), y + 16 - 32 * std::cos(r.body_angle), 16, 16,
               r.body_angle, 0, 1, tint);
      }
      if (r.shield > 0)
        sprite("bubble", x - 8, y - 8, 64, 64, 0, 0, 1, {.4f, .8f, 1, .6f});
    }
    for (const auto &s : sprite_effect_pool)
      if (s.active)
        sprite("glow64", cx + s.pos_x - s.scale / 2, cy + s.pos_y - s.scale / 2, s.scale, s.scale, s.rotation, 0,
               1, {s.color_r, s.color_g, s.color_b, s.color_a});
    for (const auto &p : particle_pool)
      if (p.active) {
        bool bubble = p.style_id == 8;
        float size = bubble ? 36 : (1.2f - p.intensity) * 32 + 12;
        sprite(bubble ? "bubble" : "flame", cx + p.position.x - size / 2, cy + p.position.y - size / 2, size, size,
               p.rotation, 0, 1, {1, 1, 1, std::clamp(p.intensity, 0.f, 1.f)});
      }
    for (const auto &r : secondary_projectile_pool)
      if (r.active) {
        if (r.fields.type_id == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
          float size = r.fields.velocity.x * r.fields.velocity.y * 160;
          sprite("shockwave", cx + r.pos_x - size / 2, cy + r.position.y - size / 2, size, size);
        } else
          sprite("rocket", cx + r.pos_x - 8, cy + r.position.y - 8, 16, 16, r.angle);
      }
    if (g.run.pickup.time > 0) {
      auto &b = g.run.pickup;
      const char *icons[] = {"bonus_fire", "bonus_freeze", "bonus_weapon",
                             "bonus_bomb", "bubble",       "bonus_timebend"};
      float x = b.pos.x + cx, y = b.pos.y + cy;
      sprite(icons[int(b.kind) - 1], x - 16, y - 16, 32, 32);
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
    hud(g);
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
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, g.perk_transparent ? 65 : 205);
    SDL_RenderFillRect(renderer, nullptr);
    text("Pick a perk:", 150, 40, .65f, white);
    text(g.run.perks[25] ? "(of random 7)" : "(of random 5)", 285, 43, .55f, {.68f, .68f, .89f, 1});
    text("(click to see through)", 390, 5, .65f, {.78f, .78f, .49f, .65f});
    for (size_t i = 0; i < g.run.choices.size(); ++i)
      text(perk_name(g.run.choices[i]), 50, 80 + 20 * i, .65f, i == size_t(g.selected) ? white : muted);
    if (!g.run.choices.empty()) {
      std::string description = perk_description(g.run.choices[g.selected]);
      size_t col = 0;
      for (char &c : description) {
        if (c == ' ' && col > 25) {
          c = '\n';
          col = 0;
        } else
          ++col;
      }
      text(description, 400, 80, .65f, white);
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
    int value = g.survival ? int(g.run.seconds) : g.run.experience;
    auto &table = g.scores();
    size_t rank = 0;
    while (rank < table.size() && (g.survival ? table[rank].seconds : table[rank].experience) >= value)
      ++rank;
    if (rank < 100 && value > 0)
      std::snprintf(line, sizeof(line), "(You scored %zu# in top 100 scores)", rank + 1);
    else
      std::snprintf(line, sizeof(line), "(You didn't make the top 100 scores)");
    text(line, 120, 118, .62f, {.85f, .55f, .35f, .8f * fade});
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
      text(g.survival ? (g.two_players ? "-SURVIVAL2-" : "-SURVIVAL--")
                      : (g.two_players ? "-CAREER2---" : "-CAREER----"),
           180, 170, .75435f, white);
      for (size_t i = 0;
           i < std::min<size_t>(g.scores().size() - std::min<size_t>(g.score_offset, g.scores().size()), 10);
           ++i) {
        const auto &score = g.scores()[g.score_offset + i];
        std::snprintf(line, sizeof(line), "%zu.  %-31s  %d", g.score_offset + i + 1, score.name.c_str(),
                      g.survival ? int(score.seconds) : score.experience);
        text(line, 180, 210 + i * 23, .75435f, muted);
      }
    } else if (g.screen == Screen::Credits) {
      credits(g.menu_clock - g.screen_started);
    } else if (g.screen == Screen::Options) {
      if (g.calibration >= 0) {
        static const char *steps[] = {"Center the joystick and press enter or a joystick button",
                                      "Set X/Y threshold with up/down, then press enter",
                                      "Press the hat LEFT and press enter (enter to skip)",
                                      "Press the hat RIGHT and press enter (enter to skip)"};
        text(steps[g.calibration], 50, 190, .65f, white);
        std::snprintf(line, sizeof(line), "X/Y-Axis threshold: %d%%", int(g.pad_threshold[g.configuring] * 100));
        text(line, 50, 225, .65f, muted);
      } else if (g.rebind < 0) {
        for (int i = 0; i < 12; ++i)
          text(g.option(i), width / 2 - 140, 170 + i * 21, .65f, g.selected == i ? white : muted);
      } else {
        static const char *actions[] = {"forward", "backward", "left", "right", "fire"};
        std::snprintf(line, sizeof(line), "Player %d: press key for %s", g.rebind / 5 + 1, actions[g.rebind % 5]);
        text(line, 180, 200, .72f, white);
      }
    } else if (g.screen == Screen::Online) {
      static const char *rows[] = {"Visit Crimsonland website", "Check for updates", "View online highscores",
                                   "back to main menu"};
      for (int i = 0; i < 4; ++i)
        text(rows[i], 180, 170 + 32 * i, .75f, i == g.selected ? white : muted);
      if (g.notice)
        text(g.notice, 50, 345, .55f, white);
    }
    if (g.screen != Screen::Options && g.screen != Screen::Scores && g.screen != Screen::Credits &&
        g.screen != Screen::Online)
      text("back to main menu", 180, 410, .75435f, muted);
  }
  if (g.screen == Screen::Playing) {
    for (int i = 0; i < g.players(); ++i) {
      auto &player = g.actor(i);
      if (player.health <= 0)
        continue;
      auto aim = player_state_table[i].freeware.aim;
      float size = std::clamp(std::hypot(aim.x - player.player.x, aim.y - player.player.y) * player.spread * .25f,
                              16.f, 64.f);
      SDL_FColor tint = i ? SDL_FColor{.45f, .75f, 1, 1} : SDL_FColor{1, 1, 1, 1};
      sprite("aim64", cx + aim.x - size / 2, cy + aim.y - size / 2, size, size, 0, 0, 1, tint);
    }
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
  if (g.console_open) {
    SDL_SetRenderDrawBlendMode(renderer, SDL_BLENDMODE_BLEND);
    SDL_SetRenderDrawColor(renderer, 12, 16, 20, 238);
    SDL_FRect area{0, 0, width, 220};
    SDL_RenderFillRect(renderer, &area);
    int y = 8;
    for (size_t i = g.console_lines.size() > 9 ? g.console_lines.size() - 9 : 0; i < g.console_lines.size(); ++i) {
      text(g.console_lines[i], 3, y, .58f, white);
      y += 19;
    }
    text("> " + g.command + "_", 3, 192, .65f, white);
  }
  SDL_RenderPresent(renderer);
}
} // namespace freeware
