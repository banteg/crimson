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
       {"font",      "grass1",         "mud1",         "ground_tile",  "crimsonland", "borg_t",
        "eiliens",   "bullet_real_16", "blood",        "aim32",        "radius256",   "assembly-logo",
        "aim128",    "aim_enh",        "aim64",        "part64",       "reaper",      "bullet",
        "arrow",     "ui_text",        "rocket",       "flame",        "bubble",      "glow64",
        "bar",       "bonus_fire",     "bonus_freeze", "bonus_weapon", "bonus_bomb",  "bonus_timebend",
        "shockwave", "icemold"}) {
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
  if (!stains || !ground)
    return false;
  SDL_SetTextureBlendMode(stains, SDL_BLENDMODE_BLEND);
  return SDL_SetRenderTarget(renderer, nullptr);
}
void Display::sprite(const char *name, float x, float y, float w, float h, float angle, int frame, int columns,
                     SDL_FColor tint, UiUv uv, unsigned filter, unsigned destination_blend,
                     unsigned source_blend) {
  // A failed Grim texture lookup leaves the previous binding in place (grim.dll 0x10004d07).
  auto *t = !std::strcmp(name, "tl_tolmec") ? last_texture : textures.at(name);
  if (!t)
    return;
  last_texture = t;
  float tw, th;
  SDL_GetTextureSize(t, &tw, &th);
  float cw = tw / columns, ch = th / columns;
  SDL_FRect src{(frame % columns) * cw, (frame / columns) * ch, cw, ch}, dst{x, y, w, h};
  src.x += uv.u * cw;
  src.y += uv.v * ch;
  src.w *= uv.s - uv.u;
  src.h *= uv.t - uv.v;
  if (filter)
    SDL_SetTextureScaleMode(t, filter == 1 ? SDL_SCALEMODE_NEAREST : SDL_SCALEMODE_LINEAR);
  SDL_BlendMode previous = SDL_BLENDMODE_BLEND;
  if (destination_blend) {
    SDL_GetTextureBlendMode(t, &previous);
    SDL_SetTextureBlendMode(t, source_blend == 1        ? SDL_ComposeCustomBlendMode(
                                                              SDL_BLENDFACTOR_ZERO, SDL_BLENDFACTOR_ONE_MINUS_SRC_ALPHA,
                                                              SDL_BLENDOPERATION_ADD, SDL_BLENDFACTOR_ZERO,
                                                              SDL_BLENDFACTOR_ONE_MINUS_SRC_ALPHA, SDL_BLENDOPERATION_ADD)
                               : destination_blend == 2 ? SDL_BLENDMODE_ADD
                                                        : SDL_BLENDMODE_BLEND);
  }
  SDL_SetTextureColorModFloat(t, tint.r, tint.g, tint.b);
  SDL_SetTextureAlphaModFloat(t, tint.a);
  SDL_RenderTextureRotated(renderer, t, &src, &dst, angle * degrees, nullptr, SDL_FLIP_NONE);
  if (destination_blend)
    SDL_SetTextureBlendMode(t, previous);
  if (filter == 1)
    SDL_SetTextureScaleMode(t, SDL_SCALEMODE_LINEAR);
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
void Display::frame_sprite(const FrameSprite &draw) {
  const char *name = draw.name;
  if (!std::strcmp(name, "ugluk"))
    name = "borg_t";
  else if (!std::strcmp(name, "goblin"))
    name = "eiliens";
  else if (!std::strcmp(name, "glow"))
    name = "glow64";
  else if (!std::strcmp(name, "bullet_i"))
    name = "bullet_real_16";
  else if (!std::strcmp(name, "aimen"))
    name = "aim_enh";
  else if (!std::strcmp(name, "radius"))
    name = "radius256";
  else if (!std::strcmp(name, "asmlogo"))
    name = "assembly-logo";
  else if (!std::strcmp(name, "b_freeze"))
    name = "bonus_freeze";
  else if (!std::strcmp(name, "part"))
    name = "part64";
  sprite(name, draw.x, draw.y, draw.width, draw.height, draw.angle, 0, 1,
         {draw.color.r, draw.color.g, draw.color.b, draw.color.a}, draw.uv, draw.filter, draw.destination_blend,
         draw.source_blend);
}
void Display::frame_art(const Game &g) {
  size_t i = 0;
  for (const auto &label : g.frame_labels) {
    while (i < label.preceding_sprites)
      frame_sprite(g.frame_sprites[i++]);
    text(label.text, label.x, label.y, label.scale, {label.color.r, label.color.g, label.color.b, label.color.a});
  }
  while (i < g.frame_sprites.size())
    frame_sprite(g.frame_sprites[i++]);
}
void Display::draw(Game &g) {
  if (g.generation != ground_generation) {
    SDL_SetRenderTarget(renderer, ground);
    SDL_SetRenderDrawColor(renderer, 63, 56, 25, 255);
    SDL_RenderClear(renderer);
    for (const auto &stamp : g.terrain)
      sprite(stamp.grass ? "grass1" : "mud1", stamp.pos.x, stamp.pos.y, 128, 128, stamp.angle, 0, 1,
             {.7f, .7f, .7f, .9f});
    SDL_SetRenderTarget(renderer, nullptr);
  }
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
    for (const auto &s : g.shells)
      sprite("bullet_real_16", s.pos.x - 2, s.pos.y - 2, 4, 4, s.rotation, 0, 1, {1, 1, 1, .8f});
    for (const auto &c : g.decals)
      sprite("eiliens", c.position.x + 2, c.position.y + 2, c.size * 1.04f, c.size * 1.04f, c.heading, c.cell, 8,
             {c.color.r, c.color.g, c.color.b, .5f}, {}, 2, 6, 1);
    for (const auto &c : g.decals) {
      sprite("eiliens", c.position.x, c.position.y, c.size, c.size, c.heading, c.cell, 8,
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
  for (const auto &draw : g.actor_sprites)
    frame_sprite(draw);
  if (g.presented_screen == Screen::Playing || g.presented_screen == Screen::Dying ||
      g.presented_screen == Screen::Death || g.presented_screen == Screen::Perks || g.paused) {
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
        }
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
      float size = g.run.bomb_age * 512;
      sprite("shockwave", cx + g.run.bomb_pos.x - size / 2, cy + g.run.bomb_pos.y - size / 2, size, size);
    }
    projectile_draws(shots, {cx, cy}, g.run.seconds, g.effects);
    const char *shot_textures[] = {"", "bullet", "part64", "bullet_real_16", "glow64", "rocket"};
    for (const auto &d : shots) {
      const auto *name = shot_textures[static_cast<int>(d.texture)];
      auto *texture = textures.at(name);
      SDL_BlendMode previous;
      SDL_GetTextureBlendMode(texture, &previous);
      SDL_SetTextureBlendMode(texture, d.additive ? SDL_BLENDMODE_ADD : SDL_BLENDMODE_BLEND);
      SDL_FColor tint{d.color.r, d.color.g, d.color.b, d.color.a};
      if (d.size > 0)
        sprite(name, d.points[0].x, d.points[0].y, d.size, d.size, d.angle, 0, 1, tint);
      else {
        SDL_Vertex v[4];
        const SDL_FPoint uv[] = {{0, 0}, {1, 0}, {1, 1}, {0, 1}};
        for (int i = 0; i < 4; ++i)
          v[i] = {{d.points[i].x, d.points[i].y}, i < 2 ? SDL_FColor{.6f, .6f, .6f, 0} : tint, uv[i]};
        const int indices[] = {0, 1, 2, 0, 2, 3};
        SDL_RenderGeometry(renderer, texture, v, 4, indices, 6);
      }
      SDL_SetTextureBlendMode(texture, previous);
    }
  }
  const SDL_FColor white{1, 1, 1, 1};
  if (g.presented_screen == Screen::Menu && g.notice)
    text(g.notice, width / 2 - 220, 478, .65f, white);
  frame_art(g);
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
  if (g.screenshot_requested) {
    char filename[48];
    std::snprintf(filename, sizeof(filename), "screenshot_%d.bmp", g.screenshot_index);
    SDL_Surface *shot = SDL_RenderReadPixels(renderer, nullptr);
    if (shot && SDL_SaveBMP(shot, (g.save_dir + filename).c_str()))
      ++g.screenshot_index;
    SDL_DestroySurface(shot);
    g.screenshot_requested = false;
  }
  SDL_RenderPresent(renderer);
}
} // namespace freeware
