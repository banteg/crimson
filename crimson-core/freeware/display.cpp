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
bool Display::load(const std::string &folder, bool &safe_mode) {
  for (const char *name :
       {"font",      "grass1",         "mud1",         "ground_tile",  "crimsonland", "borg_t",
        "eiliens",   "bullet_real_16", "blood",        "aim32",        "radius256",   "assembly-logo",
        "aim128",    "aim_enh",        "aim64",        "part64",       "reaper",      "bullet",
        "arrow",     "ui_text",        "rocket",       "flame",        "bubble",      "glow64",
        "bar",       "bonus_fire",     "bonus_freeze", "bonus_weapon", "bonus_bomb",  "bonus_timebend",
        "shockwave", "icemold",        "smoke"}) {
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
  if (!safe_mode) {
    ground = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_TARGET, arena, arena);
    if (ground)
      SDL_SetTextureBlendMode(ground, SDL_BLENDMODE_NONE);
    else
      safe_mode = true;
  }
  return SDL_SetRenderTarget(renderer, nullptr);
}
static SDL_BlendMode blend_mode(unsigned source, unsigned destination) {
  if (source != 1)
    return destination == 2 ? SDL_BLENDMODE_ADD : SDL_BLENDMODE_BLEND;
  auto dst = destination == 2 ? SDL_BLENDFACTOR_ONE : SDL_BLENDFACTOR_ONE_MINUS_SRC_ALPHA;
  return SDL_ComposeCustomBlendMode(SDL_BLENDFACTOR_ZERO, dst, SDL_BLENDOPERATION_ADD, SDL_BLENDFACTOR_ZERO, dst,
                                    SDL_BLENDOPERATION_ADD);
}
void Display::sprite(const char *name, float x, float y, float w, float h, float angle, int frame, int columns,
                     SDL_FColor tint, UiUv uv, unsigned filter, unsigned destination_blend,
                     unsigned source_blend) {
  // A failed Grim texture lookup leaves the previous binding in place (grim.dll 0x10004d07).
  auto *t = !std::strcmp(name, "tl_tolmec") ? last_texture
            : !std::strcmp(name, "ground")  ? (ground ? ground : textures.at("ground_tile"))
                                            : textures.at(name);
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
    SDL_SetTextureBlendMode(t, blend_mode(source_blend, destination_blend));
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
  else if (!std::strcmp(name, "b_fire"))
    name = "bonus_fire";
  else if (!std::strcmp(name, "b_weapon"))
    name = "bonus_weapon";
  else if (!std::strcmp(name, "b_bomb"))
    name = "bonus_bomb";
  else if (!std::strcmp(name, "b_timebend"))
    name = "bonus_timebend";
  else if (!std::strcmp(name, "b_freeze"))
    name = "bonus_freeze";
  else if (!std::strcmp(name, "part"))
    name = "part64";
  sprite(name, draw.x, draw.y, draw.width, draw.height, draw.angle, 0, 1,
         {draw.color.r, draw.color.g, draw.color.b, draw.color.a}, draw.uv, draw.filter, draw.destination_blend,
         draw.source_blend);
}
void Display::frame_art(const std::vector<FrameSprite> &sprites, const std::vector<FrameLabel> &labels) {
  size_t i = 0;
  for (const auto &label : labels) {
    while (i < label.preceding_sprites)
      frame_sprite(sprites[i++]);
    text(label.text, label.x, label.y, label.scale, {label.color.r, label.color.g, label.color.b, label.color.a});
  }
  while (i < sprites.size())
    frame_sprite(sprites[i++]);
}
void Display::draw(Game &g) {
  if (!g.safe_mode && g.generation != ground_generation) {
    SDL_SetRenderTarget(renderer, ground);
    SDL_SetRenderDrawColor(renderer, 63, 56, 25, 255);
    SDL_RenderClear(renderer);
    for (const auto &stamp : g.terrain)
      sprite(stamp.grass ? "grass1" : "mud1", stamp.pos.x, stamp.pos.y, 128, 128, stamp.angle, 0, 1,
             {.7f, .7f, .7f, .9f});
    SDL_SetRenderTarget(renderer, nullptr);
  }
  if (!g.safe_mode && (g.generation != ground_generation || !g.decals.empty() || !g.impacts.empty() ||
                       !g.marks.empty() || !g.shells.empty())) {
    SDL_SetRenderTarget(renderer, ground);
    ground_generation = g.generation;
    for (const auto &impact : g.impacts)
      frame_sprite(impact);
    for (const auto &m : g.marks)
      sprite("blood", m.pos.x - m.size / 2, m.pos.y - m.size / 2, m.size, m.size, m.rotation, 0, 1,
             {1, 1, 1, .78f});
    for (const auto &c : g.decals)
      sprite("eiliens", c.position.x + 2, c.position.y + 2, c.size * 1.04f, c.size * 1.04f, c.heading, c.cell, 8,
             {c.color.r, c.color.g, c.color.b, .5f}, {}, 2, 6, 1);
    for (const auto &c : g.decals) {
      sprite("eiliens", c.position.x, c.position.y, c.size, c.size, c.heading, c.cell, 8,
             {c.color.r, c.color.g, c.color.b, c.color.a});
    }
    for (const auto &s : g.shells)
      sprite("bullet_real_16", s.pos.x - 2, s.pos.y - 2, 4, 4, s.rotation, 0, 1, {1, 1, 1, .8f});
    SDL_SetRenderTarget(renderer, nullptr);
  }
  SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
  SDL_RenderClear(renderer);
  for (const auto &draw : g.terrain_sprites)
    frame_sprite(draw);
  for (const auto &draw : g.actor_sprites)
    frame_sprite(draw);
  for (const auto &d : g.frame_trails) {
    auto *t = textures.at(!std::strcmp(d.texture, "part") ? "part64" : d.texture);
    SDL_BlendMode previous;
    SDL_GetTextureBlendMode(t, &previous);
    SDL_SetTextureBlendMode(t, blend_mode(d.source_blend, d.destination_blend));
    SDL_SetTextureScaleMode(t, d.filter == 1 ? SDL_SCALEMODE_NEAREST : SDL_SCALEMODE_LINEAR);
    SDL_Vertex vertices[4];
    const SDL_FPoint uv[] = {{0, 0}, {1, 0}, {1, 1}, {0, 1}};
    for (int i = 0; i < 4; ++i) {
      const auto &c = d.colors[i];
      vertices[i] = {{d.points[i].x, d.points[i].y}, {c.r, c.g, c.b, c.a}, uv[i]};
    }
    const int indices[] = {0, 1, 2, 0, 2, 3};
    SDL_RenderGeometry(renderer, t, vertices, 4, indices, 6);
    SDL_SetTextureBlendMode(t, previous);
    if (d.filter == 1)
      SDL_SetTextureScaleMode(t, SDL_SCALEMODE_LINEAR);
  }
  frame_art(g.effect_sprites, g.effect_labels);
  const SDL_FColor white{1, 1, 1, 1};
  if (g.presented_screen == Screen::Menu && g.notice)
    text(g.notice, width / 2 - 220, 478, .65f, white);
  frame_art(g.frame_sprites, g.frame_labels);
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
