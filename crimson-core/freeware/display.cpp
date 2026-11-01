#include "display.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace freeware {
constexpr float degrees = 57.2957795f;
Display::~Display() {
  for (auto &entry : textures)
    SDL_DestroyTexture(entry.second);
  SDL_DestroyTexture(ground);
}
bool Display::load(const std::string &folder, bool &safe_mode) {
  std::ifstream list(folder + "/textures.txt");
  if (!list)
    return SDL_SetError("Missing freeware texture manifest");
  std::string name;
  while (std::getline(list, name)) {
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
      return SDL_SetError("Bad freeware texture %s", name.c_str());
    }
    SDL_Surface *s = SDL_CreateSurfaceFrom(w, h, SDL_PIXELFORMAT_RGBA32, data + 8, w * 4);
    SDL_Texture *texture = s ? SDL_CreateTextureFromSurface(renderer, s) : nullptr;
    SDL_DestroySurface(s);
    SDL_free(data);
    if (!texture)
      return false;
    textures.emplace(name, texture);
    SDL_SetTextureBlendMode(texture, name == "part64" ? SDL_BLENDMODE_ADD : SDL_BLENDMODE_BLEND);
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
  const auto texture = textures.find(name);
  auto *t = !std::strcmp(name, "ground") ? (ground ? ground : textures.at("ground_tile"))
            : texture != textures.end() ? texture->second : last_texture;
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
  const char *name = draw.name.c_str();
  if (!std::strcmp(name, "grass1.tga"))
    name = "grass1";
  else if (!std::strcmp(name, "mud1.tga"))
    name = "mud1";
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
void Display::rebuild_ground(const Game &g) {
  SDL_SetRenderTarget(renderer, ground);
  SDL_SetRenderDrawColorFloat(renderer, g.terrain_clear.r, g.terrain_clear.g, g.terrain_clear.b,
                              g.terrain_clear.a);
  SDL_RenderClear(renderer);
  for (const auto &draw : g.terrain)
    frame_sprite(draw);
  SDL_SetRenderTarget(renderer, nullptr);
  ground_revision = g.terrain_revision;
}
void Display::draw(Game &g) {
  if (!g.safe_mode && ground_revision != g.terrain_revision && g.presented_terrain_revision == g.terrain_revision)
    rebuild_ground(g);
  SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
  SDL_RenderClear(renderer);
  for (const auto &draw : g.terrain_sprites)
    frame_sprite(draw);
  // The PE presents the old terrain before baking this frame's marks into it.
  if (!g.terrain_marks.empty()) {
    SDL_SetRenderTarget(renderer, ground);
    for (const auto &draw : g.terrain_marks)
      frame_sprite(draw);
    SDL_SetRenderTarget(renderer, nullptr);
  }
  if (!g.safe_mode && ground_revision != g.terrain_revision)
    rebuild_ground(g);
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
