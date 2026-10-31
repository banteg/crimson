#pragma once
#include "game.h"
#include <SDL3/SDL.h>
#include <string>
#include <unordered_map>

namespace freeware {
struct Display {
  SDL_Renderer *renderer;
  std::unordered_map<std::string, SDL_Texture *> textures;
  SDL_Texture *ground{}, *last_texture{};
  int ground_revision = -1;
  void rebuild_ground(const Game &g);
  explicit Display(SDL_Renderer *r) : renderer(r) {}
  ~Display();
  bool load(const std::string &folder, bool &safe_mode);
  void draw(Game &game);
  void frame_sprite(const FrameSprite &draw);
  void frame_art(const std::vector<FrameSprite> &sprites, const std::vector<FrameLabel> &labels);
  void sprite(const char *name, float x, float y, float w, float h, float angle = 0, int frame = 0,
              int columns = 1, SDL_FColor tint = {1, 1, 1, 1}, UiUv uv = {}, unsigned filter = 0,
              unsigned destination_blend = 0, unsigned source_blend = 5);
  void text(const std::string &value, float x, float y, float scale, SDL_FColor color);
};
} // namespace freeware
