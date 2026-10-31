#pragma once
#include "game.h"
#include <SDL3/SDL.h>
#include <string>
#include <unordered_map>

namespace freeware {
struct Display {
  SDL_Renderer *renderer;
  std::unordered_map<std::string, SDL_Texture *> textures;
  SDL_Texture *ground{}, *stains{};
  std::vector<ShotDraw> shots;
  int ground_generation = -1;
  explicit Display(SDL_Renderer *r) : renderer(r) {}
  ~Display();
  bool load(const std::string &folder);
  void draw(Game &game);
  void frame_art(const Game &game);
  void hud(const Game &game);
  void credits(float clock);
  void sprite(const char *name, float x, float y, float w, float h, float angle = 0, int frame = 0,
              int columns = 1, SDL_FColor tint = {1, 1, 1, 1});
  void text(const std::string &value, float x, float y, float scale, SDL_FColor color);
};
} // namespace freeware
