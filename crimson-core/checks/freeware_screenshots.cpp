// Compile with the production display.cpp and pass an empty directory for output.
#include "display.h"
#include <cassert>
#include <string>

using namespace freeware;

static void check_bmp(const std::string &path, int w, int h, bool red) {
  SDL_Surface *image = SDL_LoadBMP(path.c_str());
  assert(image && image->w == w && image->h == h);
  Uint8 r, g, b, a;
  assert(SDL_ReadSurfacePixel(image, w / 2, h / 2, &r, &g, &b, &a));
  assert(r == (red ? 255 : 0) && g == (red ? 0 : 255) && b == 0);
  SDL_DestroySurface(image);
}

int main(int argc, char **argv) {
  assert(argc == 2);
  SDL_SetHint(SDL_HINT_VIDEO_DRIVER, "dummy");
  assert(SDL_Init(SDL_INIT_VIDEO));
  SDL_Window *window = SDL_CreateWindow("screenshot test", 400, 210, SDL_WINDOW_HIDDEN | SDL_WINDOW_RESIZABLE);
  SDL_Renderer *renderer = SDL_CreateRenderer(window, "software");
  assert(renderer && SDL_SetRenderLogicalPresentation(renderer, width, height, SDL_LOGICAL_PRESENTATION_LETTERBOX));
  {
    Game game;
    Display display(renderer);
    game.safe_mode = true;
    game.presented_screen = Screen::Playing;
    game.save_dir = std::string(argv[1]) + "/";
    SDL_Surface *white = SDL_CreateSurface(1, 1, SDL_PIXELFORMAT_RGBA32);
    assert(white && SDL_FillSurfaceRect(white, nullptr, SDL_MapSurfaceRGBA(white, 255, 255, 255, 255)));
    display.textures["pixel"] = SDL_CreateTextureFromSurface(renderer, white);
    assert(display.textures["pixel"]);
    SDL_DestroySurface(white);

    game.frame_sprites = {{"pixel", 0, 0, width, height, 0, {1, 0, 0, 1}}};
    display.draw(game);

    // The next frame is green and rendered at a new size. F12 sees the previously presented red viewport.
    assert(SDL_SetWindowSize(window, 384, 288) && SDL_SyncWindow(window));
    game.screenshot_requested = true;
    game.frame_sprites[0].color = {0, 1, 0, 1};
    display.draw(game);
    assert(!game.screenshot_requested && game.screenshot_index == 1);
    const bool previous = FREEWARE_EDITION >= 10300;
    check_bmp(game.save_dir + "screenshot_0.bmp", previous ? 280 : 384, previous ? 210 : 288, previous);

    if (previous) {
      game.quit = true;
      game.frame_sprites[0].color = {0, 0, 1, 1};
      game.screenshot_requested = true;
      display.consume_front_screenshot(game);
      check_bmp(game.save_dir + "screenshot_1.bmp", 384, 288, false);
      game.screenshot_requested = true;
      game.save_dir += "does-not-exist/";
      display.consume_front_screenshot(game);
      assert(!game.screenshot_requested && game.screenshot_index == 2);
    }
  }
  SDL_DestroyRenderer(renderer);
  SDL_DestroyWindow(window);
  SDL_Quit();
}
