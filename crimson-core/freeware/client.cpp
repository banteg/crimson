#include "display.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

namespace freeware {
struct Sample {
  SDL_AudioStream *stream{};
  Uint8 *data{};
  Uint32 size{};
};
static Sample samples[4];
static void load_audio(const std::string &folder) {
  const char *names[] = {"gunshot_01.wav", "hit_01.wav", "die_01.wav", "attack_01.wav"};
  for (int i = 0; i < 4; ++i) {
    SDL_AudioSpec spec{};
    auto &s = samples[i];
    if (SDL_LoadWAV((folder + "/" + names[i]).c_str(), &spec, &s.data, &s.size)) {
      s.stream = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, nullptr, nullptr);
      if (s.stream) {
        SDL_SetAudioStreamGain(s.stream, .45f);
        SDL_ResumeAudioStreamDevice(s.stream);
      }
    }
  }
}
void play_sound(Sound which) {
  auto &s = samples[static_cast<int>(which)];
  if (s.stream) {
    SDL_ClearAudioStream(s.stream);
    SDL_PutAudioStreamData(s.stream, s.data, s.size);
  }
}
struct Client {
  SDL_Window *window{};
  SDL_Renderer *renderer{};
  std::unique_ptr<Display> display;
  Game game;
  Input in;
  Uint64 previous{};
};
static Client client;
static void frame() {
  auto &c = client;
  auto &in = c.in;
  in.click = in.accept = in.previous = in.next = in.escape = in.backspace = false;
  in.text.clear();
  SDL_Event e;
  while (SDL_PollEvent(&e)) {
    SDL_ConvertEventToRenderCoordinates(c.renderer, &e);
    if (e.type == SDL_EVENT_QUIT)
      c.game.quit = true;
    if (e.type == SDL_EVENT_MOUSE_MOTION) {
      in.x = e.motion.x;
      in.y = e.motion.y;
    }
    if ((e.type == SDL_EVENT_MOUSE_BUTTON_DOWN || e.type == SDL_EVENT_MOUSE_BUTTON_UP) &&
        e.button.button == SDL_BUTTON_LEFT) {
      in.x = e.button.x;
      in.y = e.button.y;
      in.fire = e.type == SDL_EVENT_MOUSE_BUTTON_DOWN;
      in.click |= in.fire;
    }
    if (e.type == SDL_EVENT_WINDOW_FOCUS_LOST)
      in.fire = false;
    if (e.type == SDL_EVENT_TEXT_INPUT)
      in.text += e.text.text;
    if (e.type == SDL_EVENT_KEY_DOWN && !e.key.repeat) {
      switch (e.key.scancode) {
      case SDL_SCANCODE_UP:
        in.previous = true;
        break;
      case SDL_SCANCODE_DOWN:
        in.next = true;
        break;
      case SDL_SCANCODE_RETURN:
      case SDL_SCANCODE_KP_ENTER:
        in.accept = true;
        break;
      case SDL_SCANCODE_ESCAPE:
        in.escape = true;
        break;
      case SDL_SCANCODE_BACKSPACE:
        in.backspace = true;
        break;
      default:
        break;
      }
    }
  }
  const bool *keys = SDL_GetKeyboardState(nullptr);
  in.up = keys[SDL_SCANCODE_W] || keys[SDL_SCANCODE_UP];
  in.down = keys[SDL_SCANCODE_S] || keys[SDL_SCANCODE_DOWN];
  in.left = keys[SDL_SCANCODE_A] || keys[SDL_SCANCODE_LEFT];
  in.right = keys[SDL_SCANCODE_D] || keys[SDL_SCANCODE_RIGHT];
  const Uint64 now = SDL_GetTicksNS();
  float dt = std::min(.1f, float(now - c.previous) / 1e9f);
  c.previous = now;
  auto before = c.game.screen;
  Input controls = in;
  controls.fire |= keys[SDL_SCANCODE_TAB];
  c.game.update(dt, controls);
  if (before != c.game.screen) {
    if (c.game.screen == Screen::Death)
      SDL_StartTextInput(c.window);
    else
      SDL_StopTextInput(c.window);
  }
  c.display->draw(c.game);
#ifdef __EMSCRIPTEN__
  if (c.game.quit)
    emscripten_cancel_main_loop();
#endif
}
} // namespace freeware

int main(int argc, char **argv) {
  using namespace freeware;
  if (!SDL_Init(SDL_INIT_VIDEO)) {
    std::fprintf(stderr, "%s\n", SDL_GetError());
    return 1;
  }
  SDL_InitSubSystem(SDL_INIT_AUDIO);
  std::string folder;
#ifdef __EMSCRIPTEN__
  folder = "/assets";
#else
  folder = argc > 1 ? argv[1] : std::string(SDL_GetBasePath()) + "assets";
#endif
  if (!SDL_CreateWindowAndRenderer("Crimsonland v1.4.0", width, height, SDL_WINDOW_RESIZABLE, &client.window,
                                   &client.renderer)) {
    std::fprintf(stderr, "%s\n", SDL_GetError());
    return 1;
  }
  SDL_SetRenderVSync(client.renderer, 1);
  client.display = std::make_unique<Display>(client.renderer);
  if (!client.display->load(folder)) {
    std::fprintf(stderr, "%s\n", SDL_GetError());
    return 1;
  }
  SDL_SetRenderLogicalPresentation(client.renderer, width, height, SDL_LOGICAL_PRESENTATION_LETTERBOX);
  SDL_HideCursor();
  load_audio(folder);
  client.previous = SDL_GetTicksNS();
  std::setvbuf(stdout, nullptr, _IOLBF, 0);
#ifdef __EMSCRIPTEN__
  emscripten_set_main_loop(frame, 0, 1);
#else
  while (!client.game.quit) {
    frame();
    SDL_Delay(1);
  }
  client.display.reset();
  for (auto &s : samples) {
    SDL_DestroyAudioStream(s.stream);
    SDL_free(s.data);
  }
  SDL_DestroyRenderer(client.renderer);
  SDL_DestroyWindow(client.window);
  SDL_Quit();
#endif
  return 0;
}
