#include "display.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

namespace freeware {
void update_music(const Game &, const std::string &);
struct Sample {
  SDL_AudioStream *stream{};
  Uint8 *data{};
  Uint32 size{};
  Uint64 last{};
};
static Sample samples[int(Sound::Count)];
static void load_audio(const std::string &folder) {
  static const char *names[] = {
      "hit_01.wav",     "hit_02.wav",       "pistol_01.wav",  "die_01.wav",    "die_02.wav",
      "die_03.wav",     "die_02.wav",       "gunshot_01.wav", "plasma_01.wav", "attack_01.wav",
      "attack_02.wav",  "attack_03.wav",    "plasma_02.wav",  "wind.wav",      "flamer_01.wav",
      "shotgun_01.wav", "gunreload_01.wav", "levelup.wav",    "bonus.wav",     "berserk.wav",
      "rocket_01.wav",  "explo_01.wav",     nullptr,          nullptr,         nullptr,
      nullptr,          "gunburst.wav",     "drip.wav",       "decay_01.wav"};
  static_assert(sizeof(names) / sizeof(*names) == int(Sound::Count));
  for (int i = 0; i < int(Sound::Count); ++i) {
    if (!names[i])
      continue;
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
void play_original_sample(int id) {
  if (id < 0 || id >= int(Sound::Count))
    return;
  auto &s = samples[id];
  auto now = SDL_GetTicks();
  if (!s.stream || (s.last && now - s.last < (id == 14 ? 580 : 80)))
    return;
  s.last = now;
  SDL_ClearAudioStream(s.stream);
  SDL_PutAudioStreamData(s.stream, s.data, s.size);
}
void play_sound(Sound which) { play_original_sample(int(which)); }
struct Client {
  SDL_Window *window{};
  SDL_Renderer *renderer{};
  std::unique_ptr<Display> display;
  Game game;
  std::string assets;
  Input in;
  SDL_Gamepad *pads[2]{};
  Uint64 previous{};
};
static Client client;
static void frame() {
  auto &c = client;
  auto &in = c.in;
  in.click = in.accept = in.previous = in.next = in.escape = in.backspace = false;
  in.console = false;
  in.level_up = false;
  in.reload = false;
  in.key = 0;
  in.text.clear();
  SDL_Event e;
  while (SDL_PollEvent(&e)) {
    SDL_ConvertEventToRenderCoordinates(c.renderer, &e);
    if (e.type == SDL_EVENT_GAMEPAD_ADDED) {
      for (auto &pad : c.pads)
        if (!pad) {
          pad = SDL_OpenGamepad(e.gdevice.which);
          break;
        }
    } else if (e.type == SDL_EVENT_GAMEPAD_REMOVED) {
      for (auto &pad : c.pads)
        if (pad && SDL_GetGamepadID(pad) == e.gdevice.which) {
          SDL_CloseGamepad(pad);
          pad = nullptr;
        }
    }
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
      in.key = e.key.scancode;
      if (e.key.scancode == SDL_SCANCODE_Q && (e.key.mod & SDL_KMOD_ALT))
        c.game.quit = true;
      switch (e.key.scancode) {
      case SDL_SCANCODE_GRAVE:
        in.console = true;
        break;
      case SDL_SCANCODE_SPACE:
      case SDL_SCANCODE_KP_PLUS:
      case SDL_SCANCODE_EQUALS:
        in.level_up = true;
        break;
      case SDL_SCANCODE_R:
        in.reload = true;
        break;
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
  in.ctrl = keys[SDL_SCANCODE_LCTRL];
  auto held = [&](int actor, int key) { return keys[c.game.keys[actor][key]]; };
  in.up2 = held(1, 0);
  in.down2 = held(1, 1);
  in.left2 = held(1, 2);
  in.right2 = held(1, 3);
  in.fire2 = held(1, 4);
  in.up = held(0, 0) || (!c.game.two_players && in.up2);
  in.down = held(0, 1) || (!c.game.two_players && in.down2);
  in.left = held(0, 2) || (!c.game.two_players && in.left2);
  in.right = held(0, 3) || (!c.game.two_players && in.right2);
  for (int i = 0; i < 2; ++i) {
    auto axis = [&](SDL_GamepadAxis a) { return c.pads[i] ? SDL_GetGamepadAxis(c.pads[i], a) / 32768.f : 0.f; };
    in.stick_x[i] = axis(SDL_GAMEPAD_AXIS_LEFTX);
    in.stick_y[i] = axis(SDL_GAMEPAD_AXIS_LEFTY);
    in.aim_x[i] = axis(SDL_GAMEPAD_AXIS_RIGHTX);
    in.aim_y[i] = axis(SDL_GAMEPAD_AXIS_RIGHTY);
    if (c.pads[i] && std::hypot(in.aim_x[i], in.aim_y[i]) < c.game.pad_threshold[i]) {
      in.aim_x[i] = int(SDL_GetGamepadButton(c.pads[i], SDL_GAMEPAD_BUTTON_DPAD_RIGHT)) -
                    int(SDL_GetGamepadButton(c.pads[i], SDL_GAMEPAD_BUTTON_DPAD_LEFT));
      in.aim_y[i] = int(SDL_GetGamepadButton(c.pads[i], SDL_GAMEPAD_BUTTON_DPAD_DOWN)) -
                    int(SDL_GetGamepadButton(c.pads[i], SDL_GAMEPAD_BUTTON_DPAD_UP));
    }
    in.pad_fire[i] = c.pads[i] && (SDL_GetGamepadButton(c.pads[i], SDL_GAMEPAD_BUTTON_SOUTH) ||
                                   axis(SDL_GAMEPAD_AXIS_RIGHT_TRIGGER) > .3f);
  }
  const Uint64 now = SDL_GetTicksNS();
  float dt = std::min(.1f, float(now - c.previous) / 1e9f);
  c.previous = now;
  bool was_text = c.game.screen == Screen::Death || c.game.console_open;
  Input controls = in;
  controls.mouse_fire = in.fire;
  controls.fire |= held(0, 4) || (!c.game.two_players && in.fire2);
  c.game.update(dt, controls);
  bool wants_text = c.game.screen == Screen::Death || c.game.console_open;
  if (was_text != wants_text) {
    if (wants_text)
      SDL_StartTextInput(c.window);
    else
      SDL_StopTextInput(c.window);
  }
  if (c.game.visit_website) {
    SDL_OpenURL("https://www.crimsonland.com/");
    c.game.visit_website = false;
  }
  update_music(c.game, c.assets);
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
  SDL_InitSubSystem(SDL_INIT_GAMEPAD);
#ifdef __EMSCRIPTEN__
  client.game.save_dir = "/freeware/";
#else
  if (const char *path = std::getenv("CRIMSON_FREEWARE_SAVE_DIR")) {
    client.game.save_dir = std::string(path) + "/";
    SDL_CreateDirectory(path);
  } else if (char *path = SDL_GetPrefPath("10tons", "Crimsonland-1.4.0")) {
    client.game.save_dir = path;
    SDL_free(path);
  }
#endif
  client.game.load_scores();
  client.game.load_options();
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
  client.assets = folder;
  load_audio(folder);
  seed_random(static_cast<unsigned>(SDL_GetPerformanceCounter()));
  client.game.generate_terrain();
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
  for (auto *pad : client.pads)
    if (pad)
      SDL_CloseGamepad(pad);
  SDL_DestroyRenderer(client.renderer);
  SDL_DestroyWindow(client.window);
  SDL_Quit();
#endif
  return 0;
}
