#include "display.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ctime>
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
static bool quiet_samples;
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
  SDL_SetAudioStreamGain(s.stream, quiet_samples ? .15f : .45f);
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
// DirectInput values read by the original editor's fixed (non-rebindable) shortcuts.
struct LevelKey {
  unsigned char code;
  SDL_Scancode scan;
};
static constexpr LevelKey level_keys[] = {
    {0x4a, SDL_SCANCODE_KP_MINUS}, {0x4e, SDL_SCANCODE_KP_PLUS}, {0xc9, SDL_SCANCODE_PAGEUP},
    {0xd1, SDL_SCANCODE_PAGEDOWN}, {0xc7, SDL_SCANCODE_HOME},    {0xcf, SDL_SCANCODE_END},
    {0x2a, SDL_SCANCODE_LSHIFT},   {0xd2, SDL_SCANCODE_INSERT},  {0xd3, SDL_SCANCODE_DELETE},
    {0xcb, SDL_SCANCODE_LEFT},     {0xcd, SDL_SCANCODE_RIGHT},   {0xc8, SDL_SCANCODE_UP},
    {0xd0, SDL_SCANCODE_DOWN},     {2, SDL_SCANCODE_1},          {3, SDL_SCANCODE_2},
    {4, SDL_SCANCODE_3},           {0x1f, SDL_SCANCODE_S},       {0x26, SDL_SCANCODE_L},
    {0x13, SDL_SCANCODE_R},        {0x2e, SDL_SCANCODE_C},       {0x11, SDL_SCANCODE_W},
    {0x39, SDL_SCANCODE_SPACE},    {0x2f, SDL_SCANCODE_V},       {0x1e, SDL_SCANCODE_A},
    {0x2c, SDL_SCANCODE_Z},        {0x14, SDL_SCANCODE_T},       {0x30, SDL_SCANCODE_B}};
static Client client;
static void frame() {
  auto &c = client;
  auto &in = c.in;
  in.click = in.accept = in.previous = in.next = in.escape = in.backspace = false;
  in.console = in.screenshot = in.space_pressed = in.delete_scores = false;
  in.dx = in.dy = 0;
  in.level_up = in.perk_button = false;
  in.fire_edge[0] = in.fire_edge[1] = false;
  in.reload = false;
  in.key = 0;
  in.level_pressed.reset();
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
      in.dx += e.motion.xrel != 0 ? e.motion.xrel : e.motion.x - in.x;
      in.dy += e.motion.yrel != 0 ? e.motion.yrel : e.motion.y - in.y;
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
    if ((e.type == SDL_EVENT_MOUSE_BUTTON_DOWN || e.type == SDL_EVENT_MOUSE_BUTTON_UP) &&
        e.button.button == SDL_BUTTON_MIDDLE)
      in.mouse_reload = e.type == SDL_EVENT_MOUSE_BUTTON_DOWN;
    if (e.type == SDL_EVENT_MOUSE_BUTTON_DOWN && e.button.button == SDL_BUTTON_RIGHT)
      in.perk_button = true;
    if (e.type == SDL_EVENT_WINDOW_FOCUS_LOST)
      in.fire = in.mouse_reload = false;
    if (e.type == SDL_EVENT_TEXT_INPUT)
      in.text += e.text.text;
    if (e.type == SDL_EVENT_KEY_DOWN && !e.key.repeat) {
      in.key = e.key.scancode;
      if (c.game.level_mode == 4)
        for (auto k : level_keys)
          if (k.scan == e.key.scancode)
            in.level_pressed.set(k.code);
      for (int i = 0; i < 2; ++i)
        in.fire_edge[i] |= int(e.key.scancode) == c.game.keys[i][4];
      if (e.key.scancode == SDL_SCANCODE_Q && (e.key.mod & SDL_KMOD_ALT))
        c.game.quit = true;
      switch (e.key.scancode) {
      case SDL_SCANCODE_F12:
        in.screenshot = true;
        break;
      case SDL_SCANCODE_GRAVE:
        in.console = true;
        break;
      case SDL_SCANCODE_D:
        in.delete_scores = true;
        break;
      case SDL_SCANCODE_SPACE:
        in.space_pressed = true;
        in.level_up = true;
        break;
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
  if (c.game.level_mode == 4)
    for (auto k : level_keys)
      in.level_down.set(k.code, keys[k.scan]);
  auto held = [&](int actor, int key) { return keys[c.game.keys[actor][key]]; };
  in.up2 = held(1, 0);
  in.down2 = held(1, 1);
  in.left2 = held(1, 2);
  in.right2 = held(1, 3);
  in.fire2 = held(1, 4);
  in.up = held(0, 0);
  in.down = held(0, 1);
  in.left = held(0, 2);
  in.right = held(0, 3);
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
    in.pad_any[i] = false;
    if (c.pads[i])
      for (int b = 0; b < 5; ++b)
        in.pad_any[i] |= SDL_GetGamepadButton(c.pads[i], static_cast<SDL_GamepadButton>(b));
    in.pad_perk[i] = c.pads[i] && SDL_GetGamepadButton(c.pads[i], SDL_GAMEPAD_BUTTON_EAST);
    in.pad_fire[i] = c.pads[i] && (SDL_GetGamepadButton(c.pads[i], SDL_GAMEPAD_BUTTON_SOUTH) ||
                                   axis(SDL_GAMEPAD_AXIS_RIGHT_TRIGGER) > .3f);
  }
  const Uint64 now = SDL_GetTicksNS();
  float dt = std::min(.1f, float(now - c.previous) / 1e9f);
  c.previous = now;
  bool was_text = c.game.screen == Screen::Death || c.game.console_open;
  Input controls = in;
  controls.arrow_down = keys[SDL_SCANCODE_DOWN];
  controls.arrow_up = keys[SDL_SCANCODE_UP];
  controls.relative = c.game.screen == Screen::Playing;
  controls.mouse_fire = in.fire;
  controls.fire = held(0, 4);
  controls.reload |= keys[SDL_SCANCODE_R];
  controls.level_up |= keys[SDL_SCANCODE_SPACE] || keys[SDL_SCANCODE_KP_PLUS];
  c.game.update(dt, controls);
  quiet_samples = c.game.sound_quiet;
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
  std::time_t now = std::time(nullptr);
  if (const std::tm *date = std::localtime(&now); date && FREEWARE_EDITION != 10002) {
    auto &game = freeware::client.game;
    game.birthday = date->tm_mon == 8 && date->tm_mday == 12;
    game.memorial = date->tm_mon == 8 && date->tm_mday == 11;
    game.christmas = date->tm_mon == 11 && (date->tm_mday == 24 || date->tm_mday == 25);
    game.solstice = date->tm_mon == 11 && date->tm_year == 112;
    if (date->tm_mon == 7 && date->tm_mday >= 1 && date->tm_mday <= 4)
      game.assembly_sequence = 8;
  }

  using namespace freeware;
  if (!SDL_Init(SDL_INIT_VIDEO)) {
    std::fprintf(stderr, "%s\n", SDL_GetError());
    return 1;
  }
  SDL_InitSubSystem(SDL_INIT_AUDIO);
  SDL_InitSubSystem(SDL_INIT_GAMEPAD);
#ifdef __EMSCRIPTEN__
#if FREEWARE_EDITION == 10400
  client.game.save_dir = "/freeware/";
#else
  client.game.save_dir = "/freeware-" FREEWARE_VERSION "/";
#endif
#else
  if (const char *path = std::getenv("CRIMSON_FREEWARE_SAVE_DIR")) {
    client.game.save_dir = std::string(path) + "/";
    SDL_CreateDirectory(path);
  } else if (char *path = SDL_GetPrefPath("10tons", "Crimsonland-" FREEWARE_VERSION)) {
    client.game.save_dir = path;
    SDL_free(path);
  }
#endif
  std::string folder;
#ifdef __EMSCRIPTEN__
  folder = "/assets";
#else
  folder = argc > 1 ? argv[1] : std::string(SDL_GetBasePath()) + "assets";
#endif
  if (!SDL_CreateWindowAndRenderer("Crimsonland v" FREEWARE_VERSION, width, height, SDL_WINDOW_RESIZABLE, &client.window,
                                   &client.renderer)) {
    std::fprintf(stderr, "%s\n", SDL_GetError());
    return 1;
  }
  client.game.safe_mode = std::string(SDL_GetRendererName(client.renderer)) == "software";
  SDL_SetRenderVSync(client.renderer, 1);
  client.display = std::make_unique<Display>(client.renderer);
  if (!client.display->load(folder, client.game.safe_mode)) {
    std::fprintf(stderr, "%s\n", SDL_GetError());
    return 1;
  }
  SDL_SetRenderLogicalPresentation(client.renderer, width, height, SDL_LOGICAL_PRESENTATION_LETTERBOX);
  SDL_HideCursor();
  client.game.asset_dir = client.assets = folder;
  client.game.load_level_brushes();
  client.game.load_scores();
  client.game.load_options();
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
