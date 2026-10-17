// The client: an SDL3 window running the game module one frame per callback.
// Usage: crimson [game directory]. Without one it plays from the player's data
// folder, the Python game's too, and downloads the game's files it lacks.
#define SDL_MAIN_USE_CALLBACKS
#include "client.h"
#include "network.h"
#include "assets.h"
#include <memory>
#include <ctime>
#include "../game/host_input.h"
#include "../game/leaderboard_requests.h"
#include <SDL3/SDL.h>
#include <SDL3/SDL_main.h>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#else
#include <curl/curl.h>
#endif
#include <math.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct w2c_host {};
struct w2c_wasi__snapshot__preview1 {};

namespace {

w2c_game game;
w2c_host host;
w2c_wasi__snapshot__preview1 wasi;
std::string game_directory = ".";
SDL_Window *window;
SDL_GLContext context;
float wheel;
// Every gamepad SDL reports is open; the one used last plays: a pad takes over
// with a fresh press, not while its inputs are merely held (`held`, last frame's).
struct Pad {
  SDL_Gamepad *gamepad;
  Uint64 held;
};
std::vector<Pad> gamepads;
SDL_Gamepad *gamepad;
bool held[8];
int hold_frames[8];
// The window has the player: away (blurred, minimized, a hidden tab), no input reaches the game, the pad's
// neither (a co-op session plays on there, on neutral records).
bool focused = true;

// SDL scancodes to the DirectInput scancodes the game binds.
unsigned char dik(SDL_Scancode s) {
  if (s >= SDL_SCANCODE_A && s <= SDL_SCANCODE_Z) {
    static const unsigned char letters[] = {0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17,
                                            0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13,
                                            0x1f, 0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c};
    return letters[s - SDL_SCANCODE_A];
  }
  if (s >= SDL_SCANCODE_1 && s <= SDL_SCANCODE_0)
    return (unsigned char)(0x02 + (s - SDL_SCANCODE_1));
  if (s >= SDL_SCANCODE_F1 && s <= SDL_SCANCODE_F10)
    return (unsigned char)(0x3b + (s - SDL_SCANCODE_F1));
  switch (s) {
  case SDL_SCANCODE_RETURN: return 0x1c;
  case SDL_SCANCODE_ESCAPE: return 0x01;
  case SDL_SCANCODE_BACKSPACE: return 0x0e;
  case SDL_SCANCODE_TAB: return 0x0f;
  case SDL_SCANCODE_SPACE: return 0x39;
  case SDL_SCANCODE_MINUS: return 0x0c;
  case SDL_SCANCODE_EQUALS: return 0x0d;
  case SDL_SCANCODE_LEFTBRACKET: return 0x1a;
  case SDL_SCANCODE_RIGHTBRACKET: return 0x1b;
  case SDL_SCANCODE_BACKSLASH: return 0x2b;
  case SDL_SCANCODE_SEMICOLON: return 0x27;
  case SDL_SCANCODE_APOSTROPHE: return 0x28;
  case SDL_SCANCODE_GRAVE: return 0x29;
  case SDL_SCANCODE_COMMA: return 0x33;
  case SDL_SCANCODE_PERIOD: return 0x34;
  case SDL_SCANCODE_SLASH: return 0x35;
  case SDL_SCANCODE_CAPSLOCK: return 0x3a;
  case SDL_SCANCODE_F11: return 0x57;
  case SDL_SCANCODE_F12: return 0x58;
  case SDL_SCANCODE_PRINTSCREEN: return 0xb7;
  case SDL_SCANCODE_SCROLLLOCK: return 0x46;
  case SDL_SCANCODE_PAUSE: return 0xc5;
  case SDL_SCANCODE_INSERT: return 0xd2;
  case SDL_SCANCODE_HOME: return 0xc7;
  case SDL_SCANCODE_PAGEUP: return 0xc9;
  case SDL_SCANCODE_DELETE: return 0xd3;
  case SDL_SCANCODE_END: return 0xcf;
  case SDL_SCANCODE_PAGEDOWN: return 0xd1;
  case SDL_SCANCODE_RIGHT: return 0xcd;
  case SDL_SCANCODE_LEFT: return 0xcb;
  case SDL_SCANCODE_DOWN: return 0xd0;
  case SDL_SCANCODE_UP: return 0xc8;
  case SDL_SCANCODE_NUMLOCKCLEAR: return 0x45;
  case SDL_SCANCODE_KP_DIVIDE: return 0xb5;
  case SDL_SCANCODE_KP_MULTIPLY: return 0x37;
  case SDL_SCANCODE_KP_MINUS: return 0x4a;
  case SDL_SCANCODE_KP_PLUS: return 0x4e;
  case SDL_SCANCODE_KP_ENTER: return 0x9c;
  case SDL_SCANCODE_KP_1: return 0x4f;
  case SDL_SCANCODE_KP_2: return 0x50;
  case SDL_SCANCODE_KP_3: return 0x51;
  case SDL_SCANCODE_KP_4: return 0x4b;
  case SDL_SCANCODE_KP_5: return 0x4c;
  case SDL_SCANCODE_KP_6: return 0x4d;
  case SDL_SCANCODE_KP_7: return 0x47;
  case SDL_SCANCODE_KP_8: return 0x48;
  case SDL_SCANCODE_KP_9: return 0x49;
  case SDL_SCANCODE_KP_0: return 0x52;
  case SDL_SCANCODE_KP_PERIOD: return 0x53;
  case SDL_SCANCODE_LCTRL: return 0x1d;
  case SDL_SCANCODE_LSHIFT: return 0x2a;
  case SDL_SCANCODE_LALT: return 0x38;
  case SDL_SCANCODE_LGUI: return 0xdb;
  case SDL_SCANCODE_RCTRL: return 0x9d;
  case SDL_SCANCODE_RSHIFT: return 0x36;
  case SDL_SCANCODE_RALT: return 0xb8;
  case SDL_SCANCODE_RGUI: return 0xdc;
  default: return 0;
  }
}

HostInput *input() { return (HostInput *)(client_memory() + w2c_game_game_input(&game)); }

void key(SDL_Scancode scancode, bool down) {
  unsigned char code = dik(scancode);
  if (!code)
    return;
  HostInput *in = input();
  in->keys[code] = down ? 0x80 : 0;
  if (in->key_event_count < 32)
    in->key_events[in->key_event_count++] = {code, (unsigned char)down};
  // WM_CHAR delivers these control characters too.
  if (down && (scancode == SDL_SCANCODE_BACKSPACE || scancode == SDL_SCANCODE_RETURN))
    w2c_game_game_key_char(&game, scancode == SDL_SCANCODE_BACKSPACE ? 8 : 13);
}

// CRIMSON_CAPTURE=<directory> saves the back buffer of the frames listed in
// CRIMSON_CAPTURE_FRAMES (comma-separated: host frames that draw) as
// frame_<n>.ppm, then quits. Such a run's clock moves 16 ms a frame, so
// scripted input (CRIMSON_INPUT) lands on the same frames every time.
std::vector<int> capture_frames;
int presented, frames, captured_frame = -1;
bool capture_done;
const bool unattended = getenv("CRIMSON_CAPTURE");
void capture_frame() {
  ++presented;
  const char *directory = getenv("CRIMSON_CAPTURE");
  if (!directory)
    return;
  if (capture_frames.empty() && !capture_done)
    for (const char *p = getenv("CRIMSON_CAPTURE_FRAMES"); p && *p; p = strchr(p, ',') ? strchr(p, ',') + 1 : "")
      capture_frames.push_back(atoi(p));
  capture_done = true;
  for (size_t i = 0; i < capture_frames.size(); ++i) {
    if (capture_frames[i] != frames)
      continue;
    int width, height;
    std::vector<unsigned char> pixels = renderer_capture(width, height);
    std::string path = std::string(directory) + "/frame_" + std::to_string(frames) + ".ppm";
    if (FILE *fp = fopen(path.c_str(), "wb")) {
      fprintf(fp, "P6\n%d %d\n255\n", width, height);
      for (int y = 0; y < height; ++y)
        for (int x = 0; x < width; ++x)
          fwrite(&pixels[((size_t)y * width + x) * 4], 1, 3, fp);
      fclose(fp);
    }
    captured_frame = frames;
    capture_frames.erase(capture_frames.begin() + i);
    if (capture_frames.empty())
      w2c_game_game_close(&game);
    break;
  }
}

// CRIMSON_INPUT scripts input for unattended runs: "frame:action;..." (host
// frames) where an
// action is "move x y" (back-buffer pixels), "press button" or "release button"
// (0 left, 1 right), or "key code" / "unkey code" (DirectInput scancodes, hex).
// Virtual gamepads stand in for real ones: "padattach n", "paddetach n",
// "padbutton name 0|1 n" and "padaxis name value n" for pad n, 0 when left out
// (SDL's names: "a", "dpup", "start", "leftx", "righttrigger"; axes -32768 to 32767).
SDL_Joystick *scripted_pads[4];
void script_pad(const char *verb, const char *name, int value, int index) {
  SDL_Joystick *&joystick = scripted_pads[index & 3];
  if (!strcmp(verb, "padattach") && !joystick) {
    SDL_VirtualJoystickDesc desc;
    SDL_INIT_INTERFACE(&desc);
    desc.type = SDL_JOYSTICK_TYPE_GAMEPAD;
    desc.naxes = SDL_GAMEPAD_AXIS_COUNT;
    desc.nbuttons = SDL_GAMEPAD_BUTTON_COUNT;
    desc.name = "Scripted gamepad";
    joystick = SDL_OpenJoystick(SDL_AttachVirtualJoystick(&desc));
  } else if (!strcmp(verb, "paddetach") && joystick) {
    SDL_JoystickID id = SDL_GetJoystickID(joystick);
    SDL_CloseJoystick(joystick);
    SDL_DetachVirtualJoystick(id);
    joystick = nullptr;
  } else if (!strcmp(verb, "padbutton") && joystick) {
    SDL_SetJoystickVirtualButton(joystick, SDL_GetGamepadButtonFromString(name), value != 0);
  } else if (!strcmp(verb, "padaxis") && joystick) {
    SDL_SetJoystickVirtualAxis(joystick, SDL_GetGamepadAxisFromString(name), (Sint16)value);
  }
}
struct Scripted {
  int frame;
  std::string action;
};
std::vector<Scripted> script;
bool script_loaded;
float scripted_x = -1, scripted_y = -1;
void run_script(int frame) {
  if (!script_loaded) {
    script_loaded = true;
    if (const char *text = getenv("CRIMSON_INPUT")) {
      std::string all = text;
      for (size_t start = 0; start < all.size();) {
        size_t end = all.find(';', start);
        std::string item = all.substr(start, end == std::string::npos ? std::string::npos : end - start);
        size_t colon = item.find(':');
        if (colon != std::string::npos)
          script.push_back({atoi(item.c_str()), item.substr(colon + 1)});
        start = end == std::string::npos ? all.size() : end + 1;
      }
    }
  }
  for (const Scripted &s : script) {
    if (s.frame != frame)
      continue;
    char verb[16] = {}, name[32] = {};
    float a = 0, b = 0;
    sscanf(s.action.c_str(), "%15s %f %f", verb, &a, &b);
    HostInput *in = input();
    if (!strncmp(verb, "pad", 3)) {
      int value = 0, index = 0;
      if (!strcmp(verb, "padattach") || !strcmp(verb, "paddetach"))
        sscanf(s.action.c_str(), "%*s %d", &index);
      else
        sscanf(s.action.c_str(), "%*s %31s %d %d", name, &value, &index);
      script_pad(verb, name, value, index);
    } else if (!strcmp(verb, "move")) {
      scripted_x = a;
      scripted_y = b;
    } else if (!strcmp(verb, "press") || !strcmp(verb, "release")) {
      in->mouse_buttons[(int)a] = verb[0] == 'p' ? 0x80 : 0;
    } else if (!strcmp(verb, "key") || !strcmp(verb, "unkey")) {
      unsigned code = (unsigned)strtoul(s.action.c_str() + strlen(verb), nullptr, 16);
      in->keys[code & 255] = verb[0] == 'k' ? 0x80 : 0;
      if (in->key_event_count < 32)
        in->key_events[in->key_event_count++] = {(unsigned char)code, (unsigned char)(verb[0] == 'k')};
    }
  }
}

// The buttons held, and the sticks and triggers past half travel, either way, as bits.
static_assert(SDL_GAMEPAD_BUTTON_COUNT + 2 * SDL_GAMEPAD_AXIS_COUNT <= 64, "a pad's inputs fit its bits");
Uint64 pad_held(SDL_Gamepad *pad) {
  Uint64 held = 0;
  for (int button = 0; button < SDL_GAMEPAD_BUTTON_COUNT; ++button)
    held |= (Uint64)SDL_GetGamepadButton(pad, (SDL_GamepadButton)button) << button;
  for (int axis = 0; axis < SDL_GAMEPAD_AXIS_COUNT; ++axis) {
    int value = SDL_GetGamepadAxis(pad, (SDL_GamepadAxis)axis);
    held |= (Uint64)(value > 16384) << (SDL_GAMEPAD_BUTTON_COUNT + 2 * axis);
    held |= (Uint64)(value < -16384) << (SDL_GAMEPAD_BUTTON_COUNT + 2 * axis + 1);
  }
  return held;
}

// No stick pushed, no button held, the hat centred.
void pad_release(HostInput *in) {
  memset(in->pad_axes, 0, sizeof in->pad_axes);
  memset(in->pad_buttons, 0, sizeof in->pad_buttons);
  in->pad_hat = ~0u;
}

// The gamepad, as the Logitech Dual Action layout the module's joystick reports
// (game/dinput.cpp): buttons 1-4 are the west, south, east and north faces, then
// the shoulders, the triggers, back, start and the stick clicks. SDL lays out
// PlayStation, Xbox and Switch pads alike, the faces by position.
void pad(HostInput *in) {
  pad_release(in);
  for (Pad &pad : gamepads) {
    Uint64 held = pad_held(pad.gamepad);
    if (held & ~pad.held)
      gamepad = pad.gamepad;
    pad.held = held;
  }
  in->pad_connected = gamepad != nullptr;
  if (!gamepad)
    return;
  static const SDL_GamepadAxis axes[] = {SDL_GAMEPAD_AXIS_LEFTX, SDL_GAMEPAD_AXIS_LEFTY, SDL_GAMEPAD_AXIS_RIGHTX,
                                         SDL_GAMEPAD_AXIS_RIGHTY};
  for (int i = 0; i < 4; ++i)
    in->pad_axes[i] = SDL_GetGamepadAxis(gamepad, axes[i]) * 1000 / 32767;
  static const SDL_GamepadButton buttons[] = {SDL_GAMEPAD_BUTTON_WEST,       SDL_GAMEPAD_BUTTON_SOUTH,
                                              SDL_GAMEPAD_BUTTON_EAST,       SDL_GAMEPAD_BUTTON_NORTH,
                                              SDL_GAMEPAD_BUTTON_LEFT_SHOULDER, SDL_GAMEPAD_BUTTON_RIGHT_SHOULDER};
  for (int i = 0; i < 6; ++i)
    in->pad_buttons[i] = SDL_GetGamepadButton(gamepad, buttons[i]) ? 0x80 : 0;
  in->pad_buttons[6] = SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_LEFT_TRIGGER) > 16384 ? 0x80 : 0;
  in->pad_buttons[7] = SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_RIGHT_TRIGGER) > 16384 ? 0x80 : 0;
  static const SDL_GamepadButton rest[] = {SDL_GAMEPAD_BUTTON_BACK, SDL_GAMEPAD_BUTTON_START,
                                           SDL_GAMEPAD_BUTTON_LEFT_STICK, SDL_GAMEPAD_BUTTON_RIGHT_STICK};
  for (int i = 0; i < 4; ++i)
    in->pad_buttons[8 + i] = SDL_GetGamepadButton(gamepad, rest[i]) ? 0x80 : 0;
  int x = SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_DPAD_RIGHT) - SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_DPAD_LEFT);
  int y = SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_DPAD_DOWN) - SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_DPAD_UP);
  if (x || y)
    in->pad_hat = ((int)lroundf(atan2f((float)x, (float)-y) * 18000 / (float)M_PI) + 36000) % 36000;
}

} // namespace

u8 *client_memory() { return w2c_game_memory(&game)->data; }
const std::string &client_game_directory() { return game_directory; }
void client_fatal(const char *message) {
  SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Crimsonland", message, window);
  fprintf(stderr, "crimson: %s\n", message);
  exit(1);
}

#ifndef __EMSCRIPTEN__
namespace { void network_request(int request); }
#endif

extern "C" {
void w2c_host_fatal(struct w2c_host *, u32 message) { client_fatal((const char *)client_memory() + message); }
// The original's message boxes: startup failures and warnings the player must see.
void w2c_host_message(struct w2c_host *, u32 text, u32 caption) {
  const char *body = (const char *)client_memory() + text, *title = (const char *)client_memory() + caption;
  fprintf(stderr, "%s: %s\n", title, body);
  SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, title, body, window);
}
// The leaderboard (host/ranked.inc): the page signs in and uploads
// (client/web/shell.html); the native client uses the same protocol through its worker.
void w2c_host_leaderboard(struct w2c_host *, u32 request) {
#ifdef __EMSCRIPTEN__
  MAIN_THREAD_EM_ASM({ Module.leaderboard($0); }, request);
#else
  network_request((int)request);
#endif
}
// An unattended run's clock moves 16 ms a frame, and a millisecond each time it is read.
u32 w2c_host_time_ms(struct w2c_host *) {
  static u32 reads;
  return unattended ? (u32)frames * 16 + reads++ : (u32)SDL_GetTicks();
}
static void show_frame(int width, int height) {
  renderer_present(width, height);
  SDL_GL_SwapWindow(window);
  renderer_resume();
}
void w2c_host_present(struct w2c_host *) {
  int width, height;
  SDL_GetWindowSizeInPixels(window, &width, &height);
  capture_frame();
  show_frame(width, height);
}
}

// CRIMSON_WATCH=<replay> plays a replay, from the game folder, as a link to a
// run does, for unattended captures: CRIMSON_WATCH_SEEK=<tick> goes to a tick
// once it is prepared, and CRIMSON_WATCH_STOP=<tick> pauses playback there;
// CRIMSON_WATCH_CARD=<name>,<rank>,<day>,<month>,<year> gives its card's runner.
void watch_from_env() {
  static bool asked;
  const char *path = getenv("CRIMSON_WATCH");
  if (asked || !path)
    return;
  asked = true;
  snprintf((char *)client_memory() + w2c_game_game_replay_path(&game), 256, "%s", path);
  char name[32] = "";
  int rank = 0, day = 0, month = 0, year = 2000;
  if (const char *card = getenv("CRIMSON_WATCH_CARD"))
    sscanf(card, "%31[^,],%d,%d,%d,%d", name, &rank, &day, &month, &year);
  snprintf((char *)client_memory() + w2c_game_game_watch_name(&game), 32, "%s", name);
  if (!w2c_game_game_replay_open(&game) || !w2c_game_game_watch(&game, rank, day, month, year))
    client_fatal("CRIMSON_WATCH: this replay does not play");
  if (const char *seek = getenv("CRIMSON_WATCH_SEEK"))
    w2c_game_game_watch_seek(&game, atoi(seek));
  if (const char *stop = getenv("CRIMSON_WATCH_STOP"))
    w2c_game_game_watch_stop_at(&game, atoi(stop));
}

#ifndef __EMSCRIPTEN__
namespace {
std::unique_ptr<LeaderboardNetwork> network;
std::string linked_replay;
std::string profile_key;
bool profile_pending;
Uint64 next_upload;
std::deque<int> network_requests;
void network_request(int request) { network_requests.push_back(request); }
void network_submit(int request) {
  if (!network || !network->enabled())
    return;
  using N = LeaderboardNetwork;
  if (request == HOST_LEADERBOARD_UPLOAD)
    network->request(N::UPLOAD);
  else if (request == HOST_LEADERBOARD_SCORES)
    network->request(N::SCORES, (char *)client_memory() +
                                    w2c_game_game_scores_request(&game));
  else if (request == HOST_LEADERBOARD_REPLAY)
    network->request(N::REPLAY, (char *)client_memory() +
                                    w2c_game_game_replay_download(&game));
  else if (request == HOST_LEADERBOARD_PROFILE) {
    if (profile_pending)
      return;
    // The key and challenge signature are read only on the main thread.
    u32 key_at = w2c_game_game_identity_public_key(&game);
    std::string key = (char *)client_memory() + key_at;
    if (!N::run_id(key)) {
      SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, "Leaderboard",
                               "Could not load your identity key.", window);
      return;
    }
    if (network->request(N::CHALLENGE,
                         "{\"public_key\":" + N::quote(key) + "}")) {
      profile_key = key;
      profile_pending = true;
    }
  }
}
void network_update() {
  if (!network)
    return;
  while (!network_requests.empty()) {
    int request = network_requests.front();
    network_requests.pop_front();
    network_submit(request);
  }
  using N = LeaderboardNetwork;
  N::Event event{N::UPLOAD};
  while (network->poll(event)) {
    if (event.kind == N::SCORES) {
      int size = event.ok ? (int)event.body.size() : -1;
      if (event.ok) {
        u32 buffer = w2c_game_game_scores_buffer(&game, size);
        memcpy(client_memory() + buffer, event.body.data(), event.body.size());
      }
      w2c_game_game_scores_received(&game, size);
    } else if (event.kind == N::REPLAY) {
      w2c_game_game_replay_downloaded(&game, event.ok              ? 0
                                             : event.status == 404 ? 1
                                                                   : 2);
    } else if (event.kind == N::LINK) {
      const char *reason = event.status == 404
                               ? "This run is no longer on the leaderboard."
                               : "Could not download this run.";
      if (event.ok) {
        snprintf((char *)client_memory() + w2c_game_game_replay_path(&game),
                 256, "%s", event.body.c_str());
        snprintf((char *)client_memory() + w2c_game_game_watch_name(&game), 32,
                 "%s", event.runner.c_str());
        int day = 0, month = 0, year = 2000;
        time_t when = (time_t)(event.accepted_at / 1000);
        if (event.accepted_at && (when >= 0))
          if (tm *date = localtime(&when)) {
            day = date->tm_mday;
            month = date->tm_mon + 1;
            year = date->tm_year + 1900;
          }
        if (!w2c_game_game_replay_open(&game))
          reason = (char *)client_memory() + w2c_game_game_replay_reason(&game);
        else if (w2c_game_game_watch(&game, event.rank, day, month, year))
          reason = nullptr;
        else
          reason = "This run cannot play now.";
      }
      if (reason)
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, "Replay", reason,
                                 window);
    } else if (event.kind == N::CHALLENGE && event.ok) {
      snprintf((char *)client_memory() + w2c_game_game_login_challenge(&game),
               65, "%s", event.body.c_str());
      u32 signature_at = w2c_game_game_login_signature(&game);
      std::string signature = (char *)client_memory() + signature_at;
      if (signature.empty() ||
          !network->request(
              N::LOGIN, "{\"public_key\":" + N::quote(profile_key) +
                            ",\"challenge\":" + N::quote(event.body) +
                            ",\"signature\":" + N::quote(signature) + "}")) {
        profile_pending = false;
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, "Leaderboard",
                                 "Could not sign in. Try again later.", window);
      }
    } else if (event.kind == N::LOGIN && event.ok) {
      profile_pending = false;
      if (!SDL_OpenURL(event.body.c_str()))
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, "Leaderboard",
                                 "Could not open your browser.", window);
    } else if (event.kind == N::CHALLENGE || event.kind == N::LOGIN) {
      profile_pending = false;
      SDL_ShowSimpleMessageBox(
          SDL_MESSAGEBOX_WARNING, "Leaderboard",
          "Can't sign in to the leaderboard. Try again later.", window);
    }
    if (!event.error.empty())
      fprintf(stderr, "leaderboard: %s\n", event.error.c_str());
  }
  Uint64 now = SDL_GetTicks();
  if (now >= next_upload) {
    network->request(N::UPLOAD);
    next_upload = now + 600000;
  }
}
} // namespace
#endif

bool started;

// Co-op (docs/rewrite/network-coop.md §6): the page's transport
// (client/web/coop.js) carries the session's bytes (host/coop_wire.inc) on two
// channels, and the client pumps them between it and the game on the clock
// host_time_ms reads. The page calls the client_coop_* exports; after each
// frame the session's outgoing messages go to Module.coopSend. Only the browser
// has a transport: a native build keeps the exports, which nothing calls.
#ifdef __EMSCRIPTEN__
#define CLIENT_EXPORT extern "C" EMSCRIPTEN_KEEPALIVE
#else
#define CLIENT_EXPORT extern "C"
#endif
double coop_now() { return w2c_host_time_ms(&host); }
// The transport connected this page as `seat` (0 the room's host, 1 its guest): a session begins.
// -1 before the game has started.
CLIENT_EXPORT int client_coop_connect(int seat) {
  return started ? (int)w2c_game_game_coop_connect(&game, seat, coop_now()) : -1;
}
// The transport closed, or the partner's page went (host/coop_wire.inc CoopReason).
CLIENT_EXPORT int client_coop_disconnect(int reason) { return w2c_game_game_coop_disconnect(&game, reason); }
// A message on `channel`, copied onto the page's stack by Module.ccall: the
// game's buffer first, since making room can move the module's memory.
CLIENT_EXPORT void client_coop_receive(int channel, const u8 *bytes, int size) {
  u32 buffer = w2c_game_game_coop_rx(&game, size);
  memcpy(client_memory() + buffer, bytes, size);
  w2c_game_game_coop_receive(&game, channel, size, coop_now());
}
// game_coop_status's flags and reasons, for the page; for checks (checks/coop_browser.mjs) also the run's
// confirmed tick (-1 none) and the screen the game shows (game_state_id_t, -1 before it started).
CLIENT_EXPORT u32 client_coop_status() { return started ? w2c_game_game_coop_status(&game) : 0; }
CLIENT_EXPORT int client_coop_confirmed() { return started ? (int)w2c_game_game_coop_confirmed(&game) : -1; }
CLIENT_EXPORT int client_game_state() { return started ? (int)w2c_game_game_state(&game) : -1; }
// What the session has to send, each message copied out of the module before
// the page takes it.
void coop_send() {
#ifdef __EMSCRIPTEN__
  static std::vector<u8> staging;
  for (int channel = 0; channel < 2; ++channel)
    for (int size; (size = (int)w2c_game_game_coop_tx(&game, channel, coop_now())) > 0;) {
      const u8 *message = client_memory() + w2c_game_game_coop_tx_buffer(&game);
      staging.assign(message, message + size);
      MAIN_THREAD_EM_ASM({ Module.coopSend($0, HEAPU8.slice($1, $1 + $2)); }, channel, staging.data(), size);
    }
#endif
}

bool start_game() {
  wasm_rt_init();
  client_wasi_init();
  wasm2c_game_instantiate(&game, &host, &wasi);
  w2c_game_0x5Finitialize(&game);
  started = true;
  snprintf((char *)client_memory() + w2c_game_game_recorder_version(&game), 64,
           "%s", CRIMSON_CLIENT_VERSION);
#ifdef __EMSCRIPTEN__
  w2c_game_game_platform(&game, 1);
  // Inside another site's page (a post's player card) the browser keeps the
  // game's storage apart, so its key would start an account of its own: there
  // the game reads the leaderboard, and ranked play waits for crimson.land.
  w2c_game_game_leaderboard_enable(&game, !EM_ASM_INT({ return window.self !== window.top; }));
#else
  w2c_game_game_platform(&game, 2);
  const char *api = getenv("CRIMSON_LEADERBOARD_URL");
  try {
    network = std::make_unique<LeaderboardNetwork>(
        api          ? api
        : unattended ? ""
                     : "https://crimson.land/api",
        game_directory, CRIMSON_CLIENT_VERSION);
  } catch (const std::exception &error) {
    client_fatal(error.what());
  }
  if (network->enabled())
    w2c_game_game_leaderboard_enable(&game, true);
#endif
  bool running = w2c_game_game_start(&game);
#ifndef __EMSCRIPTEN__
  if (running && !linked_replay.empty()) {
    if (!network->enabled())
      client_fatal("Watching an online run needs a leaderboard service.");
    network->request(LeaderboardNetwork::LINK, linked_replay);
  }
#endif
  return running;
}

#ifdef __EMSCRIPTEN__
// The page's sign-in (client/web/shell.html): the player's public key, and the
// signature of a challenge, both as hex.
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_public_key() {
  return (const char *)client_memory() +
         w2c_game_game_identity_public_key(&game);
}
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_sign_login(const char *challenge) {
  snprintf((char *)client_memory() + w2c_game_game_login_challenge(&game), 65, "%s", challenge);
  return (const char *)client_memory() + w2c_game_game_login_signature(&game);
}
// The high score screen's Update scores: the board it asks for, then the
// service's answer, or none when it could not be fetched.
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_scores_request() {
  return (const char *)client_memory() + w2c_game_game_scores_request(&game);
}
extern "C" EMSCRIPTEN_KEEPALIVE void client_scores_received(const char *answer) {
  int size = answer ? (int)strlen(answer) : -1;
  // The buffer first: making room can move the module's memory.
  if (answer) {
    uint32_t buffer = w2c_game_game_scores_buffer(&game, size);
    memcpy(client_memory() + buffer, answer, size);
  }
  w2c_game_game_scores_received(&game, size);
}
// A board run's replay to watch: the run the page fetches into
// /game/replays/online/<run>.crd, then how it went (0 written, 1 gone, 2 failed).
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_replay_download() {
  return (const char *)client_memory() + w2c_game_game_replay_download(&game);
}
extern "C" EMSCRIPTEN_KEEPALIVE void client_replay_downloaded(int result) {
  w2c_game_game_replay_downloaded(&game, result);
}
// The page leaves: the game quits as it would itself, so Module.quit commits
// what its exit writes.
extern "C" EMSCRIPTEN_KEEPALIVE void client_close() { w2c_game_game_close(&game); }
// A link to a run: plays the replay at `path` (in the game folder) once the
// game is up, its card naming the runner with the board's rank and the day the
// board took the run, which is `run` on the board. "" when it will, "wait"
// before the game has started, else why not.
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_watch(const char *path, const char *run, const char *name, int rank,
                                                         int day, int month, int year) {
  if (!started)
    return "wait";
  snprintf((char *)client_memory() + w2c_game_game_replay_path(&game), 256, "%s", path);
  snprintf((char *)client_memory() + w2c_game_game_watch_link_run(&game), 65, "%s", run);
  snprintf((char *)client_memory() + w2c_game_game_watch_name(&game), 32, "%s", name);
  if (!w2c_game_game_replay_open(&game))
    return (const char *)client_memory() + w2c_game_game_replay_reason(&game);
  return w2c_game_game_watch(&game, rank, day, month, year) ? "" : "This run cannot play now.";
}
// A link to a moment of the run playing or about to (game_watch_moment): "" when it
// takes, else why not.
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_watch_moment(int tick, int stop) {
  return w2c_game_game_watch_moment(&game, tick, stop) ? "" : "This moment is past the end of the run.";
}
// The board run playing, or "", and where playback is, for a link to its moment.
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_watch_run() {
  return started ? (const char *)client_memory() + w2c_game_game_watch_run(&game) : "";
}
extern "C" EMSCRIPTEN_KEEPALIVE int client_watch_tick() {
  return started ? (int)w2c_game_game_watch_tick(&game) : 0;
}
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_play_quest(const char *path, const char *title, const char *author) {
  if (!started)
    return "wait";
  size_t size = 0;
  void *bytes = SDL_LoadFile((game_directory + "/" + path).c_str(), &size);
  if (!bytes || size != 6184) {
    SDL_free(bytes);
    return "Could not load this quest.";
  }
  memcpy(client_memory() + w2c_game_portable_quest(&game), bytes, 6184);
  SDL_free(bytes);
  snprintf((char *)client_memory() + w2c_game_game_custom_quest_title(&game), 65, "%s", title);
  snprintf((char *)client_memory() + w2c_game_game_custom_quest_author(&game), 32, "%s", author);
  return w2c_game_game_custom_quest_play(&game) ? "" : "This quest cannot start now.";
}
#endif

#ifndef __EMSCRIPTEN__
// The player's data folder, shared with the Python game (src/crimson/paths.py):
// CRIMSON_RUNTIME_DIR, else banteg/crimsonland in the platform's user data.
std::string runtime_directory() {
  if (const char *directory = getenv("CRIMSON_RUNTIME_DIR")) {
    SDL_CreateDirectory(directory);
    return directory;
  }
  char *pref = SDL_GetPrefPath("banteg", "crimsonland");
  if (!pref)
    client_fatal(SDL_GetError());
  std::string directory = pref;
  SDL_free(pref);
  directory.pop_back(); // the trailing separator
  return directory;
}
bool present(const std::string &name) {
  std::string path;
  return client_resolve(name, path) && SDL_GetPathInfo(path.c_str(), nullptr);
}
// The files the game directory lacks: the PAQs, and the music, which music.paq
// holds or else the loose files the GOG release ships: the music the executable
// plays by name, and the tunes music/game_tunes.txt adds.
std::vector<std::string> missing_files() {
  std::vector<std::string> names = {"crimson.paq", "sfx.paq"};
  if (!present("music.paq")) {
    names.insert(names.end(), {"music/intro.ogg", "music/shortie_monk.ogg", "music/crimson_theme.ogg",
                               "music/crimsonquest.ogg", "music/game_tunes.txt"});
    std::string path;
    if (client_resolve("music/game_tunes.txt", path))
      if (char *text = (char *)SDL_LoadFile(path.c_str(), nullptr)) {
        std::istringstream lines(text);
        SDL_free(text);
        for (std::string line, command, tune; std::getline(lines, line);)
          if (std::istringstream(line) >> command >> tune && command == "snd_addGameTune")
            names.push_back("music/" + tune);
      }
  }
  std::vector<std::string> missing;
  for (const std::string &name : names)
    if (!present(name))
      missing.push_back(name);
  return missing;
}
// The executable's own pack lookup finds music.paq's entries by their whole
// names, music\intro.ogg and the rest; an earlier repack stored intro.ogg and
// music/game_tunes.txt, renamed here as the Python game does
// (src/crimson/assets_fetch.py). Each entry: a NUL-terminated name, a
// little-endian size, the bytes.
void migrate_music_paq() {
  std::string path;
  size_t size;
  u8 *data;
  if (!client_resolve("music.paq", path) || !(data = (u8 *)SDL_LoadFile(path.c_str(), &size)))
    return;
  std::string renamed(data, data + 4);
  bool changed = false, whole = true;
  for (size_t at = 4; at < size;) {
    std::string name = (const char *)data + at;
    size_t start = at + name.size() + 5;
    u32 length = 0;
    if (start <= size)
      memcpy(&length, data + start - 4, 4);
    if (start > size || length > size - start) {
      whole = false;
      break;
    }
    std::string wanted = "music\\" + name.substr(name.find_last_of("/\\") + 1);
    changed |= wanted != name;
    renamed += wanted;
    renamed.append(data + at + name.size(), data + start + length);
    at = start + length;
  }
  SDL_free(data);
  std::string partial = path + ".part";
  if (whole && changed && SDL_SaveFile(partial.c_str(), renamed.data(), renamed.size()))
    rename(partial.c_str(), path.c_str());
}
// The PAQs the folder lacks come from the project's asset host, as the Python
// game fetches them (src/crimson/assets_fetch.py), through a partial file.
constexpr const char *ASSET_BASE_URL = "https://paq.crimson.banteg.xyz/v1.9.93/";
void download(const std::string &name) {
  std::string path = game_directory + "/" + name, partial = path + ".part";
  FILE *file = fopen(partial.c_str(), "wb");
  if (!file)
    return;
  CURL *curl = curl_easy_init();
  std::string url = ASSET_BASE_URL + name;
  if (name == "crimson.paq")
    url += std::string("?sha256=") + artwork_sha256();
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  // The host refuses requests without a user agent.
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "crimsonland/" CRIMSON_CLIENT_VERSION);
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
  CURLcode result = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  bool written = fclose(file) == 0 && result == CURLE_OK;
  if (!written)
    fprintf(stderr, "crimson: %s did not download: %s\n", name.c_str(), curl_easy_strerror(result));
  if (written && name == "crimson.paq" && !artwork_is_current(partial)) {
    fprintf(stderr, "crimson: downloaded game art has an unexpected hash\n");
    written = false;
  }
  if (!written || rename(partial.c_str(), path.c_str()) != 0)
    remove(partial.c_str());
}
// Before the game starts: a folder lacking the game's files gets the PAQs it
// lacks.
void fetch_assets() {
  std::string art_path;
  bool upgrade = client_resolve("crimson.paq", art_path) && artwork_needs_update(art_path);
  if (!missing_files().empty() || upgrade) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    for (const char *name : {"crimson.paq", "music.paq", "sfx.paq"})
      if (!present(name) || (upgrade && !strcmp(name, "crimson.paq"))) {
        fprintf(stderr, "crimson: downloading %s into %s\n", name, game_directory.c_str());
        download(name);
      }
  }
  migrate_music_paq();
  std::vector<std::string> missing = missing_files();
  if (missing.empty())
    return;
  std::string message = game_directory + " lacks";
  for (const std::string &name : missing)
    message += " " + name;
  client_fatal((message + ". Check the connection, or name the folder Crimsonland is installed in.").c_str());
}
#endif

SDL_AppResult SDL_AppInit(void **, int argc, char **argv) {
  bool directory_given = false;
  for (int i = 1; i < argc; ++i) {
#ifndef __EMSCRIPTEN__
    if (!strcmp(argv[i], "--watch")) {
      if (++i == argc)
        client_fatal(
            "Usage: crimson [game directory] [--watch <run id or replay URL>]");
      const char *api = getenv("CRIMSON_LEADERBOARD_URL");
      linked_replay = LeaderboardNetwork::replay_link(
          argv[i], api ? api : "https://crimson.land/api");
      if (linked_replay.empty())
        client_fatal(
            "Expected a run id or a replay link on the leaderboard service.");
      continue;
    }
#endif
    if (directory_given)
      client_fatal(
          "Usage: crimson [game directory] [--watch <run id or replay URL>]");
    game_directory = argv[i];
    directory_given = true;
  }
#ifndef __EMSCRIPTEN__
  if (!directory_given)
    game_directory = runtime_directory();
  fetch_assets();
#endif
  // An unattended run's window never has the focus SDL wants before a pad counts.
  if (unattended)
    SDL_SetHint(SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS, "1");
  if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS | SDL_INIT_GAMEPAD))
    client_fatal(SDL_GetError());
#ifdef __EMSCRIPTEN__
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#else
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
#endif
#ifdef __EMSCRIPTEN__
  // A window title would replace the page's.
  const char *title = nullptr;
#else
  const char *title = "Crimsonland";
#endif
  window = SDL_CreateWindow(title, 1024, 768, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY);
  if (!window || !(context = SDL_GL_CreateContext(window)))
    client_fatal(SDL_GetError());
  // Unattended captures run unthrottled: a hidden window would otherwise wait on vsync.
  SDL_GL_SetSwapInterval(unattended ? 0 : 1);
  SDL_HideCursor();
  SDL_StartTextInput(window);
  renderer_init();
  audio_init();
  if (!start_game())
    return SDL_APP_FAILURE;
#ifndef __EMSCRIPTEN__
  // The page's fullscreen is the player's to ask for; a desktop window opens as crimson.cfg left it.
  if (!w2c_game_game_windowed(&game))
    SDL_SetWindowFullscreen(window, true);
#endif
  return SDL_APP_CONTINUE;
}

SDL_AppResult SDL_AppEvent(void *, SDL_Event *event) {
  if (!started && event->type != SDL_EVENT_GAMEPAD_ADDED && event->type != SDL_EVENT_GAMEPAD_REMOVED)
    return event->type == SDL_EVENT_QUIT ? SDL_APP_SUCCESS : SDL_APP_CONTINUE;
  switch (event->type) {
  case SDL_EVENT_QUIT:
    w2c_game_game_close(&game);
    break;
  // The browser's tab going to the background arrives as hidden, its window's blur as the focus.
  case SDL_EVENT_WINDOW_FOCUS_LOST:
  case SDL_EVENT_WINDOW_MINIMIZED:
  case SDL_EVENT_WINDOW_HIDDEN: {
    // Releases happen elsewhere while the window is away: nothing stays held,
    // the pad's buttons and sticks neither. The game freezes, or a co-op
    // session plays on (game/frame.cpp game_activate).
    focused = false;
    HostInput *in = input();
    memset(in->keys, 0, sizeof in->keys);
    memset(in->mouse_buttons, 0, sizeof in->mouse_buttons);
    in->key_event_count = 0;
    pad_release(in);
    memset(held, 0, sizeof held);
    memset(hold_frames, 0, sizeof hold_frames);
    w2c_game_game_activate(&game, 0);
    break;
  }
  // A tab shown again may still lack the focus, which then comes on its own.
  case SDL_EVENT_WINDOW_SHOWN:
    if (!(SDL_GetWindowFlags(window) & SDL_WINDOW_INPUT_FOCUS))
      break;
    [[fallthrough]];
  case SDL_EVENT_WINDOW_FOCUS_GAINED:
  case SDL_EVENT_WINDOW_RESTORED:
    focused = true;
    w2c_game_game_activate(&game, 1);
    break;
  case SDL_EVENT_KEY_DOWN:
  case SDL_EVENT_KEY_UP:
#ifndef __EMSCRIPTEN__
    // Alt+Enter toggles fullscreen, as in the Python port; the game never sees that Enter.
    if (event->type == SDL_EVENT_KEY_DOWN && event->key.scancode == SDL_SCANCODE_RETURN && (event->key.mod & SDL_KMOD_ALT)) {
      if (!event->key.repeat)
        SDL_SetWindowFullscreen(window, !(SDL_GetWindowFlags(window) & SDL_WINDOW_FULLSCREEN));
      break;
    }
#endif
    if (!event->key.repeat)
      key(event->key.scancode, event->type == SDL_EVENT_KEY_DOWN);
    break;
#ifndef __EMSCRIPTEN__
  // However the window got there, crimson.cfg keeps the mode for the next launch.
  case SDL_EVENT_WINDOW_ENTER_FULLSCREEN:
  case SDL_EVENT_WINDOW_LEAVE_FULLSCREEN:
    w2c_game_game_set_windowed(&game, event->type == SDL_EVENT_WINDOW_LEAVE_FULLSCREEN);
    break;
#endif
  case SDL_EVENT_TEXT_INPUT:
    for (const unsigned char *c = (const unsigned char *)event->text.text; *c; ++c)
      if (*c < 0x80)
        w2c_game_game_key_char(&game, *c);
    break;
  case SDL_EVENT_MOUSE_BUTTON_DOWN:
  case SDL_EVENT_MOUSE_BUTTON_UP: {
    // DirectInput's order: left, right, middle, then the side buttons.
    int button = event->button.button == SDL_BUTTON_LEFT ? 0 : event->button.button == SDL_BUTTON_RIGHT ? 1
                 : event->button.button == SDL_BUTTON_MIDDLE ? 2 : event->button.button - 1;
    if (button >= 8)
      break;
    // The game polls button state once a frame, so a tap shorter than a frame
    // (a touchpad's) still shows for two before letting go (SDL_AppIterate).
    bool down = event->type == SDL_EVENT_MOUSE_BUTTON_DOWN;
    held[button] = down;
    if (down)
      hold_frames[button] = 2;
    if (down || !hold_frames[button])
      input()->mouse_buttons[button] = down ? 0x80 : 0;
    break;
  }
  case SDL_EVENT_GAMEPAD_ADDED:
    if (SDL_Gamepad *added = SDL_OpenGamepad(event->gdevice.which)) {
      gamepads.push_back({added, 0});
      if (!gamepad)
        gamepad = added;
    }
    break;
  case SDL_EVENT_GAMEPAD_REMOVED:
    for (size_t i = 0; i < gamepads.size(); ++i)
      if (SDL_GetGamepadID(gamepads[i].gamepad) == event->gdevice.which) {
        SDL_CloseGamepad(gamepads[i].gamepad);
        // Another pad still connected takes over.
        if (gamepads[i].gamepad == gamepad)
          gamepad = gamepads.size() > 1 ? gamepads[i ? 0 : 1].gamepad : nullptr;
        gamepads.erase(gamepads.begin() + i);
        break;
      }
    break;
  case SDL_EVENT_MOUSE_WHEEL:
    wheel += event->wheel.y * 120;
    break;
  default:
    break;
  }
  return SDL_APP_CONTINUE;
}

SDL_AppResult SDL_AppIterate(void *) {
#ifndef __EMSCRIPTEN__
  network_update();
#endif
  // The window cursor, in back-buffer pixels, reaches DirectInput as motion.
  float x, y;
  SDL_GetMouseState(&x, &y);
  int width, height, pixel_width, pixel_height;
  SDL_GetWindowSize(window, &width, &height);
  SDL_GetWindowSizeInPixels(window, &pixel_width, &pixel_height);
  Viewport v = renderer_viewport(pixel_width, pixel_height);
  if (v.back_width) {
    float scale = (float)pixel_width / width;
    float gx = (x * scale - v.x) / v.width * v.back_width, gy = (y * scale - v.y) / v.height * v.back_height;
    run_script(frames + 1);
    if (scripted_x >= 0) {
      gx = scripted_x;
      gy = scripted_y;
    }
    HostInput *in = input();
    // The game moves its cursor by DirectInput motion: send what reaches the window cursor.
    in->mouse_dx = (int)lroundf(w2c_game_game_motion_x(&game, gx));
    in->mouse_dy = (int)lroundf(w2c_game_game_motion_y(&game, gy));
    in->mouse_dz += (int)wheel;
    wheel = 0;
    w2c_game_game_mouse_move(&game, gx, gy);
  }
  if (focused)
    pad(input());
  int before = presented;
  ++frames;
  watch_from_env();
  // Finish the elapsed audio before this frame creates new sounds. In
  // particular, dropping a stall's unheard time must not eat a fresh attack.
  audio_update(&game);
  bool running = w2c_game_game_frame(&game);
  coop_send();
  // Snapshot viewer state after the frame returns; never re-enter the module
  // from its presentation import. Used by packaged-client integration checks.
  if (captured_frame >= 0) {
    std::string path = std::string(getenv("CRIMSON_CAPTURE")) + "/frame_" +
                       std::to_string(captured_frame) + ".json";
    if (FILE *fp = fopen(path.c_str(), "w")) {
      fprintf(fp,
              "{\"watch_status\":%d,\"watch_tick\":%d,\"watch_ticks\":%d,\"practice_state\":%d,\"practice_ticks\":%d}\n",
              (int)w2c_game_game_watch_status(&game),
              (int)w2c_game_game_watch_tick(&game),
              (int)w2c_game_game_watch_ticks(&game),
              (int)w2c_game_game_practice_state(&game),
              (int)w2c_game_game_practice_ticks(&game));
      fclose(fp);
    }
    captured_frame = -1;
  }
#ifdef __EMSCRIPTEN__
  // At most once a second, and on gameplay transitions. The browser measures
  // visible wall time; the game exposes only a mode and local run generation.
  static bool analytics_ready;
  static int activity_mode;
  static unsigned activity_run;
  static Uint64 activity_at;
  if (!analytics_ready) {
    MAIN_THREAD_EM_ASM({ Module.analyticsReady(); });
    analytics_ready = true;
  }
  int mode = SDL_GetWindowFlags(window) & SDL_WINDOW_INPUT_FOCUS ? w2c_game_game_play_mode(&game) : 0;
  unsigned generation = w2c_game_game_play_run(&game);
  Uint64 now = SDL_GetTicks();
  if (mode != activity_mode || generation != activity_run || now - activity_at >= 1000) {
    MAIN_THREAD_EM_ASM({ Module.playActivity($0, $1); }, mode, generation);
    activity_mode = mode;
    activity_run = generation;
    activity_at = now;
  }
  // The page offers a link to a moment while a board run plays, prepared: it
  // hears the run's ticks, or 0 once none plays.
  static int sharing;
  int share = *((char *)client_memory() + w2c_game_game_watch_run(&game)) ? (int)w2c_game_game_watch_ticks(&game) : 0;
  if (share != sharing)
    MAIN_THREAD_EM_ASM({ Module.watching($0); }, sharing = share);
#endif
  // A pass of a run that covered no tick drew nothing: show the last frame
  // again.
  if (running && presented == before)
    show_frame(pixel_width, pixel_height);
  for (int button = 0; button < 8; ++button)
    if (hold_frames[button] && !--hold_frames[button] && !held[button])
      input()->mouse_buttons[button] = 0;
  if (!running) {
    w2c_game_game_exit(&game);
#ifdef __EMSCRIPTEN__
    // The page stays: the shell commits the saves the exit wrote.
    MAIN_THREAD_EM_ASM(Module.quit());
#endif
    return SDL_APP_SUCCESS;
  }
  return SDL_APP_CONTINUE;
}

void SDL_AppQuit(void *, SDL_AppResult) {
#ifndef __EMSCRIPTEN__
  network.reset(); // Cancels network work before the module and host go away.
#endif
}
