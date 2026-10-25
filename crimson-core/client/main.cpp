// The client: an SDL3 window running the game module one frame per callback.
// Usage: crimson [game directory] [--watch <run>] [--rtx]. Without a directory it
// plays from the player's data folder, the Python game's too, and downloads the
// game's files it lacks. --rtx (or CRIMSON_RTX=1) starts in the RTX rendering mode.
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
#ifdef __APPLE__
#include <objc/message.h>
#include <objc/runtime.h>
#endif
#include <math.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utility>

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
// The RTX mode the launch asks for (--rtx, CRIMSON_RTX=1), the one the renderer shows, and whether the window shows
// extended range.
bool rtx_requested = getenv("CRIMSON_RTX") && strcmp(getenv("CRIMSON_RTX"), "0");
bool rtx_shown;
bool edr;
// The replay the host asks to play, named for the window title (show_title): its file and the tick it stops at
// (watch_from_env), a link's runner.
std::string watch_label;

// On macOS the RTX window opts into extended dynamic range: its half-float back
// buffer (SDL_GL_FLOATBUFFERS) then carries highlights past white to the display,
// whose headroom SDL reports. SDL leaves the Cocoa view's opt-in to its user.
void display_edr(bool enabled) {
#ifdef __APPLE__
  void *cocoa = SDL_GetPointerProperty(SDL_GetWindowProperties(window), SDL_PROP_WINDOW_COCOA_WINDOW_POINTER, nullptr);
  void *view = ((void *(*)(void *, SEL))objc_msgSend)(cocoa, sel_registerName("contentView"));
  ((void (*)(void *, SEL, BOOL))objc_msgSend)(view, sel_registerName("setWantsExtendedDynamicRangeOpenGLSurface:"),
                                              enabled);
  edr = enabled;
#endif
  if (!edr)
    renderer_set_headroom(1);
}

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
// CRIMSON_CAPTURE_TICK=<tick> instead pauses a watched replay (CRIMSON_WATCH)
// on that tick and saves its frame as tick_<tick>.ppm, then quits.
std::vector<int> capture_frames;
int presented, frames, captured_frame = -1;
bool capture_done;
const bool unattended = getenv("CRIMSON_CAPTURE");
// A run a script drives (a capture, a watched moment, scripted input) ends by
// itself: its messages go to stderr, never to a dialog that waits for a click.
// It takes its input from its script alone, and plays on in the background.
const bool scripted = unattended || getenv("CRIMSON_WATCH") || getenv("CRIMSON_INPUT");
void client_message(SDL_MessageBoxFlags flags, const char *title, const char *text) {
  fprintf(stderr, "%s: %s\n", title, text);
  if (!scripted)
    SDL_ShowSimpleMessageBox(flags, title, text, window);
}
void write_capture(const std::string &name) {
  int width, height;
  std::vector<unsigned char> pixels = renderer_capture(width, height);
  std::string path = std::string(getenv("CRIMSON_CAPTURE")) + "/" + name + ".ppm";
  if (FILE *fp = fopen(path.c_str(), "wb")) {
    fprintf(fp, "P6\n%d %d\n255\n", width, height);
    for (int y = 0; y < height; ++y)
      for (int x = 0; x < width; ++x)
        fwrite(&pixels[((size_t)y * width + x) * 4], 1, 3, fp);
    fclose(fp);
  }
}
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
    write_capture("frame_" + std::to_string(frames));
    captured_frame = frames;
    capture_frames.erase(capture_frames.begin() + i);
    if (capture_frames.empty())
      w2c_game_game_close(&game);
    break;
  }
}

// CRIMSON_INPUT scripts input for unattended runs: "frame:action;..." (host
// frames) where an
// action is "move x y" (logical game pixels), "press button" or "release button"
// (0 left, 1 right), or "key code" / "unkey code" (DirectInput scancodes, hex).
// Virtual gamepads stand in for real ones: "padattach n", "paddetach n",
// "padbutton name 0|1 n" and "padaxis name value n" for pad n, 0 when left out
// (SDL's names: "a", "dpup", "start", "leftx", "righttrigger"; axes -32768 to 32767).
// "resize width height" changes the window in SDL coordinates.
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
float scripted_x, scripted_y;
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
    } else if (!strcmp(verb, "resize") && a > 0 && b > 0) {
      SDL_SetWindowSize(window, (int)a, (int)b);
      SDL_SyncWindow(window);
    } else if (!strcmp(verb, "move")) {
      scripted_x = a;
      scripted_y = b;
      w2c_game_game_hide_cursor(&game, 0);
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
  client_message(SDL_MESSAGEBOX_ERROR, "Crimsonland", message);
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
  client_message(SDL_MESSAGEBOX_WARNING, title, body);
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
// The clock the game times its own work by, to the nanosecond SDL reads.
f64 w2c_host_clock_ms(struct w2c_host *) { return SDL_GetTicksNS() / 1e6; }
static void show_frame(int width, int height) {
  renderer_present(width, height);
  // WebGPU shows its frame when the browser composites the canvas.
  if (renderer_uses_gl())
    SDL_GL_SwapWindow(window);
  renderer_resume();
}
void w2c_host_present(struct w2c_host *) {
  int width, height;
  SDL_GetWindowSizeInPixels(window, &width, &height);
  capture_frame();
  show_frame(width, height);
}
// RTX (game/rtx.cpp): the mode the renderer shows of the one asked for. The page's
// switch follows it, whoever changed it (shell.html).
u32 w2c_host_render_mode(struct w2c_host *, u32 requested) {
  bool rtx = rtx_shown = renderer_set_rtx(requested == 1);
  display_edr(rtx);
#ifdef __EMSCRIPTEN__
  MAIN_THREAD_EM_ASM({ Module.renderMode?.($0); }, rtx);
#endif
  return rtx;
}
}

// CRIMSON_WATCH=<replay> plays a replay, from the game folder, as a link to a
// run does, for unattended captures: CRIMSON_WATCH_SEEK=<tick> goes to a tick
// once it is prepared, and CRIMSON_WATCH_STOP=<tick> pauses playback there and
// ends the run once that tick has drawn (unless it captures frames past it);
// CRIMSON_WATCH_CARD=<name>,<rank>,<day>,<month>,<year> gives its card's runner.
// CRIMSON_WATCH_MOMENTS=<tick>,<tick>,... measures several moments of one
// prepared replay instead: playback goes CRIMSON_WATCH_WINDOW ticks (240) before
// each, plays to it and pauses there, then goes on to the next; the run ends
// once the last has drawn.
std::vector<int> watch_moments;
int watch_window = 240;
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
  if (const char *window = getenv("CRIMSON_WATCH_WINDOW"))
    watch_window = atoi(window);
  for (const char *p = getenv("CRIMSON_WATCH_MOMENTS"); p && *p; p = strchr(p, ',') ? strchr(p, ',') + 1 : "")
    watch_moments.push_back(atoi(p));
  if (!watch_moments.empty())
    w2c_game_game_watch_seek(&game, std::max(1, watch_moments[0] - watch_window));
  else if (const char *seek = getenv("CRIMSON_WATCH_SEEK"))
    w2c_game_game_watch_seek(&game, atoi(seek));
  // A hash-named replay goes by its first 8 digits.
  std::string file = path;
  file = file.substr(file.find_last_of("/\\") + 1);
  file = file.substr(0, file.rfind('.'));
  if (file.size() > 8 && file.find_first_not_of("0123456789abcdef") == std::string::npos)
    file.resize(8);
  watch_label = file;
  const char *stop = getenv("CRIMSON_WATCH_STOP");
  if (!stop)
    stop = getenv("CRIMSON_CAPTURE_TICK");
  if (!watch_moments.empty()) {
    w2c_game_game_watch_stop_at(&game, watch_moments[0]);
    watch_label += " at " + std::to_string(watch_moments.size()) + " moments";
  } else if (stop) {
    w2c_game_game_watch_stop_at(&game, atoi(stop));
    watch_label += " to tick " + std::to_string(atoi(stop));
  }
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
      client_message(SDL_MESSAGEBOX_WARNING, "Leaderboard", "Could not load your identity key.");
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
      w2c_game_game_watch_awaited(&game, 0);
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
        else if (w2c_game_game_watch(&game, event.rank, day, month, year)) {
          reason = nullptr;
          watch_label = event.runner;
        } else
          reason = "This run cannot play now.";
      }
      if (reason)
        client_message(SDL_MESSAGEBOX_WARNING, "Replay", reason);
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
        client_message(SDL_MESSAGEBOX_WARNING, "Leaderboard", "Could not sign in. Try again later.");
      }
    } else if (event.kind == N::LOGIN && event.ok) {
      profile_pending = false;
      if (!SDL_OpenURL(event.body.c_str()))
        client_message(SDL_MESSAGEBOX_WARNING, "Leaderboard", "Could not open your browser.");
    } else if (event.kind == N::CHALLENGE || event.kind == N::LOGIN) {
      profile_pending = false;
      client_message(SDL_MESSAGEBOX_WARNING, "Leaderboard", "Can't sign in to the leaderboard. Try again later.");
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
// The window says what it shows, so windows side by side tell apart: the rendering mode and the replay playing, by
// the name the host gave it as it starts (watch_label) or its run on the leaderboard.
void show_title() {
  static std::string playing;
  static bool watched;
  static char shown[128] = "Crimsonland";
  bool watching = (int)w2c_game_game_watch_status(&game) >= 0;
  if (watching && !watched)
    playing = std::exchange(watch_label, {});
  watched = watching;
  char title[sizeof shown];
  int length = snprintf(title, sizeof title, "Crimsonland%s", rtx_shown ? " RTX" : "");
  if (watching && !playing.empty())
    snprintf(title + length, sizeof title - length, " · %s", playing.c_str());
  else if (watching) {
    const char *run = (const char *)client_memory() + w2c_game_game_watch_run(&game);
    snprintf(title + length, sizeof title - length, " · %.8s", *run ? run : "replay");
  }
  if (strcmp(title, shown))
    SDL_SetWindowTitle(window, strcpy(shown, title));
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
// The page holds `seat` in a co-op room, or none (-1) once it left the room or co-op ended there
// (host/coop_live.inc game_coop_in_room): while it does, the menus are co-op's, a session or not. -1 before the
// game has started.
CLIENT_EXPORT int client_coop_room(int seat) { return started ? (int)w2c_game_game_coop_in_room(&game, seat) : -1; }
// The transport closed, or the partner's page went (host/coop_wire.inc CoopReason).
CLIENT_EXPORT int client_coop_disconnect(int reason) { return w2c_game_game_coop_disconnect(&game, reason); }
// A message of `size` bytes on `channel`: the page writes it where
// client_coop_rx says, in the game's buffer (its address read after making
// room, which can move the module's memory), then hands it over.
CLIENT_EXPORT u8 *client_coop_rx(int size) {
  u32 buffer = w2c_game_game_coop_rx(&game, size);
  return client_memory() + buffer;
}
CLIENT_EXPORT void client_coop_receive(int channel, int size) {
  w2c_game_game_coop_receive(&game, channel, size, coop_now());
}
// game_coop_status's flags and reasons, and why the session or its run stopped as the game tells its player
// (game_coop_why, null for none), for the page; for checks (checks/coop_browser.mjs) also the screen the game
// shows (game_state_id_t, -1 before it started), the run's confirmed tick (-1 none), what a confirmed tick ran
// with (the seat's PortableInput, null for a tick out of the ring) and left (its state's hash), and a change to
// the state that the next hash shows (game_coop_corrupt).
CLIENT_EXPORT u32 client_coop_status() { return started ? w2c_game_game_coop_status(&game) : 0; }
CLIENT_EXPORT const char *client_coop_why() {
  u32 why = started ? w2c_game_game_coop_why(&game) : 0;
  return why ? (const char *)client_memory() + why : nullptr;
}
CLIENT_EXPORT int client_coop_confirmed() { return started ? (int)w2c_game_game_coop_confirmed(&game) : -1; }
CLIENT_EXPORT int client_game_state() { return started ? (int)w2c_game_game_state(&game) : -1; }
CLIENT_EXPORT const u8 *client_coop_used(int t, int seat) {
  u32 used = w2c_game_game_coop_used(&game, t, seat);
  return used ? client_memory() + used : nullptr;
}
CLIENT_EXPORT u32 client_coop_hash_at(int t) { return w2c_game_game_coop_hash_at(&game, t); }
CLIENT_EXPORT int client_coop_corrupt(int kind) { return w2c_game_game_coop_corrupt(&game, kind); }
// The session's telemetry as it stands (game_coop_telemetry); null before the game started.
CLIENT_EXPORT const u8 *client_coop_telemetry() {
  return started ? client_memory() + w2c_game_game_coop_telemetry(&game) : nullptr;
}
// The next summary of an ended session the page reports (game_coop_report); null when none is due.
CLIENT_EXPORT const u8 *client_coop_report() {
  u32 at = started ? w2c_game_game_coop_report(&game) : 0;
  return at ? client_memory() + at : nullptr;
}
// The room's word on the pair (host/coop_ranked.inc), which the page passes on
// as the room says it, "wait" or -1 before the game has started. A room socket's
// challenge to this page's seat: the player's proof for it, "<public key>
// <signature>" in hex, empty when the game proves no key.
CLIENT_EXPORT const char *client_coop_prove(const char *room, const char *challenge) {
  if (!started)
    return "wait";
  char *text = (char *)client_memory() + w2c_game_game_coop_room_text(&game);
  if (snprintf(text, COOP_ROOM_TEXT, "%s%s", room, challenge) >= COOP_ROOM_TEXT)
    return "";
  return (const char *)client_memory() + w2c_game_game_coop_prove(&game, (u32)strlen(room));
}
// The key the room recorded for a seat (0 its host, 1 its guest), as hex: 1 when the game took it.
CLIENT_EXPORT int client_coop_key(int seat, const char *key) {
  if (!started)
    return -1;
  char *text = (char *)client_memory() + w2c_game_game_coop_room_text(&game);
  if (snprintf(text, COOP_ROOM_TEXT, "%s", key) >= COOP_ROOM_TEXT)
    return 0;
  return (int)w2c_game_game_coop_room_key(&game, seat);
}
// A seed the room issued to the pair.
CLIENT_EXPORT int client_coop_seed(u32 seed) {
  if (!started)
    return -1;
  w2c_game_game_coop_room_seed(&game, seed);
  return 1;
}
// What the session has to send, each message copied out of the module for the
// page (no game call moves its memory in between), and the Host's request for a
// run's seed, which the page asks the room for.
void coop_send() {
#ifdef __EMSCRIPTEN__
  for (int channel = 0; channel < 2; ++channel)
    for (int size; (size = (int)w2c_game_game_coop_tx(&game, channel, coop_now())) > 0;) {
      const u8 *message = client_memory() + w2c_game_game_coop_tx_buffer(&game);
      MAIN_THREAD_EM_ASM({ Module.coopSend($0, HEAPU8.slice($1, $1 + $2)); }, channel, message, size);
    }
  if (w2c_game_game_coop_room_ask(&game))
    MAIN_THREAD_EM_ASM({ Module.coopSeed(); });
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
  // A scripted run's cursor shows once its script moves it.
  w2c_game_game_hide_cursor(&game, scripted);
  // A link to a run, fetched meanwhile, skips the intro (game_watch_awaited).
#ifdef __EMSCRIPTEN__
  if (running && EM_ASM_INT({ return Module.watchAwaited?.() ? 1 : 0; }))
    w2c_game_game_watch_awaited(&game, 1);
#else
  if (running && !linked_replay.empty()) {
    if (!network->enabled())
      client_fatal("Watching an online run needs a leaderboard service.");
    network->request(LeaderboardNetwork::LINK, linked_replay);
    w2c_game_game_watch_awaited(&game, 1);
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
// The page's link to a run came to nothing (game_watch_awaited).
extern "C" EMSCRIPTEN_KEEPALIVE void client_watch_failed() {
  if (started)
    w2c_game_game_watch_awaited(&game, 0);
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
// The page's RTX switch: the rendering mode, as the console's rendermode sets it.
extern "C" EMSCRIPTEN_KEEPALIVE void client_render_mode(int mode) {
  if (started)
    w2c_game_game_render_mode(&game, mode);
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
  const char *usage = "Usage: crimson [game directory] [--watch <run id or replay URL>] [--rtx]";
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--rtx")) {
      rtx_requested = true;
      continue;
    }
#ifndef __EMSCRIPTEN__
    if (!strcmp(argv[i], "--watch")) {
      if (++i == argc)
        client_fatal(usage);
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
      client_fatal(usage);
    game_directory = argv[i];
    directory_given = true;
  }
#ifndef __EMSCRIPTEN__
  if (!directory_given)
    game_directory = runtime_directory();
  fetch_assets();
#endif
  // A scripted run opens behind what the player is doing, and its window never
  // has the focus SDL wants before a pad counts.
  if (scripted) {
    SDL_SetHint(SDL_HINT_WINDOW_ACTIVATE_WHEN_SHOWN, "0");
    SDL_SetHint(SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS, "1");
  }
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
#ifdef __APPLE__
  // Half-float from the start, so switching to RTX needs no new context; classic
  // presents the same 8-bit image into it (display_edr).
  SDL_GL_SetAttribute(SDL_GL_FLOATBUFFERS, 1);
  for (SDL_GLAttr size : {SDL_GL_RED_SIZE, SDL_GL_GREEN_SIZE, SDL_GL_BLUE_SIZE, SDL_GL_ALPHA_SIZE})
    SDL_GL_SetAttribute(size, 16);
#endif
#ifdef __EMSCRIPTEN__
  // A window title would replace the page's.
  const char *title = nullptr;
#else
  const char *title = "Crimsonland";
#endif
  // A browser with WebGPU draws into the canvas without a GL context (renderer_webgpu.cpp).
  bool gl = renderer_uses_gl();
  window = SDL_CreateWindow(title, 1024, 768,
                            (gl ? SDL_WINDOW_OPENGL : 0) | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY);
  if (!window || (gl && !(context = SDL_GL_CreateContext(window))))
    client_fatal(SDL_GetError());
  // Unattended captures run unthrottled: a hidden window would otherwise wait on vsync.
  if (gl)
    SDL_GL_SetSwapInterval(unattended ? 0 : 1);
  SDL_HideCursor();
  SDL_StartTextInput(window);
  renderer_init();
  int pixel_width, pixel_height;
  SDL_GetWindowSizeInPixels(window, &pixel_width, &pixel_height);
  renderer_resize(pixel_width, pixel_height);
  audio_init();
  if (!start_game())
    return SDL_APP_FAILURE;
#ifdef __EMSCRIPTEN__
  // The page's choice (?rtx=1, the player's last one; shell.html).
  rtx_requested = EM_ASM_INT({ return Module.rtxWanted?.() ? 1 : 0; });
#endif
  if (rtx_requested)
    w2c_game_game_render_mode(&game, 1);
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
    if (scripted)
      break;
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
    if (scripted)
      break;
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
    if (scripted)
      break;
    for (const unsigned char *c = (const unsigned char *)event->text.text; *c; ++c)
      if (*c < 0x80)
        w2c_game_game_key_char(&game, *c);
    break;
  case SDL_EVENT_MOUSE_BUTTON_DOWN:
  case SDL_EVENT_MOUSE_BUTTON_UP: {
    if (scripted)
      break;
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
    if (scripted)
      break;
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
  // Raster density changes only the host targets; the game and DirectInput
  // continue to see the configured logical dimensions.
  run_script(frames + 1);
  float x, y;
  SDL_GetMouseState(&x, &y);
  int width, height, pixel_width, pixel_height;
  SDL_GetWindowSize(window, &width, &height);
  SDL_GetWindowSizeInPixels(window, &pixel_width, &pixel_height);
  renderer_resize(pixel_width, pixel_height);
  Viewport v = renderer_viewport(pixel_width, pixel_height);
  if (v.width && width > 0 && height > 0) {
    float gx = v.logical_x(x * pixel_width / width), gy = v.logical_y(y * pixel_height / height);
    if (scripted) {
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
  // The headroom moves with brightness and the display the window is on. Unattended captures tonemap for SDR, so
  // they read the same on any display.
  if (edr && !unattended)
    renderer_set_headroom(SDL_GetFloatProperty(SDL_GetWindowProperties(window), SDL_PROP_WINDOW_HDR_HEADROOM_FLOAT, 1));
  bool running = w2c_game_game_frame(&game);
  coop_send();
#ifndef __EMSCRIPTEN__
  show_title();
#endif
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
  // CRIMSON_GPU_TIMERS: the GPU time per pass, a frame late, with the replay tick it drew,
  // and that frame's draws by pass, texture and target: quads and covered pixels.
  static const bool gpu_timers = getenv("CRIMSON_GPU_TIMERS");
  static int timed_tick;
  if (gpu_timers) {
    std::string timings = renderer_gpu_timings();
    if (!timings.empty()) {
      fprintf(stderr, "gpu tick=%d %s\n", timed_tick, timings.c_str());
      fprintf(stderr, "draws tick=%d %s\n", timed_tick, renderer_draw_stats().c_str());
    }
    timed_tick = (int)w2c_game_game_watch_tick(&game);
  }
  // A moment's frame, once the replay has held on it for a frame. A run that
  // only stops there ends there too, unless it captures frames past it.
  static const int capture_tick = unattended && getenv("CRIMSON_CAPTURE_TICK") ? atoi(getenv("CRIMSON_CAPTURE_TICK")) : 0;
  static int end_tick = capture_tick ? capture_tick
                        : !watch_moments.empty()                                           ? watch_moments[0]
                        : getenv("CRIMSON_WATCH_STOP") && !getenv("CRIMSON_CAPTURE_FRAMES") ? atoi(getenv("CRIMSON_WATCH_STOP"))
                                                                                            : 0;
  static int held_frames;
  static size_t moment;
  if (end_tick && (int)w2c_game_game_watch_paused_tick(&game) == end_tick && ++held_frames == 2) {
    if (capture_tick)
      write_capture("tick_" + std::to_string(capture_tick));
    if (++moment < watch_moments.size()) {
      end_tick = watch_moments[moment];
      held_frames = 0;
      w2c_game_game_watch_moment(&game, std::max(1, end_tick - watch_window), end_tick);
    } else
      w2c_game_game_close(&game);
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
