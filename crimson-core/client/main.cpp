// The client: an SDL3 window running the game module one frame per callback.
// Usage: crimson [game directory]. Without one it uses the folder chosen last
// time, or asks for the folder that holds the game's files.
#define SDL_MAIN_USE_CALLBACKS
#include "client.h"
#include "../game/host_input.h"
#include <SDL3/SDL.h>
#include <SDL3/SDL_main.h>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif
#include <math.h>
#include <sstream>
#include <stdio.h>
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
SDL_Gamepad *gamepad;
bool held[8];
int hold_frames[8];

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
int presented, frames;
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
    char verb[16] = {};
    float a = 0, b = 0;
    sscanf(s.action.c_str(), "%15s %f %f", verb, &a, &b);
    HostInput *in = input();
    if (!strcmp(verb, "move")) {
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

// The gamepad, as the Logitech Dual Action layout the module's joystick reports
// (game/dinput.cpp): buttons 1-4 are the west, south, east and north faces, then
// the shoulders, the triggers, back, start and the stick clicks.
void pad(HostInput *in) {
  memset(in->pad_axes, 0, sizeof in->pad_axes);
  memset(in->pad_buttons, 0, sizeof in->pad_buttons);
  in->pad_hat = ~0u;
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

extern "C" {
void w2c_host_fatal(struct w2c_host *, u32 message) { client_fatal((const char *)client_memory() + message); }
// The original's message boxes: startup failures and warnings the player must see.
void w2c_host_message(struct w2c_host *, u32 text, u32 caption) {
  const char *body = (const char *)client_memory() + text, *title = (const char *)client_memory() + caption;
  fprintf(stderr, "%s: %s\n", title, body);
  SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, title, body, window);
}
// The leaderboard (host/ranked.inc): the page signs in and uploads
// (client/web/shell.html); the native client takes no runs to it yet.
void w2c_host_leaderboard(struct w2c_host *, u32 request) {
#ifdef __EMSCRIPTEN__
  MAIN_THREAD_EM_ASM({ Module.leaderboard($0); }, request);
#else
  (void)request;
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

bool started;
bool start_game() {
  wasm_rt_init();
  client_wasi_init();
  wasm2c_game_instantiate(&game, &host, &wasi);
  w2c_game_0x5Finitialize(&game);
  started = true;
  snprintf((char *)client_memory() + w2c_game_game_recorder_version(&game), 64, "%s", CRIMSON_CLIENT_VERSION);
#ifdef __EMSCRIPTEN__
  w2c_game_game_platform(&game, 1);
  w2c_game_game_leaderboard_enable(&game);
#else
  w2c_game_game_platform(&game, 2);
#endif
  return w2c_game_game_start(&game);
}

#ifdef __EMSCRIPTEN__
// The page's sign-in (client/web/shell.html): the player's public key, and the
// signature of a challenge, both as hex.
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_public_key() {
  return (const char *)client_memory() + w2c_game_game_identity_public_key(&game);
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
// board took the run. "" when it will, "wait" before the game has started, else why not.
extern "C" EMSCRIPTEN_KEEPALIVE const char *client_watch(const char *path, const char *name, int rank, int day,
                                                         int month, int year) {
  if (!started)
    return "wait";
  snprintf((char *)client_memory() + w2c_game_game_replay_path(&game), 256, "%s", path);
  snprintf((char *)client_memory() + w2c_game_game_watch_name(&game), 32, "%s", name);
  if (!w2c_game_game_replay_open(&game))
    return (const char *)client_memory() + w2c_game_game_replay_reason(&game);
  return w2c_game_game_watch(&game, rank, day, month, year) ? "" : "This run cannot play now.";
}
#endif

#ifndef __EMSCRIPTEN__
// The game directory the player chose, remembered between launches.
std::string remembered() {
  char *pref = SDL_GetPrefPath("crimson", "crimsonland");
  std::string path = std::string(pref ? pref : "") + "game-directory";
  SDL_free(pref);
  return path;
}
// The files the game directory lacks: the PAQs, the music the executable plays
// by name, and the tunes music/game_tunes.txt adds.
std::vector<std::string> missing_files() {
  std::vector<std::string> names = {"crimson.paq", "sfx.paq", "music/intro.ogg", "music/shortie_monk.ogg",
                                    "music/crimson_theme.ogg", "music/crimsonquest.ogg", "music/game_tunes.txt"};
  std::string path;
  if (client_resolve("music/game_tunes.txt", path))
    if (char *text = (char *)SDL_LoadFile(path.c_str(), nullptr)) {
      std::istringstream lines(text);
      SDL_free(text);
      for (std::string line, command, tune; std::getline(lines, line);)
        if (std::istringstream(line) >> command >> tune && command == "snd_addGameTune")
          names.push_back("music/" + tune);
    }
  std::vector<std::string> missing;
  for (const std::string &name : names)
    if (!client_resolve(name, path) || !SDL_GetPathInfo(path.c_str(), nullptr))
      missing.push_back(name);
  return missing;
}
// music.paq, as the project distributes the music, fills in what music/ lacks.
// Each entry: a NUL-terminated name, a little-endian size, the bytes.
void unpack_music() {
  std::string path;
  size_t size;
  u8 *data;
  if (!client_resolve("music.paq", path) || !(data = (u8 *)SDL_LoadFile(path.c_str(), &size)))
    return;
  if (client_resolve("music", path))
    SDL_CreateDirectory(path.c_str());
  for (size_t at = 4; at < size;) {
    std::string name = (const char *)data + at;
    size_t start = at + name.size() + 5;
    if (start > size)
      break;
    u32 length;
    memcpy(&length, data + start - 4, 4);
    if (length > size - start)
      break;
    if (client_resolve("music/" + name.substr(name.rfind('/') + 1), path) && !SDL_GetPathInfo(path.c_str(), nullptr))
      SDL_SaveFile(path.c_str(), data + start, length);
    at = start + length;
  }
  SDL_free(data);
}
// The files the game directory still lacks once music.paq has filled in music/.
std::vector<std::string> lacking_files() {
  std::vector<std::string> missing = missing_files();
  if (missing.empty())
    return missing;
  unpack_music();
  return missing_files();
}
// The folder dialog answers on its own thread; the main loop takes the answer.
SDL_AtomicInt answered;
std::string chosen;
void choose_folder();
void on_folder(void *, const char *const *files, int) {
  chosen = files && files[0] ? files[0] : "";
  SDL_SetAtomicInt(&answered, 1);
}
void choose_folder() {
  SDL_SetAtomicInt(&answered, 0);
  SDL_ShowOpenFolderDialog(on_folder, nullptr, window, nullptr, false);
}


// Until the game directory is known.
SDL_AppResult wait_for_folder() {
  if (!SDL_GetAtomicInt(&answered)) {
    SDL_Delay(16);
    return SDL_APP_CONTINUE;
  }
  if (chosen.empty())
    return SDL_APP_SUCCESS;
  game_directory = chosen;
  if (std::vector<std::string> lacking = lacking_files(); !lacking.empty()) {
    std::string names;
    for (const std::string &name : lacking)
      names += (names.empty() ? "" : ", ") + name;
    names = "That folder lacks " + names + ". Choose the folder Crimsonland is installed in.";
    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, "Crimsonland", names.c_str(), window);
    choose_folder();
    return SDL_APP_CONTINUE;
  }
  if (SDL_IOStream *file = SDL_IOFromFile(remembered().c_str(), "w")) {
    SDL_WriteIO(file, chosen.data(), chosen.size());
    SDL_CloseIO(file);
  }
  return start_game() ? SDL_APP_CONTINUE : SDL_APP_FAILURE;
}
#endif

SDL_AppResult SDL_AppInit(void **, int argc, char **argv) {
  if (argc > 1)
    game_directory = argv[1];
#ifndef __EMSCRIPTEN__
  else if (size_t size; char *saved = (char *)SDL_LoadFile(remembered().c_str(), &size)) {
    game_directory.assign(saved, size);
    SDL_free(saved);
  }
#endif
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
#ifndef __EMSCRIPTEN__
  if (!lacking_files().empty()) {
    choose_folder();
    return SDL_APP_CONTINUE;
  }
#endif
  return start_game() ? SDL_APP_CONTINUE : SDL_APP_FAILURE;
}

SDL_AppResult SDL_AppEvent(void *, SDL_Event *event) {
  if (!started && event->type != SDL_EVENT_GAMEPAD_ADDED && event->type != SDL_EVENT_GAMEPAD_REMOVED)
    return event->type == SDL_EVENT_QUIT ? SDL_APP_SUCCESS : SDL_APP_CONTINUE;
  switch (event->type) {
  case SDL_EVENT_QUIT:
    w2c_game_game_close(&game);
    break;
  case SDL_EVENT_WINDOW_FOCUS_LOST:
  case SDL_EVENT_WINDOW_MINIMIZED: {
    // Releases happen elsewhere while the window is away: nothing stays held.
    HostInput *in = input();
    memset(in->keys, 0, sizeof in->keys);
    memset(in->mouse_buttons, 0, sizeof in->mouse_buttons);
    in->key_event_count = 0;
    memset(held, 0, sizeof held);
    memset(hold_frames, 0, sizeof hold_frames);
    w2c_game_game_activate(&game, 0);
    break;
  }
  case SDL_EVENT_WINDOW_FOCUS_GAINED:
  case SDL_EVENT_WINDOW_RESTORED:
    w2c_game_game_activate(&game, 1);
    break;
  case SDL_EVENT_KEY_DOWN:
  case SDL_EVENT_KEY_UP:
    if (!event->key.repeat)
      key(event->key.scancode, event->type == SDL_EVENT_KEY_DOWN);
    break;
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
    if (!gamepad)
      gamepad = SDL_OpenGamepad(event->gdevice.which);
    break;
  case SDL_EVENT_GAMEPAD_REMOVED:
    if (gamepad && SDL_GetGamepadID(gamepad) == event->gdevice.which) {
      SDL_CloseGamepad(gamepad);
      gamepad = nullptr;
      // Another pad still connected takes over.
      int count;
      if (SDL_JoystickID *pads = SDL_GetGamepads(&count)) {
        for (int i = 0; i < count && !gamepad; ++i)
          if (pads[i] != event->gdevice.which)
            gamepad = SDL_OpenGamepad(pads[i]);
        SDL_free(pads);
      }
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
  if (!started)
    return wait_for_folder();
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
  pad(input());
  int before = presented;
  ++frames;
  watch_from_env();
  bool running = w2c_game_game_frame(&game);
  // A pass of a run that covered no tick drew nothing: show the last frame again.
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
  audio_update(&game);
  return SDL_APP_CONTINUE;
}

void SDL_AppQuit(void *, SDL_AppResult) {}
