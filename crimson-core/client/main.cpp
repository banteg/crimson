// The client: an SDL3 window running the game module one frame per callback.
// Usage: crimson [game directory], defaulting to the current directory.
#define SDL_MAIN_USE_CALLBACKS
#include "client.h"
#include <SDL3/SDL.h>
#include <SDL3/SDL_main.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// The module's DirectInput state (game/dinput.cpp).
struct HostInput {
  unsigned char keys[256];
  int mouse_dx, mouse_dy, mouse_dz;
  unsigned char mouse_buttons[8];
  int key_event_count;
  struct {
    unsigned char key, down;
  } key_events[32];
};

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
// CRIMSON_CAPTURE_FRAMES (comma-separated) as frame_<n>.ppm, then quits.
std::vector<int> capture_frames;
int presented;
bool capture_done;
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
    if (capture_frames[i] != presented)
      continue;
    int width, height;
    std::vector<unsigned char> pixels = renderer_capture(width, height);
    std::string path = std::string(directory) + "/frame_" + std::to_string(presented) + ".ppm";
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

// CRIMSON_INPUT scripts input for unattended runs: "frame:action;..." where an
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
void w2c_host_message(struct w2c_host *, u32 text, u32 caption) {
  fprintf(stderr, "%s: %s\n", (const char *)client_memory() + caption, (const char *)client_memory() + text);
}
u32 w2c_host_time_ms(struct w2c_host *) { return (u32)SDL_GetTicks(); }
void w2c_host_present(struct w2c_host *) {
  int width, height;
  SDL_GetWindowSizeInPixels(window, &width, &height);
  capture_frame();
  renderer_present(width, height);
  SDL_GL_SwapWindow(window);
}
}

SDL_AppResult SDL_AppInit(void **, int argc, char **argv) {
  if (argc > 1)
    game_directory = argv[1];
  if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS))
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
  window = SDL_CreateWindow("Crimsonland", 1024, 768, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY);
  if (!window || !(context = SDL_GL_CreateContext(window)))
    client_fatal(SDL_GetError());
  SDL_GL_SetSwapInterval(1);
  SDL_HideCursor();
  SDL_StartTextInput(window);
  renderer_init();

  wasm_rt_init();
  client_wasi_init();
  wasm2c_game_instantiate(&game, &host, &wasi);
  w2c_game_0x5Finitialize(&game);
  if (!w2c_game_game_start(&game))
    return SDL_APP_FAILURE;
  return SDL_APP_CONTINUE;
}

SDL_AppResult SDL_AppEvent(void *, SDL_Event *event) {
  switch (event->type) {
  case SDL_EVENT_QUIT:
    w2c_game_game_close(&game);
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
    int button = event->button.button == SDL_BUTTON_LEFT ? 0 : event->button.button == SDL_BUTTON_RIGHT ? 1
                 : event->button.button == SDL_BUTTON_MIDDLE ? 2 : event->button.button + 1;
    if (button < 8)
      input()->mouse_buttons[button] = event->type == SDL_EVENT_MOUSE_BUTTON_DOWN ? 0x80 : 0;
    break;
  }
  case SDL_EVENT_MOUSE_WHEEL:
    wheel += event->wheel.y * 120;
    break;
  default:
    break;
  }
  return SDL_APP_CONTINUE;
}

SDL_AppResult SDL_AppIterate(void *) {
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
    run_script(presented + 1);
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
  if (!w2c_game_game_frame(&game)) {
    w2c_game_game_exit(&game);
    return SDL_APP_SUCCESS;
  }
  return SDL_APP_CONTINUE;
}

void SDL_AppQuit(void *, SDL_AppResult) {}
