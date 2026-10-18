// A modern controller over the original's joystick, as the Python port plays
// one (src/crimson/input_codes.py, gamepad_profile.py, ui/focus.py). The host
// lays the pad out as the Logitech Dual Action (host_input.h), so the original's
// Joys/JoyAxis codes keep reading the fields they always read. On top of that:
//
// - the standard controller codes (PadCode, 0x200-0x21f) name what the player
//   holds, through the same joystick state (Grim's key and axis queries,
//   changes/pad-codes.patch); a crimson.cfg the Python port saved keeps working;
// - a stock player who picks up a pad gets the Python port's twin-stick profile;
// - outside gameplay, and over a co-op run's banner (host/coop_live.inc), the
//   pad steps the original's keyboard focus about the screen and presses the
//   keys its screens read, and its right stick steers the cursor, which A
//   clicks with; B is Escape, which every screen takes as its way out
//   (changes/escape-back.patch); Start pauses and resumes;
// - the controls screen captures pad buttons and sticks as standard codes.
#include <math.h>
#include "crimsonland_gameplay.h"
#include "crimsonland_ui.h"
#include "grim2d_cpp.h"
#include "grim_joystick_state.h"
#include "host_input.h"

extern unsigned char grim_keyboard_state[256];
extern IGrim2D_cpp *grim_interface_ptr;
extern float grim_frame_dt;
extern "C" {
HostInput *game_input();
void config_init_defaults(void);
bool config_sync_from_grim(void);
void ui_menu_pause_click_resume(void);
void game_key_char(int character);
bool game_coop_banner(void);
bool game_watching(void);
unsigned char ui_focus_update(int id);
void ui_focus_draw(float *xy);
extern int ui_screen_phase;
extern unsigned char ui_focus_input_locked;
extern int ui_focus_frame_marker_ms;
extern int controls_rebind_slot_index, controls_rebind_player_index;
extern unsigned char controls_rebind_capture_armed;
extern int config_key_pick_perk, config_key_reload;
}

namespace {

// The standard codes (PadCode in src/crimson/input_codes.py), each read from
// the host's layout: an axis, a button, or a d-pad direction of the hat.
enum PadCode {
  LEFT_STICK_X = 0x200,
  LEFT_STICK_Y,
  RIGHT_STICK_X,
  RIGHT_STICK_Y,
  FACE_DOWN = 0x210,
  FACE_RIGHT,
  FACE_LEFT,
  FACE_UP,
  L1,
  R1,
  L2,
  R2,
  L3,
  R3,
  SELECT,
  START,
  DPAD_UP,
  DPAD_DOWN,
  DPAD_LEFT,
  DPAD_RIGHT,
  PAD_CODE_END
};
struct PadSource {
  enum { AXIS, BUTTON, HAT } kind;
  int index; // the axis's field, the button, or the hat's direction in hundredths of a degree
  const char *name;
};
const PadSource *pad_source(int code) {
  static const PadSource axes[] = {{PadSource::AXIS, 0, "Left Stick X"},
                                   {PadSource::AXIS, 1, "Left Stick Y"},
                                   {PadSource::AXIS, 2, "Right Stick X"},
                                   {PadSource::AXIS, 5, "Right Stick Y"}};
  static const PadSource buttons[] = {
      {PadSource::BUTTON, 1, "Cross / A"},    {PadSource::BUTTON, 2, "Circle / B"},
      {PadSource::BUTTON, 0, "Square / X"},   {PadSource::BUTTON, 3, "Triangle / Y"},
      {PadSource::BUTTON, 4, "L1 / LB"},      {PadSource::BUTTON, 5, "R1 / RB"},
      {PadSource::BUTTON, 6, "L2 / LT"},      {PadSource::BUTTON, 7, "R2 / RT"},
      {PadSource::BUTTON, 10, "L3 / LS"},     {PadSource::BUTTON, 11, "R3 / RS"},
      {PadSource::BUTTON, 8, "Select"},       {PadSource::BUTTON, 9, "Start"},
      {PadSource::HAT, 0, "D-Pad Up"},        {PadSource::HAT, 18000, "D-Pad Down"},
      {PadSource::HAT, 27000, "D-Pad Left"},  {PadSource::HAT, 9000, "D-Pad Right"}};
  if (code >= LEFT_STICK_X && code <= RIGHT_STICK_Y)
    return &axes[code - LEFT_STICK_X];
  if (code >= FACE_DOWN && code < PAD_CODE_END)
    return &buttons[code - FACE_DOWN];
  return nullptr;
}

// Raw like the original's `lX * 0.001f`: dead zones belong to whoever reads
// both axes (the simulation's 0.2 move radius, the pad aim's).
float axis(int index) {
  const long *fields = &grim_joystick_state.lX;
  return (float)fields[index] * 0.001f;
}
// A d-pad direction, diagonals counting for both of theirs.
bool hat(int direction) {
  unsigned long pov = grim_joystick_state.rgdwPOV[0];
  if (pov == ~0ul)
    return false;
  long apart = ((long)pov - direction + 36000) % 36000;
  return apart <= 4500 || apart >= 31500;
}

const float AXIS_DOWN = 0.5f; // an axis read as a button (_AXIS_DOWN_THRESHOLD)

bool connected() { return game_input()->pad_connected; }

} // namespace

extern "C" float grim_pad_code_axis(int code) {
  const PadSource *source = pad_source(code);
  if (!source || source->kind != PadSource::AXIS)
    return 0.0f;
  float value = axis(source->index);
  return value < -1.0f ? -1.0f : value > 1.0f ? 1.0f : value;
}
extern "C" unsigned char grim_pad_code_active(int code) {
  const PadSource *source = pad_source(code);
  if (!source)
    return 0;
  switch (source->kind) {
  case PadSource::AXIS:
    return fabsf(grim_pad_code_axis(code)) >= AXIS_DOWN;
  case PadSource::BUTTON:
    return grim_joystick_state.rgbButtons[source->index] >> 7;
  case PadSource::HAT:
    return hat(source->index);
  }
  return 0;
}
extern "C" const char *grim_pad_code_name(int code) {
  const PadSource *source = pad_source(code);
  return source ? source->name : nullptr;
}

namespace {

// --- The modern profile (src/crimson/gamepad_profile.py) -------------------

const int PROFILE_MOVE_Y = LEFT_STICK_Y, PROFILE_MOVE_X = LEFT_STICK_X;
const int PROFILE_AIM_Y = RIGHT_STICK_Y, PROFILE_AIM_X = RIGHT_STICK_X;
const int PROFILE_FIRE = R2;
// Shoulder reload next to trigger fire, as in 10tons' 2014 remake.
const int PROFILE_RELOAD = L1;
const int PROFILE_PICK_PERK = FACE_UP;
const int MOVEMENT_PAD = 3, AIM_PAD = 4; // the Dual Action Pad schemes

enum Upgrade { METHODS = 1, MOVE_AXES = 2, AIM_AXES = 4, FIRE = 8, RELOAD = 16, LEVEL_UP = 32 };

// What a fresh configuration binds (config_init_defaults), which the profile
// replaces where the player kept it.
const crimson_cfg_t &stock() {
  static crimson_cfg_t defaults;
  static bool made;
  if (!made) {
    crimson_cfg_t player = config_blob;
    config_init_defaults();
    defaults = config_blob;
    config_blob = player;
    made = true;
  }
  return defaults;
}

// The player's bindings and methods as a fresh configuration has them; the
// direction arrow is a display choice, not a binding.
bool bindings_stock(int player) {
  const crimson_cfg_t &s = stock();
  const player_input_config_t &a = config_blob.input_config[player], &b = s.input_config[player];
  return config_blob.movement_schemes[player] == s.movement_schemes[player] &&
         config_blob.aim_schemes[player] == s.aim_schemes[player] && a.move_key_forward == b.move_key_forward &&
         a.move_key_backward == b.move_key_backward && a.turn_key_left == b.turn_key_left &&
         a.turn_key_right == b.turn_key_right && a.fire_key == b.fire_key && a.aim_key_left == b.aim_key_left &&
         a.aim_key_right == b.aim_key_right && a.axis_aim_y == b.axis_aim_y && a.axis_aim_x == b.axis_aim_x &&
         a.axis_move_y == b.axis_move_y && a.axis_move_x == b.axis_move_x;
}

// The upgrades the next pad use would apply (pending_pad_upgrades): a fully
// stock player switches to the pad methods; stock axes become the sticks; with
// pad aim a stock Fire becomes R2; on any pad method the stock Reload and Level
// Up become pad buttons. What the player changed stays.
int pending(int player) {
  const crimson_cfg_t &s = stock();
  const player_input_config_t &a = config_blob.input_config[player], &b = s.input_config[player];
  int upgrades = bindings_stock(player) ? METHODS : 0;
  bool aim_pad = upgrades & METHODS || config_blob.aim_schemes[player] == AIM_PAD;
  bool any_pad = aim_pad || config_blob.movement_schemes[player] == MOVEMENT_PAD;
  if (a.axis_move_y == b.axis_move_y && a.axis_move_x == b.axis_move_x)
    upgrades |= MOVE_AXES;
  if (a.axis_aim_y == b.axis_aim_y && a.axis_aim_x == b.axis_aim_x)
    upgrades |= AIM_AXES;
  if (aim_pad && a.fire_key == b.fire_key)
    upgrades |= FIRE;
  // Reload and Level Up are global, owned by player one.
  if (player == 0 && any_pad) {
    if (config_blob.key_reload == s.key_reload)
      upgrades |= RELOAD;
    if (config_blob.key_pick_perk == s.key_pick_perk)
      upgrades |= LEVEL_UP;
  }
  return upgrades;
}

void apply(int player, int upgrades) {
  player_input_config_t &keys = config_blob.input_config[player];
  if (upgrades & METHODS) {
    config_blob.movement_schemes[player] = MOVEMENT_PAD;
    config_blob.aim_schemes[player] = AIM_PAD;
  }
  if (upgrades & MOVE_AXES) {
    keys.axis_move_y = PROFILE_MOVE_Y;
    keys.axis_move_x = PROFILE_MOVE_X;
  }
  if (upgrades & AIM_AXES) {
    keys.axis_aim_y = PROFILE_AIM_Y;
    keys.axis_aim_x = PROFILE_AIM_X;
  }
  if (upgrades & FIRE)
    keys.fire_key = PROFILE_FIRE;
  if (upgrades & RELOAD)
    config_blob.key_reload = PROFILE_RELOAD;
  if (upgrades & LEVEL_UP)
    config_blob.key_pick_perk = PROFILE_PICK_PERK;
  // The player's input reads the bindings from this copy, which the original
  // refreshes only at startup and on the controls screen (controls_menu_update).
  player_input_t &input = player_state_table[player].input;
  input.axis_aim_x = keys.axis_aim_x;
  input.axis_aim_y = keys.axis_aim_y;
  input.axis_move_x = keys.axis_move_x;
  input.axis_move_y = keys.axis_move_y;
  input.fire_key = keys.fire_key;
}

// A standard button held or a stick pushed past half travel (gamepad_has_activity).
bool pad_used() {
  for (int code = FACE_DOWN; code < PAD_CODE_END; ++code)
    if (grim_pad_code_active(code))
      return true;
  for (int code = LEFT_STICK_X; code <= RIGHT_STICK_Y; ++code)
    if (grim_pad_code_active(code))
      return true;
  return false;
}

// auto_apply_pad_profiles for the host's one pad, player one's: stale stock
// bindings upgrade once the pad is connected, and switching a fully stock
// player's methods waits until the pad is used, so a mouse player with an idle
// pad plugged in keeps the mouse. The configuration is saved then, as the
// original saves it when it quits.
void profile_update() {
  int upgrades = connected() ? pending(0) : 0;
  if (upgrades && (!(upgrades & METHODS) || pad_used())) {
    apply(0, upgrades);
    config_sync_from_grim();
  }
}

// --- Menus (src/crimson/ui/focus.py) ----------------------------------------

// DirectInput scancodes the original's screens read.
enum Key { ESCAPE = 0x01, ENTER = 0x1c, UP = 0xc8, PAGE_UP = 0xc9, LEFT = 0xcb, RIGHT = 0xcd, DOWN = 0xd0,
           PAGE_DOWN = 0xd1 };

struct {
  // A pad navigated since the mouse last moved: the focus stays lit, and
  // hovering leaves it where the pad put it.
  bool active;
  // The right stick moved the cursor since the pad last stepped the focus: A
  // clicks where it points, which reaches what the focus does not.
  bool pointing;
  // The cursor stays where the right stick left it until the window's own
  // cursor moves (pad_holds_cursor), rather than the host's motion bringing it
  // back there.
  bool holds_cursor;
  // A holds the mouse button it pressed while pointing.
  bool clicking;
  // The pad must let go before it navigates: after gameplay (the sticks moved
  // and aimed the player) and after the controls screen took a press as a
  // binding.
  bool stick_held, aim_held, buttons_held;
  // The focused widget takes the pad's up/down or left/right as arrow keys
  // (hold), its A as Down, which opens a closed list, or its A as a typed
  // Enter, which a text field takes. Widgets set these each frame for the next.
  bool hold_up, hold_down, hold_sideways, enter_opens, enter_types;
  // A screen just shown, until its widgets register: then the focus goes to
  // the first of them.
  bool shown;
  // The direction held, and the seconds until it steps again.
  int direction;
  float repeat;
  bool buttons[PAD_CODE_END - FACE_DOWN]; // last frame's
  float mouse_x, mouse_y;
  float window[2]; // the window cursor the host last brought the game's to
} nav;

void press(int key) { grim_keyboard_state[key] = 0x80; }

// Where each widget of the screen drew last, by its focus id: the original
// registers them for Tab in whatever order its screens update them (the menu
// elements from the bottom of the screen up, a panel's list after its buttons),
// so the pad steps them as the screen shows them instead.
struct Place {
  int id;
  float x, y;
};
Place places[64];
int place_count;
void place(const void *widget, float x, float y) {
  int id = (int)(size_t)widget, at = 0;
  while (at < place_count && places[at].id != id)
    ++at;
  if (at == 64)
    return;
  places[at] = {id, x, y};
  place_count += at == place_count;
}
// Row by row, top first, then left to right; a widget never placed goes last.
float rank(int id) {
  for (int at = 0; at < place_count; ++at)
    if (places[at].id == id)
      return floorf(places[at].y / 8.0f) * 4096.0f + places[at].x;
  return 1e9f;
}
// The focus candidates as the screen shows them.
int screen_order(int order[32]) {
  float ranks[32];
  for (int slot = 0; slot < ui_focus_count; ++slot) {
    ranks[slot] = rank(ui_focus_candidates[slot]);
    int at = slot;
    for (; at > 0 && ranks[order[at - 1]] > ranks[slot]; --at)
      order[at] = order[at - 1];
    order[at] = slot;
  }
  return ui_focus_count;
}
enum Direction { NONE, NORTH, SOUTH, WEST, EAST };
// The focus one step that way: to the nearest widget there from where the
// focused one draws, sideways distance weighing half, so the next row's widget
// is reached however far across it sits. Left and right look within 56 degrees
// of straight and report nothing there, which leaves the arrow keys to page
// the quest list and the high scores; up and down wrap as Tab does.
bool step(Direction direction) {
  static const float dx[] = {0, 0, 0, -1, 1}, dy[] = {0, -1, 1, 0, 0};
  int order[32], count = screen_order(order);
  if (!count)
    return false;
  bool sideways = direction == WEST || direction == EAST;
  const Place *from = nullptr;
  for (int at = 0; at < place_count && ui_focus_index < ui_focus_count; ++at)
    if (places[at].id == ui_focus_candidates[ui_focus_index])
      from = &places[at];
  int nearest = -1;
  float best = INFINITY;
  for (int slot = 0; from && slot < ui_focus_count; ++slot)
    for (int at = 0; at < place_count; ++at) {
      if (places[at].id != ui_focus_candidates[slot])
        continue;
      float x = places[at].x - from->x, y = places[at].y - from->y;
      float along = x * dx[direction] + y * dy[direction], across = fabsf(x * dy[direction] - y * dx[direction]);
      if (along > 4.0f && (!sideways || across <= along * 1.5f) && along + across * 0.5f < best) {
        best = along + across * 0.5f;
        nearest = slot;
      }
    }
  if (nearest < 0 && sideways)
    return false;
  ui_focus_index = nearest >= 0 ? nearest : order[direction == SOUTH ? 0 : count - 1];
  return true;
}
int first_widget() {
  int order[32];
  return screen_order(order) ? order[0] : 0;
}

// The d-pad, or the left stick past half travel, as one direction.
Direction direction(bool stick) {
  float x = grim_pad_code_axis(LEFT_STICK_X), y = grim_pad_code_axis(LEFT_STICK_Y);
  bool pushed = fmaxf(fabsf(x), fabsf(y)) >= AXIS_DOWN;
  if (!pushed)
    nav.stick_held = false;
  if (grim_pad_code_active(DPAD_UP))
    return NORTH;
  if (grim_pad_code_active(DPAD_DOWN))
    return SOUTH;
  if (grim_pad_code_active(DPAD_LEFT))
    return WEST;
  if (grim_pad_code_active(DPAD_RIGHT))
    return EAST;
  if (!stick || nav.stick_held || !pushed)
    return NONE;
  if (fabsf(y) >= fabsf(x))
    return y > 0 ? SOUTH : NORTH;
  return x > 0 ? EAST : WEST;
}
// A direction steps when pushed, then after 400 ms every 120 ms while held (UiFocus._stick_press).
Direction stepped(Direction held) {
  if (held != nav.direction) {
    nav.direction = held;
    nav.repeat = 0.4f;
    return held;
  }
  if (held && (nav.repeat -= grim_frame_dt) <= 0.0f) {
    nav.repeat = 0.12f;
    return held;
  }
  return NONE;
}

// Once a frame, after Grim polls its devices: the pad's presses as the keys the
// original's screens read, and its directions as steps of the focus. Start is
// Escape everywhere (it pauses a run); in gameplay the rest of the pad plays,
// but over a co-op banner's buttons, and B leaves a replay as Escape does.
void navigate() {
  bool gameplay =
      (game_state_id == GAME_STATE_GAMEPLAY || game_state_id == GAME_STATE_TYPO_GAMEPLAY) && !game_coop_banner();
  bool hold_up = nav.hold_up, hold_down = nav.hold_down, hold_sideways = nav.hold_sideways,
       enter_opens = nav.enter_opens, enter_types = nav.enter_types, clicking = nav.clicking;
  nav.hold_up = nav.hold_down = nav.hold_sideways = nav.enter_opens = nav.enter_types = nav.clicking = false;
  if (ui_mouse_x != nav.mouse_x || ui_mouse_y != nav.mouse_y)
    nav.active = false;
  nav.mouse_x = ui_mouse_x;
  nav.mouse_y = ui_mouse_y;
  if (!connected())
    return;
  if (gameplay)
    nav.stick_held = nav.aim_held = true;
  Direction held = direction(!gameplay);
  bool pressed[PAD_CODE_END - FACE_DOWN], any = held != NONE;
  for (int code = FACE_DOWN; code < PAD_CODE_END; ++code) {
    bool down = grim_pad_code_active(code);
    pressed[code - FACE_DOWN] = down && !nav.buttons[code - FACE_DOWN];
    nav.buttons[code - FACE_DOWN] = down;
    any |= down;
  }
  if (!any)
    nav.buttons_held = false;
  // A rebind waits for its input, which takes the pad's (controls_menu_update).
  if (ui_focus_input_locked || nav.buttons_held)
    return;
  // Start, or B, resumes a paused run, as Start pauses it (the original resumes
  // only from its Back item).
  if (game_state_id == GAME_STATE_PAUSE_MENU && (pressed[START - FACE_DOWN] || pressed[FACE_RIGHT - FACE_DOWN])) {
    ui_menu_pause_click_resume();
    return;
  }
  if (pressed[START - FACE_DOWN] || (gameplay && game_watching() && pressed[FACE_RIGHT - FACE_DOWN]))
    press(ESCAPE);
  if (gameplay)
    return;
  // The right stick steers the cursor past the original analog cursor's dead
  // zone, quadratically: fine near the centre, and across the screen in about a
  // second at full tilt and the default sensitivity, where the original's
  // analog cursor took five.
  float x = grim_pad_code_axis(RIGHT_STICK_X), y = grim_pad_code_axis(RIGHT_STICK_Y), tilt = hypotf(x, y);
  nav.aim_held &= tilt > 0.2f;
  if (tilt > 0.2f && !nav.aim_held) {
    float scale = config_blob.mouse_sensitivity * 2160.0f * fminf(tilt, 1.0f) * grim_frame_dt;
    ui_mouse_x += x * scale;
    ui_mouse_y += y * scale;
    nav.pointing = nav.holds_cursor = true;
    nav.active = false;
  }
  Direction moved = stepped(held);
  if (moved)
    nav.pointing = false;
  switch (moved) {
  case NORTH:
    hold_up ? press(UP) : (void)step(NORTH);
    break;
  case SOUTH:
    hold_down ? press(DOWN) : (void)step(SOUTH);
    break;
  case WEST:
    if (hold_sideways || !step(WEST))
      press(LEFT);
    break;
  case EAST:
    if (hold_sideways || !step(EAST))
      press(RIGHT);
    break;
  case NONE:
    break;
  }
  bool accept = pressed[FACE_DOWN - FACE_DOWN];
  nav.clicking = nav.buttons[FACE_DOWN - FACE_DOWN] && (clicking || (accept && nav.pointing));
  if (accept && !nav.clicking) {
    press(enter_opens ? DOWN : ENTER);
    if (enter_types)
      game_key_char(13);
  }
  if (pressed[FACE_RIGHT - FACE_DOWN])
    press(ESCAPE);
  if (pressed[L1 - FACE_DOWN])
    press(PAGE_UP);
  if (pressed[R1 - FACE_DOWN])
    press(PAGE_DOWN);
  if (any)
    nav.active = true;
  // The original fades the focus a second after each Tab; a pad player would
  // lose track of it.
  if (nav.active)
    ui_focus_timer_ms = 1000;
}

bool focused(void *widget) { return ui_focus_candidates[ui_focus_index] == (int)(size_t)widget; }

// A pad press as a binding: a standard button, or for the axis rows a stick
// past half travel (capture_first_pressed_input_code).
int captured(bool axes) {
  if (axes) {
    for (int code = LEFT_STICK_X; code <= RIGHT_STICK_Y; ++code)
      if (grim_pad_code_active(code))
        return code;
    return 0;
  }
  for (int code = FACE_DOWN; code < PAD_CODE_END; ++code)
    if (grim_pad_code_active(code))
      return code;
  return 0;
}

} // namespace

extern "C" {
// game_frame (game/frame.cpp), once Grim has polled the devices.
void pad_frame() {
  // A newly shown screen starts on its first widget, not on the focus index
  // the last one left (UiFocus.screen_changed).
  // The end screens show their name entry and then their buttons as phases of
  // one state; a co-op banner shows its buttons over gameplay.
  static int state = -1, phase, marker;
  static bool banner;
  if (game_state_id != state || ui_screen_phase != phase || game_coop_banner() != banner) {
    state = game_state_id;
    phase = ui_screen_phase;
    banner = game_coop_banner();
    ui_focus_index = 0;
    place_count = 0;
    nav.shown = true;
    nav.pointing = false;
    marker = ui_focus_frame_marker_ms;
  } else if (nav.shown && ui_focus_frame_marker_ms != marker) {
    nav.shown = false;
    ui_focus_index = first_widget();
  }
  profile_update();
  navigate();
}

// Hovering takes the focus only while the mouse leads (ui_focus_set).
void ui_focus_set_recovered(int id, char reset_timer);
void ui_focus_set(int id, char reset_timer) {
  if (!nav.active || reset_timer)
    ui_focus_set_recovered(id, reset_timer);
}

// The widgets, each placed where it draws, from its top left corner; the menu
// elements by their clickable bounds.
#define PLACED(type, name, widget)                                                                             \
  type name##_recovered(float *xy, widget *state);                                                             \
  type name(float *xy, widget *state) {                                                                        \
    place(state, xy[0], xy[1]);                                                                                \
    return name##_recovered(xy, state);                                                                        \
  }
PLACED(bool, ui_button_update, void)
PLACED(bool, ui_checkbox_update, void)
PLACED(bool, ui_menu_item_update, void)
#undef PLACED
// A focused slider takes left and right (ui_segmented_slider_update).
void ui_segmented_slider_update_recovered(float *xy, void *state);
void ui_segmented_slider_update(float *xy, void *state) {
  place(state, xy[0], xy[1]);
  ui_segmented_slider_update_recovered(xy, state);
  nav.hold_sideways |= focused(state);
}
// A focused text field takes A as a typed Enter, which submits it (ui_text_input_update).
bool ui_text_input_update_recovered(float *xy, void *state);
bool ui_text_input_update(float *xy, void *state) {
  place(state, xy[0], xy[1]);
  bool submitted = ui_text_input_update_recovered(xy, state);
  nav.enter_types |= focused(state);
  return submitted;
}
// The quest list's rows, which the original leaves to the mouse and the number
// keys (changes/pad-menus.patch): each takes the focus, with its marker.
bool ui_focus_row(int row, float x, float y) {
  static char rows[10];
  place(&rows[row], x, y);
  bool focused = ui_focus_update((int)(size_t)&rows[row]);
  if (focused) {
    float at[2] = {x - 16.0f, y};
    ui_focus_draw(at);
  }
  return focused;
}
bool game_pad_connected() { return connected(); }

// The motion the host asks for to bring the game's cursor to the window's
// (game_motion_x): none while the right stick's cursor holds, which it does
// until the window's cursor moves.
bool pad_holds_cursor(int axis, float window) {
  if (window != nav.window[axis])
    nav.holds_cursor = nav.pointing = false;
  nav.window[axis] = window;
  return nav.holds_cursor;
}
// The mouse button A holds while the pad points (game/dinput.cpp).
bool pad_clicking() { return nav.clicking; }

void ui_element_render_recovered(ui_element_t *element);
void ui_element_render(ui_element_t *element) {
  place(element, element->hover_min_x, (element->hover_min_y + element->hover_max_y) * 0.5f);
  ui_element_render_recovered(element);
}

// A focused list: closed, A opens it; open, the pad's up/down walk its rows and
// A picks one (dropdown.py). An open list takes Escape, the keyboard's or B, as
// closing it, ahead of the screen, which takes it as going back
// (changes/escape-back.patch).
int ui_list_widget_update_recovered(float *xy, ui_list_widget_t *list);
int ui_list_widget_update(float *xy, ui_list_widget_t *list) {
  place(list, xy[0], xy[1]);
  if (list->open > 0 && grim_interface_ptr->grim_was_key_pressed(ESCAPE))
    list->open = 0;
  int result = ui_list_widget_update_recovered(xy, list);
  if (focused(list) && list->enabled) {
    nav.enter_opens |= list->open <= 0;
    nav.hold_up |= list->open > 0;
    nav.hold_down |= list->open > 0;
  }
  return result;
}

// A focused scroll list takes the pad's up/down until it reaches that end (scrollbar.py).
void ui_scrollbar_update_recovered(float *xy, ui_scrollbar_t *bar);
void ui_scrollbar_update(float *xy, ui_scrollbar_t *bar) {
  place(bar, xy[0], xy[1]);
  ui_scrollbar_update_recovered(xy, bar);
  if (focused(bar)) {
    nav.hold_up |= bar->scroll_offset > 0.0f;
    nav.hold_down |= bar->scroll_offset < (float)(bar->item_count - bar->visible_rows);
  }
}

// The controls screen: a rebind waiting for its input takes a pad press as the
// standard code, ahead of the original's scan, which would take the Joys and
// JoyAxis codes and never the d-pad. Rows 9-12 are the axes, 13 Level Up and
// 14 Reload.
void controls_menu_update_recovered(void);
void controls_menu_update(void) {
  int slot = controls_rebind_slot_index;
  if (slot != -1 && controls_rebind_capture_armed) {
    if (int code = captured(slot >= 9 && slot < 13)) {
      if (slot == 13)
        config_key_pick_perk = code;
      else if (slot == 14)
        config_key_reload = code;
      else
        config_blob.player_keys[controls_rebind_player_index * 16 + slot] = code;
      grim_interface_ptr->grim_flush_input();
      controls_rebind_slot_index = -1;
      controls_rebind_capture_armed = 0;
      nav.buttons_held = true;
    }
  }
  controls_menu_update_recovered();
}
}
