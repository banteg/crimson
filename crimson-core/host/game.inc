// The game module's Grim: the recovered engine, except that a simulation tick
// sees exactly the verifier's answers to input and time queries, so live play
// and verification read the same values.
extern "C" {
extern unsigned char game_ticking;
void register_core_cvars();
}
void grim_state_init();
class SessionGrim final : public IGrim2D_cpp {
public:
#define GAME_TICK_QUERY(ret, name, params, args)                               \
  ret name params override {                                                   \
    return game_ticking ? headless_grim.name args : IGrim2D_cpp::name args;   \
  }
  GAME_TICK_QUERY(int, grim_get_time_ms, (void), ())
  GAME_TICK_QUERY(float, grim_get_frame_dt, (void), ())
  GAME_TICK_QUERY(float, grim_get_fps, (void), ())
  GAME_TICK_QUERY(unsigned char, grim_is_key_down, (unsigned char key), (key))
  GAME_TICK_QUERY(bool, grim_was_key_pressed, (unsigned int key), (key))
  GAME_TICK_QUERY(void, grim_flush_input, (void), ())
  GAME_TICK_QUERY(int, grim_get_key_char, (void), ())
  GAME_TICK_QUERY(void, grim_set_key_char_buffer, (unsigned char *buffer, int *count, int size), (buffer, count, size))
  GAME_TICK_QUERY(void, grim_set_mouse_pos, (float x, float y), (x, y))
  GAME_TICK_QUERY(unsigned char, grim_is_mouse_button_down, (int button), (button))
  GAME_TICK_QUERY(bool, grim_was_mouse_button_pressed, (int button), (button))
  GAME_TICK_QUERY(float, grim_get_mouse_wheel_delta, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_x, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_y, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_dx, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_dy, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_dx_indexed, (int index), (index))
  GAME_TICK_QUERY(float, grim_get_mouse_dy_indexed, (int index), (index))
  GAME_TICK_QUERY(unsigned char, grim_is_key_active, (int key), (key))
  GAME_TICK_QUERY(float, grim_get_config_float, (int id), (id))
  GAME_TICK_QUERY(int, grim_get_joystick_x, (void), ())
  GAME_TICK_QUERY(int, grim_get_joystick_y, (void), ())
  GAME_TICK_QUERY(int, grim_get_joystick_z, (void), ())
  GAME_TICK_QUERY(int, grim_get_joystick_pov, (int index), (index))
  GAME_TICK_QUERY(unsigned char, grim_is_joystick_button_down, (int button), (button))
#undef GAME_TICK_QUERY
};
static SessionGrim session_grim;
unsigned char game_ticking;
void platform_headless_device();
extern "C" void portable_reset_grim_data();
extern "C" unsigned char grim_render_disabled;
static void game_init_run() {
  static bool booted;
  if (!booted) {
    portable_reset_grim_data();
    grim_state_init();
    // Headless, Grim's own switch keeps every draw and render target away from
    // the device; the recovered state changes still reach it.
    platform_headless_device();
    grim_render_disabled = 1;
    booted = true;
  }
  grim_interface_ptr = &session_grim;
  register_core_cvars();
  cv_friendlyFire->value = cfg.friendly_fire ? 1 : 0;
}
// Live input and wall time reach the simulation only through the verifier's
// seam: inside run start and ticks, Grim answers as the headless verifier does.
struct GameTick {
  GameTick() { game_ticking = 1; }
  ~GameTick() { game_ticking = 0; }
};
