// The game module's Grim: the recovered engine, except that a simulation tick
// sees exactly the verifier's answers to input and time queries, so live play
// and verification read the same values.
extern "C" {
extern unsigned char game_ticking;
void register_core_cvars();
void game_audio_tick(float dt);
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
  GAME_TICK_QUERY(unsigned char, grim_is_key_active, (int key), (key))
  GAME_TICK_QUERY(unsigned char, grim_is_mouse_button_down, (int button), (button))
  GAME_TICK_QUERY(bool, grim_was_mouse_button_pressed, (int button), (button))
  GAME_TICK_QUERY(float, grim_get_mouse_wheel_delta, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_x, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_y, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_dx, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_dy, (void), ())
  GAME_TICK_QUERY(float, grim_get_mouse_dx_indexed, (int index), (index))
  GAME_TICK_QUERY(float, grim_get_mouse_dy_indexed, (int index), (index))
  GAME_TICK_QUERY(float, grim_get_config_float, (int id), (id))
  GAME_TICK_QUERY(int, grim_get_joystick_x, (void), ())
  GAME_TICK_QUERY(int, grim_get_joystick_y, (void), ())
  GAME_TICK_QUERY(int, grim_get_joystick_z, (void), ())
  GAME_TICK_QUERY(int, grim_get_joystick_pov, (int index), (index))
  GAME_TICK_QUERY(unsigned char, grim_is_joystick_button_down, (int button), (button))
#undef GAME_TICK_QUERY
  // The interface outlives every caller; the original deleted its heap copy.
  void grim_release(void) override {}
};
static SessionGrim session_grim;
unsigned char game_ticking;
// Engine strings outlive runs: those made while it boots, and every string of
// the original's own startup and loop (game_start).
static bool game_heap_strings;
// A run the verifier could replay: run start and ticks own the gameplay RNG.
static bool game_session;
// The original is running (game_start): its engine, device and loaded assets
// outlive a run.
static bool game_original;
// The client is playing a run inside it (host/session.inc).
static bool game_live;
void platform_headless_device();
extern "C" void portable_reset_engine_data();
extern "C" void portable_reset_simulation_data();
extern "C" unsigned char grim_render_disabled;
// The music tracks the run names, by audio_init_music's load order. A run
// inside the original ticks with the verifier's (portable_init's), which tell
// the end tunes from the in-game tune's request whatever the original loaded:
// with sound or music off it loaded none, and its ids are all 0. Between ticks
// the original's own are back (LiveSettings, host/session.inc).
struct GameMusic {
  int intro, shortie_monk, crimson_theme, crimsonquest, game_playlist, extra_1, playlist_count;
  music_playlist_t playlist;
};
static GameMusic game_music() {
  GameMusic music = {music_track_intro_id,        music_track_shortie_monk_id, music_track_crimson_theme_id,
                     music_track_crimsonquest_id, music_track_game_playlist,   music_track_extra_1,
                     music_playlist_entry_count,  {}};
  memcpy(music.playlist, music_playlist, sizeof music.playlist);
  return music;
}
static void game_music_install(const GameMusic &music) {
  music_track_intro_id = music.intro;
  music_track_shortie_monk_id = music.shortie_monk;
  music_track_crimson_theme_id = music.crimson_theme;
  music_track_crimsonquest_id = music.crimsonquest;
  music_track_game_playlist = music.game_playlist;
  music_track_extra_1 = music.extra_1;
  music_playlist_entry_count = music.playlist_count;
  memcpy(music_playlist, music.playlist, sizeof music_playlist);
}
// Inside the original, a run keeps what it loaded (game.py's SESSION_KEEPS),
// and plays the tracks the original loaded, at the player's volumes, saved
// before the reset.
static struct {
  GameMusic music;
  float music_volume, sfx_volume;
} game_shell_audio;
static void game_save_shell_audio() {
  game_shell_audio = {game_music(), config_blob.music_volume, config_blob.sfx_volume};
}
static void game_run_ready() {
  if (!game_original)
    return;
  config_blob.music_volume = game_shell_audio.music_volume;
  config_blob.sfx_volume = game_shell_audio.sfx_volume;
}
extern "C" {
// The original's track for one a tick names by the verifier's id: what a tick
// plays, or changes the volume of, is the original's.
int game_shell_track(int id) {
  if (!game_ticking || !game_original)
    return id;
  const GameMusic &shell = game_shell_audio.music;
  return id == music_track_intro_id           ? shell.intro
         : id == music_track_shortie_monk_id  ? shell.shortie_monk
         : id == music_track_crimson_theme_id ? shell.crimson_theme
         : id == music_track_crimsonquest_id  ? shell.crimsonquest
         : id == music_track_game_playlist    ? shell.game_playlist
         : id == music_track_extra_1          ? shell.extra_1
                                              : id;
}
}
static void game_reset_run_data() {
  if (game_original) {
    game_save_shell_audio();
    portable_reset_simulation_data();
  } else {
    portable_reset_data();
  }
}
static void game_init_run() {
  static bool booted;
  if (!booted && !game_original) {
    game_heap_strings = true;
    portable_reset_engine_data();
    grim_state_init();
    register_core_cvars();
    game_heap_strings = false;
    // Headless, Grim's own switch keeps every draw and render target away from
    // the device; the recovered state changes still reach it.
    platform_headless_device();
    grim_render_disabled = 1;
    booted = true;
  }
  game_session = true;
  grim_interface_ptr = &session_grim;
  cv_friendlyFire->value = cfg.friendly_fire ? 1 : 0;
}
// Live input and wall time reach the simulation only through the verifier's
// seam: inside run start and ticks, Grim answers as the headless verifier does.
struct GameTick {
  unsigned char outer = game_ticking;
  GameTick() { game_ticking = 1; }
  ~GameTick() { game_ticking = outer; }
};
// The executable's own seams: the verifier's session policy inside ticks, the
// recovered behaviour elsewhere.
extern "C" {
bool input_primary_just_pressed_recovered();
int play_time_get_recovered();
bool input_primary_just_pressed() {
  return game_ticking ? (player_in().flags & 2) != 0 : input_primary_just_pressed_recovered();
}
int play_time_get() { return game_ticking ? 0 : play_time_get_recovered(); }
// Headless, the verifier's silent audio has no buffers to play. Ticks nobody
// hears (a replay's preparing pass and seeks, host/watch.inc) play none either:
// they get the first buffer, unplayed, which callers set up as they would a
// playing one.
static bool sound_unheard;
int sfx_entry_start_playback_recovered(music_entry_t *entry);
int sfx_entry_start_playback(music_entry_t *entry) {
  if (!entry->buffers[0])
    return -1;
  return sound_unheard ? 0 : sfx_entry_start_playback_recovered(entry);
}
// During a run the host owns the run-down this UI timeline drives in the
// original (portable_step_many), exactly as in the verifier.
void ui_elements_update_and_render_recovered();
// This build, as the console's corner names it.
char *game_version_label() {
  static char label[64];
  if (!*label)
    snprintf(label, sizeof label, "crimson.land %s", CRIMSON_GAME_VERSION);
  return label;
}
void ui_elements_update_and_render() {
  if (!game_ticking)
    ui_elements_update_and_render_recovered();
}
}
// The original's own startup (game/frame.cpp): no session, so the recovered RNG,
// input and clock run everywhere, as in the 2003 executable.
extern "C" {
int crimsonland_main(void *, void *, char *, int);
void game_outputs(int enabled);
void crt_srand(unsigned int seed) { rng = seed; }
// GRIM__GetInterface (api/get_interface.cpp): the engine's state, then its interface,
// which Grim's own joystick direction queries call through.
// The main menu leaves out Other Games, 10tons' catalogue of the time (Grim's
// config var 100), as the Python port does (screens/menu.py).
extern grim_config_value_t grim_config_values[128];
extern IGrim2D_cpp *grim_interface_instance;
IGrim2D_cpp *grim_load_interface(char *) {
  static bool loaded;
  if (!loaded) {
    grim_state_init();
    grim_config_values[100] = false;
    grim_interface_instance = &session_grim;
    loaded = true;
  }
  return &session_grim;
}
// The compiler-generated constructors of the metadata tables data.cpp lays out.
void quest_meta_global_construct_and_register() {
  for (int i = 0; i < 50; ++i)
    new (&quest_meta_table[i]) quest_meta_cpp_t;
}
void perk_meta_global_construct_and_register() {
  for (int i = 0; i < 128; ++i)
    new (&perk_meta_table[i]) perk_meta_cpp_t;
}
void bonus_meta_global_construct_and_register() {
  for (int i = 0; i < 15; ++i)
    new (&bonus_meta_table[i]) bonus_meta_cpp_t;
}
void game_static_init();
__attribute__((export_name("game_start"))) int game_start() {
  game_session = false;
  game_original = true;
  game_heap_strings = true;
  portable_reset_engine_data();
  portable_reset_data();
  rng = 1; // the CRT's rand seed before any srand
  game_static_init();
  game_outputs(1);
  static char command_line[] = "";
  return crimsonland_main(nullptr, nullptr, command_line, 0);
}
}
