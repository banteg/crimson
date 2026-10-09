// What a replay shows over its world (host/watch.inc, docs/rewrite/replay-viewer.md),
// in the original's own art: a transport bar along the bottom, the HUD's top
// plate turned over, with its buttons and a scrub bar of the Options sliders'
// segments marked with the run's milestone waves, Energizer drops and perk
// picks; a card for each perk pick, under where the level-up prompt swings in;
// and the menus' panel for preparing the replay and for its end. The bar slides
// away while the replay plays untouched.
extern "C" {
bool ui_button_update(float *xy, ui_button_t *button);
void ui_cursor_render(void);
}

// Survival's milestone waves (survival_update), by the stage they start.
static const char *const viewer_waves[] = {"",
                                           "Alien rings",
                                           "Red alien boss",
                                           "Spider swarm",
                                           "Fast aliens",
                                           "Stop-and-go spiders",
                                           "Spider boss",
                                           "Splitter spider",
                                           "Splitter spiders",
                                           "Plasma spiders",
                                           "Second spider boss"};

static constexpr float VIEWER_BAR_H = 64.0f;
static constexpr float VIEWER_IDLE_SECONDS = 2.5f;
static constexpr float VIEWER_PIP_W = 8.0f, VIEWER_PIP_H = 16.0f;

static struct {
  int top, panel, pip_on, pip_off; // texture handles
  float idle;   // seconds since the viewer moved the cursor
  float shown;  // the bar's slide: 0 away, 1 up
  float last_x, last_y;
  bool dragging, down, clicked;
  float card;   // the card's slide in: 0 off, 1 in
  ui_button_t back, play, forward, speed, again, leave;
} viewer;

// The textures the original loaded at startup, by the names it gave them: the
// HUD's (hud_update_and_render), the menus' panel (ui_element_load names a
// texture by its path) and the Options sliders' segments.
static void viewer_reset() {
  auto handle = [](const char *name) { return grim_interface_ptr->grim_get_texture_handle((char *)name); };
  viewer.top = handle("iGameUI");
  viewer.panel = handle("ui\\ui_menuPanel");
  viewer.pip_on = handle("ui_rectOn");
  viewer.pip_off = handle("ui_rectOff");
  viewer.idle = 0;
  viewer.shown = 1;
  viewer.dragging = viewer.down = false;
  viewer.card = 0;
  const ui_button_t plate = {(char *)"", 0, 0, 1, 0, 0, 0, 1.0f, 1, 0};
  viewer.back = viewer.play = viewer.forward = viewer.speed = viewer.again = viewer.leave = plate;
  viewer.back.label = (char *)"<<";
  viewer.forward.label = (char *)">>";
  viewer.again.label = (char *)"Watch again";
  viewer.leave.label = (char *)"Back";
  viewer.again.force_small = viewer.leave.force_small = 0;
  viewer.again.force_wide = viewer.leave.force_wide = 1;
}

static float viewer_w() { return (float)config_blob.screen_width; }
static float viewer_h() { return (float)config_blob.screen_height; }
// The bar's top edge, slid by how far it is shown.
static float viewer_bar_y() { return viewer_h() - VIEWER_BAR_H * viewer.shown; }
// The scrub bar: its segments' left edge, count and row.
static float viewer_scrub_x() { return 280.0f; }
static int viewer_pips() { return (int)((viewer_w() - viewer_scrub_x() - 112.0f) / VIEWER_PIP_W); }
static float viewer_scrub_y() { return viewer_bar_y() + 30.0f; }
static int viewer_tick_at(float x) {
  float t = (x - viewer_scrub_x()) / (viewer_pips() * VIEWER_PIP_W);
  return (int)lroundf(fminf(fmaxf(t, 0.0f), 1.0f) * watch.ticks);
}
static float viewer_x_of(int at_tick) {
  return viewer_scrub_x() + (watch.ticks ? (float)at_tick / watch.ticks : 0) * viewer_pips() * VIEWER_PIP_W;
}
static bool viewer_over_scrub(float x, float y) {
  return x >= viewer_scrub_x() - 4 && x <= viewer_scrub_x() + viewer_pips() * VIEWER_PIP_W + 4 &&
         y >= viewer_scrub_y() - 10 && y <= viewer_scrub_y() + VIEWER_PIP_H + 6;
}

static void viewer_clock(char *out, size_t size, int at_tick) {
  int seconds = at_tick / 60;
  snprintf(out, size, "%d:%02d", seconds / 60, seconds % 60);
}
static void viewer_text(float x, float y, const char *text, float r, float g, float b, float a) {
  grim_interface_ptr->grim_set_color(r, g, b, a);
  grim_interface_ptr->grim_draw_text_small(x, y, (char *)text);
}
static float viewer_text_w(const char *text) { return (float)grim_interface_ptr->grim_measure_text_width((char *)text); }
// Grim's quad state carries from the game's last draw (its rotation among it): each quad sets its own.
static void viewer_quad(int texture, float x, float y, float w, float h, float u0, float v0, float u1, float v1, float a) {
  grim_interface_ptr->grim_bind_texture(texture, 0);
  grim_interface_ptr->grim_set_color(1, 1, 1, a);
  grim_interface_ptr->grim_set_rotation(0);
  grim_interface_ptr->grim_begin_batch();
  grim_interface_ptr->grim_set_uv(u0, v0, u1, v1);
  grim_interface_ptr->grim_draw_quad(x, y, w, h);
  grim_interface_ptr->grim_end_batch();
}
// The menus' panel, its frame and screen without the wire (ui_menuPanel, 322x234
// of its 512x256), at `scale`.
static void viewer_panel(float x, float y, float scale, float a) {
  viewer_quad(viewer.panel, x, y, 322 * scale, 234 * scale, 178 / 512.0f, 14 / 256.0f, 500 / 512.0f, 248 / 256.0f, a);
}
static constexpr float VIEWER_PANEL_IN_X = 18, VIEWER_PANEL_IN_Y = 22; // the screen's corner inside the panel

static const char *viewer_mark_label(const WatchMark &mark, char *out, size_t size) {
  if (mark.kind == WATCH_WAVE)
    snprintf(out, size, "Wave %d: %s", mark.value, mark.value < 11 ? viewer_waves[mark.value] : "");
  else if (mark.kind == WATCH_ENERGIZER)
    snprintf(out, size, "Energizer");
  else {
    const WatchPick &pick = watch.picks[mark.value];
    snprintf(out, size, "Level %d: %s", pick.level, perk_meta_table[pick.offered[pick.chosen]].name);
  }
  return out;
}

// The cursor and the scrub bar before the frame's ticks: a drag seeks at once.
static void viewer_update(float dt) {
  float x = watch.mouse_x, y = watch.mouse_y;
  bool down = session_grim.IGrim2D_cpp::grim_is_mouse_button_down(0) != 0, pressed = down && !viewer.down;
  viewer.down = down;
  viewer.clicked = pressed;
  if (x != viewer.last_x || y != viewer.last_y || down)
    viewer.idle = 0;
  else
    viewer.idle += dt;
  viewer.last_x = x;
  viewer.last_y = y;
  bool want = watch.paused || watch.phase != WATCH_PLAYING || viewer.idle < VIEWER_IDLE_SECONDS || viewer.dragging ||
              y > viewer_h() - VIEWER_BAR_H - 16;
  viewer.shown = fminf(1.0f, fmaxf(0.0f, viewer.shown + (want ? dt : -dt) * 6.0f));
  if (pressed && viewer.shown > 0.5f && viewer_over_scrub(x, y))
    viewer.dragging = true;
  if (!down)
    viewer.dragging = false;
  if (viewer.dragging) {
    int at = viewer_tick_at(x);
    if (at != watch.tick)
      watch_ask(at);
  }
}

static void viewer_bar() {
  float y = viewer_bar_y(), w = viewer_w();
  // The HUD's top plate turned over: its left end, its plain middle stretched,
  // and its left end mirrored for the right (its own right end is slanted).
  float cap = 96, middle0 = 128 / 512.0f, middle1 = 384 / 512.0f;
  viewer_quad(viewer.top, 0, y, cap, VIEWER_BAR_H, 0, 1, cap / 512, 0, 0.95f);
  viewer_quad(viewer.top, cap, y, w - 2 * cap, VIEWER_BAR_H, middle0, 1, middle1, 0, 0.95f);
  viewer_quad(viewer.top, w - cap, y, cap, VIEWER_BAR_H, cap / 512, 1, 0, 0, 0.95f);

  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  float by = y + 22.0f;
  float at[2] = {14.0f, by};
  if (ui_button_update(at, &viewer.back))
    watch_ask(watch.tick - 5 * 60);
  viewer.play.label = (char *)(watch.phase == WATCH_ENDED ? "Again" : watch.paused ? "Play" : "Pause");
  at[0] = 96.0f;
  if (ui_button_update(at, &viewer.play)) {
    if (watch.phase == WATCH_ENDED)
      watch_ask(1), watch.paused = false;
    else
      watch.paused = !watch.paused;
  }
  at[0] = 178.0f;
  if (ui_button_update(at, &viewer.forward))
    watch_ask(watch.tick + 5 * 60);

  // The scrub bar: segments up to where playback is, the marks over them.
  int pips = viewer_pips(), lit = watch.ticks ? (int)((int64_t)pips * watch.tick / watch.ticks) : pips;
  float sx = viewer_scrub_x(), sy = viewer_scrub_y();
  grim_interface_ptr->grim_bind_texture(viewer.pip_off, 0);
  grim_interface_ptr->grim_set_rotation(0);
  grim_interface_ptr->grim_set_color(1, 1, 1, 0.5f);
  grim_interface_ptr->grim_begin_batch();
  grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
  for (int i = lit; i < pips; ++i)
    grim_interface_ptr->grim_draw_quad(sx + i * VIEWER_PIP_W, sy, VIEWER_PIP_W, VIEWER_PIP_H);
  grim_interface_ptr->grim_end_batch();
  grim_interface_ptr->grim_bind_texture(viewer.pip_on, 0);
  grim_interface_ptr->grim_set_color(1, 1, 1, 1);
  grim_interface_ptr->grim_begin_batch();
  grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
  for (int i = 0; i < lit; ++i)
    grim_interface_ptr->grim_draw_quad(sx + i * VIEWER_PIP_W, sy, VIEWER_PIP_W, VIEWER_PIP_H);
  grim_interface_ptr->grim_end_batch();
  for (const WatchMark &mark : watch.marks) {
    float mx = viewer_x_of(mark.tick);
    float color[4] = {1, 1, 1, 0.8f}, h = 5;
    if (mark.kind == WATCH_WAVE)
      color[0] = 1, color[1] = 0.35f, color[2] = 0.25f, color[3] = 1, h = 8;
    else if (mark.kind == WATCH_ENERGIZER)
      color[0] = 0.3f, color[1] = 0.85f, color[2] = 1, color[3] = 1, h = 8;
    float pos[2] = {floorf(mx), sy - h - 2};
    grim_interface_ptr->grim_draw_rect_filled(pos, 2, h, color);
  }
  // The playhead.
  float head[2] = {floorf(viewer_x_of(watch.tick)) - 1, sy - 3}, white[4] = {1, 1, 1, 1};
  grim_interface_ptr->grim_draw_rect_filled(head, 3, VIEWER_PIP_H + 6, white);

  // Time and speed, right of the bar.
  float mx = watch.mouse_x, my = watch.mouse_y;
  char now[16], total[16], line[48];
  viewer_clock(now, sizeof now, watch.tick);
  viewer_clock(total, sizeof total, watch.ticks);
  snprintf(line, sizeof line, "%s / %s", now, total);
  float tx = sx + pips * VIEWER_PIP_W + 12;
  viewer_text(tx, sy - 6, line, 0.9f, 0.9f, 0.9f, 0.9f);
  char speed[16];
  snprintf(speed, sizeof speed, watch_speeds[watch.speed] < 1 ? "%.2gx" : "%.0fx", watch_speeds[watch.speed]);
  // A click on the speed steps it up, round to the slowest.
  bool over = mx >= tx && mx < tx + 40 && my >= sy + 6 && my < sy + 24;
  viewer_text(tx, sy + 8, speed, over ? 1.0f : 0.7f, over ? 1.0f : 0.75f, over ? 1.0f : 0.8f, 0.9f);
  if (over && viewer.clicked)
    watch.speed = (watch.speed + 1) % WATCH_SPEEDS;

  // Under the cursor: the time, and a mark near it.
  if (viewer_over_scrub(mx, my) || viewer.dragging) {
    char tip[64];
    viewer_clock(tip, sizeof tip, viewer_tick_at(mx));
    for (const WatchMark &mark : watch.marks)
      if (fabsf(viewer_x_of(mark.tick) - mx) <= 4) {
        char label[48];
        snprintf(tip + strlen(tip), sizeof tip - strlen(tip), "  %s", viewer_mark_label(mark, label, sizeof label));
        break;
      }
    float tw = viewer_text_w(tip) + 12, px = fminf(fmaxf(mx - tw * 0.5f, 4.0f), viewer_w() - tw - 4);
    float pos[2] = {px, sy - 32}, back[4] = {0, 0, 0, 0.8f};
    grim_interface_ptr->grim_draw_rect_filled(pos, tw, 18, back);
    viewer_text(px + 6, sy - 30, tip, 1, 1, 1, 1);
  }
}

// The last pick's card, under the level-up prompt: the menu's offers, the
// chosen one lit, and its description.
static void viewer_card(float dt) {
  if (watch.card >= 0 && !watch.paused)
    watch.card_left -= dt;
  bool in = watch.card >= 0 && watch.card_left > 0;
  viewer.card = fminf(1.0f, fmaxf(0.0f, viewer.card + (in ? dt : -dt) * 5.0f));
  if (viewer.card <= 0) {
    if (!in)
      watch.card = -1;
    return;
  }
  const WatchPick &pick = watch.picks[watch.card];
  float scale = 0.9f, w = 322 * scale, ease = 1 - (1 - viewer.card) * (1 - viewer.card);
  float x = viewer_w() - (w + 8) * ease, y = 88;
  viewer_panel(x, y, scale, 1);
  float tx = x + VIEWER_PANEL_IN_X * scale + 10, ty = y + VIEWER_PANEL_IN_Y * scale + 6;
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  char line[64];
  snprintf(line, sizeof line, "Level %d: perk picked", pick.level);
  viewer_text(tx, ty, line, 0.5f, 0.75f, 1, 1);
  for (int i = 0; i < pick.count; ++i) {
    const char *name = perk_meta_table[pick.offered[i]].name;
    float ry = ty + 20 + i * 16;
    if (i == pick.chosen) {
      // The perk menu's lit row.
      float row[2] = {tx - 6, ry - 1}, color[4] = {0.27f, 0.51f, 0.86f, 0.35f};
      grim_interface_ptr->grim_draw_rect_filled(row, w - 2 * VIEWER_PANEL_IN_X * scale - 8, 16, color);
      viewer_text(tx, ry, name, 1, 1, 1, 1);
    } else
      viewer_text(tx, ry, name, 0.6f, 0.62f, 0.66f, 0.8f);
  }
  // The chosen perk's description, as the perk menu wraps it.
  grim_interface_ptr->grim_set_config_var(0x18, 0.43f);
  viewer_text(tx, ty + 26 + pick.count * 16, perk_meta_table[pick.offered[pick.chosen]].description, 0.8f, 0.8f, 0.8f,
              0.9f);
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
}

static void viewer_center_panel(const char *const *lines, int count, bool buttons) {
  float scale = 1.0f, w = 322 * scale, h = 234 * scale;
  float x = (viewer_w() - w) * 0.5f, y = (viewer_h() - h) * 0.5f - 30;
  viewer_panel(x, y, scale, 1);
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  float ty = y + VIEWER_PANEL_IN_Y + 16;
  for (int i = 0; i < count; ++i) {
    float lw = viewer_text_w(lines[i]);
    float bright = i == 0 ? 1.0f : 0.8f;
    viewer_text(x + (w - lw) * 0.5f + 4, ty + i * 20, lines[i], bright, bright, bright, 1);
  }
  if (!buttons)
    return;
  float at[2] = {x + 22, y + h - 60};
  if (ui_button_update(at, &viewer.again))
    watch_ask(1), watch.paused = false;
  at[0] = x + w - 22 - 145;
  if (ui_button_update(at, &viewer.leave))
    watch.leave = true;
}

static void viewer_preparing() {
  float black[4] = {0, 0, 0, 1}, at[2] = {0, 0};
  grim_interface_ptr->grim_draw_rect_filled(at, viewer_w(), viewer_h(), black);
  const char *lines[] = {"Preparing the replay", ""};
  viewer_center_panel(lines, 1, false);
  // Segments for how much of the recording the pass has played.
  int pips = 24;
  size_t size = watch.replay.recording.size();
  int lit = size ? (int)((int64_t)pips * watch.at / size) : 0;
  float x = (viewer_w() - pips * VIEWER_PIP_W) * 0.5f + 4, y = viewer_h() * 0.5f - 18;
  for (int i = 0; i < pips; ++i)
    viewer_quad(i < lit ? viewer.pip_on : viewer.pip_off, x + i * VIEWER_PIP_W, y, VIEWER_PIP_W, VIEWER_PIP_H, 0, 0, 1, 1,
                i < lit ? 1.0f : 0.5f);
}

static void viewer_end() {
  const LoadedReplay &replay = watch.replay;
  char ending[64], score[64], elapsed[16];
  if (replay.outcome == "death") {
    viewer_clock(elapsed, sizeof elapsed, (int)(replay.elapsed_ms * 60 / 1000));
    snprintf(ending, sizeof ending, "Died at %s", elapsed);
  } else if (replay.outcome == "quest_completed")
    snprintf(ending, sizeof ending, "Quest completed in %.2f s",
             (replay.quest_final_ms >= 0 ? replay.quest_final_ms : replay.elapsed_ms) / 1000.0);
  else
    snprintf(ending, sizeof ending, "Left before the end");
  snprintf(score, sizeof score, "Experience %lld, kills %lld", (long long)replay.experience, (long long)replay.kills);
  const char *verdict = !watch.stopped.empty() ? watch.stopped.c_str()
                        : watch.played         ? "Played as recorded"
                                               : "This run played differently";
  const char *lines[] = {ending, score, verdict};
  viewer_center_panel(lines, 3, true);
}

static void viewer_draw(float dt) {
  if (watch.phase == WATCH_PREPARING)
    return viewer_preparing();
  viewer_card(dt);
  if (watch.phase == WATCH_ENDED)
    viewer_end();
  if (viewer.shown > 0)
    viewer_bar();
  if (viewer.shown > 0 || watch.phase == WATCH_ENDED)
    ui_cursor_render();
}
