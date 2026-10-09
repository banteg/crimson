// What a replay shows over its world (host/watch.inc, docs/rewrite/replay-viewer.md).
// While it plays, the viewer keeps to dim bands that stay clear of the game's
// own HUD: a scrub bar of the Options sliders' segments along the bottom,
// marked with the run's milestone waves, Energizer drops and perk picks, and a
// box for each perk pick under where the level-up prompt swings in. Preparing
// the replay and its end are the original's own: the game over screen's panel
// and score card. The bar slides away while the replay plays untouched; a click
// on the world pauses it.
extern "C" {
extern ui_element_t ui_element_slot_30; // the game over screen's panel
extern int ui_text_reaper_texture, ui_text_well_done_texture;
bool ui_button_update(float *xy, ui_button_t *button);
void ui_cursor_render(void);
void ui_element_render(ui_element_t *element);
void ui_draw_textured_quad(int x, int y, int width, int height, int texture_id);
void ui_text_input_render(float *xy, highscore_record_t *record, float alpha, int rank);
char *format_ordinal_recovered(int value);

// A rank the card does not know (a board run that is not its runner's best),
// which no screen of the original's asks for: a dash.
char *format_ordinal(int value) { return value > 0 ? format_ordinal_recovered(value) : (char *)"-"; }
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

// The bar's band: the segments' row, with room above for the marks.
static constexpr float VIEWER_BAR_H = 48.0f;
static constexpr float VIEWER_IDLE_SECONDS = 2.5f;
static constexpr float VIEWER_PIP_W = 8.0f, VIEWER_PIP_H = 16.0f;

static struct {
  int pip_on, pip_off; // texture handles
  float idle;   // seconds since the viewer moved the cursor
  float shown;  // the bar's slide: 0 away, 1 up
  float last_x, last_y;
  bool dragging, down, clicked;
  float card;   // the card's slide in: 0 off, 1 in
  float card_box[4]; // the pick box as last drawn: x, y, width, height
  float end;    // the end screen's slide in
  ui_button_t again, leave;
} viewer;

// The Options sliders' segments, which the original loaded at startup, by the
// names it gave them.
static void viewer_reset() {
  auto handle = [](const char *name) { return grim_interface_ptr->grim_get_texture_handle((char *)name); };
  viewer.pip_on = handle("ui_rectOn");
  viewer.pip_off = handle("ui_rectOff");
  viewer.idle = 0;
  viewer.shown = 1;
  viewer.dragging = viewer.down = false;
  viewer.card = viewer.end = 0;
  // The game over screen's buttons.
  const ui_button_t plate = {(char *)"", 0, 0, 1, 0, 0, 0, 1.0f, 0, 0};
  viewer.again = viewer.leave = plate;
  viewer.again.label = (char *)"Watch Again";
  viewer.leave.label = (char *)"High scores";
}

static float viewer_w() { return (float)config_blob.screen_width; }
static float viewer_h() { return (float)config_blob.screen_height; }
// The bar's top edge, slid by how far it is shown.
static float viewer_bar_y() { return viewer_h() - VIEWER_BAR_H * viewer.shown; }
// The scrub bar: its segments' left edge, count and row.
static float viewer_scrub_x() { return 112.0f; }
static int viewer_pips() { return (int)((viewer_w() - viewer_scrub_x() - 120.0f) / VIEWER_PIP_W); }
static float viewer_scrub_y() { return viewer_bar_y() + 18.0f; }
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

// The cursor and the scrub bar before the frame's ticks: a drag seeks at once,
// and a click on the world pauses or plays on.
static bool viewer_over_card(float x, float y);
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
  bool on_bar = viewer.shown > 0.5f && y >= viewer_bar_y();
  if (pressed && viewer.shown > 0.5f && viewer_over_scrub(x, y))
    viewer.dragging = true;
  else if (pressed && !on_bar && !viewer_over_card(x, y) && watch.phase == WATCH_PLAYING)
    watch.paused = !watch.paused;
  if (!down)
    viewer.dragging = false;
  if (viewer.dragging) {
    int at = viewer_tick_at(x);
    if (at != watch.tick)
      watch_ask(at);
  }
}

// Text with the game's drop shadow under it, for text on the world itself.
static void viewer_shadowed(float x, float y, const char *text, float r, float g, float b, float a) {
  viewer_text(x + 1, y + 1, text, 0, 0, 0, a * 0.8f);
  viewer_text(x, y, text, r, g, b, a);
}

static void viewer_bar() {
  // A dim band along the bottom, which keeps the segments clear of any ground,
  // snow too, and leaves the game's own HUD its look.
  float band[2] = {0, viewer_bar_y()}, dim[4] = {0, 0, 0, 0.45f};
  grim_interface_ptr->grim_draw_rect_filled(band, viewer_w(), VIEWER_BAR_H, dim);
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

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

  // Paused, or the speed, left of the bar; time right of it.
  float mx = watch.mouse_x, my = watch.mouse_y;
  char state[16];
  if (watch.paused)
    snprintf(state, sizeof state, "Paused");
  else
    snprintf(state, sizeof state, watch_speeds[watch.speed] < 1 ? "%.2gx" : "%.0fx", watch_speeds[watch.speed]);
  // A click on it steps the speed up, round to the slowest.
  float lx = sx - 12 - viewer_text_w(state);
  bool over = mx >= lx - 4 && mx < sx - 4 && my >= sy - 2 && my < sy + 18;
  viewer_shadowed(lx, sy + 1, state, over ? 1.0f : 0.75f, over ? 1.0f : 0.78f, over ? 1.0f : 0.82f, 0.9f);
  if (over && viewer.clicked)
    watch.speed = (watch.speed + 1) % WATCH_SPEEDS;
  char now[16], total[16], line[48];
  viewer_clock(now, sizeof now, watch.tick);
  viewer_clock(total, sizeof total, watch.ticks);
  snprintf(line, sizeof line, "%s / %s", now, total);
  viewer_shadowed(sx + pips * VIEWER_PIP_W + 12, sy + 1, line, 0.9f, 0.9f, 0.9f, 0.9f);

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

// The pick box, right-aligned under the level-up prompt.
static constexpr float VIEWER_CARD_Y = 88;
static bool viewer_over_card(float x, float y) {
  const float *box = viewer.card_box;
  return viewer.card > 0 && x >= box[0] && x < box[0] + box[2] && y >= box[1] && y < box[1] + box[3];
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
  const perk_meta_t &chosen = perk_meta_table[pick.offered[pick.chosen]];
  char line[64];
  float w = 0;
  for (int i = 0; i < pick.count; ++i)
    w = fmaxf(w, viewer_text_w(perk_meta_table[pick.offered[i]].name));
  w += 28;
  float ease = 1 - (1 - viewer.card) * (1 - viewer.card);
  float x = viewer_w() - (w + 8) * ease, y = VIEWER_CARD_Y, h = 32.0f + pick.count * 15;
  viewer.card_box[0] = x, viewer.card_box[1] = y, viewer.card_box[2] = w, viewer.card_box[3] = h;
  // The offers in a dim box with the perk menu's blue along its top, the chosen one lit.
  float box[2] = {x, y}, back[4] = {0, 0, 0, 0.55f}, blue[4] = {0.27f, 0.51f, 0.86f, 0.9f};
  grim_interface_ptr->grim_draw_rect_filled(box, w, h, back);
  grim_interface_ptr->grim_draw_rect_filled(box, w, 2, blue);
  snprintf(line, sizeof line, "Level %d", pick.level);
  viewer_text(x + 12, y + 8, line, 0.5f, 0.75f, 1, 1);
  for (int i = 0; i < pick.count; ++i) {
    bool lit = i == pick.chosen;
    viewer_text(x + 12, y + 26 + i * 15, perk_meta_table[pick.offered[i]].name, lit ? 1.0f : 0.62f, lit ? 1.0f : 0.64f,
                lit ? 1.0f : 0.68f, lit ? 1.0f : 0.75f);
  }
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
}

// The game over screen's panel, `offset` along from where the original puts it,
// and its banner's corner, where game_over_screen_update lays out from.
static void viewer_over_panel(float offset, float *corner) {
  ui_element_t &panel = ui_element_slot_30;
  unsigned char active = panel.active;
  float ox = panel.render_offset_x, oy = panel.render_offset_y;
  panel.active = 1;
  panel.render_offset_x = offset;
  panel.render_offset_y = 0;
  ui_element_render(&panel);
  panel.active = active;
  panel.render_offset_x = ox;
  panel.render_offset_y = oy;
  corner[0] = panel.pos.x + panel.vertices[0].position.x + 180 + offset + 34;
  corner[1] = panel.pos.y + panel.vertices[0].position.y + 40;
}
// The card under the banner, and the buttons under it: the original's layout
// (game_over_screen_update), the card the taller for the runner's name and date
// it shows outside the game over screen.
static constexpr float VIEWER_OVER_CARD_Y = 80, VIEWER_OVER_BUTTONS_Y = 250;

static void viewer_preparing() {
  float black[4] = {0, 0, 0, 1}, at[2] = {0, 0};
  grim_interface_ptr->grim_draw_rect_filled(at, viewer_w(), viewer_h(), black);
  float corner[2];
  viewer_over_panel(0, corner);
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  viewer_text(corner[0] + 38, corner[1] + 30, "Preparing the replay", 1, 1, 1, 1);
  float card[2] = {corner[0] + 30, corner[1] + VIEWER_OVER_CARD_Y};
  ui_text_input_render(card, &watch.run.record, 1.0f, watch.run.rank);
  // Segments for how much of the recording the pass has played, where the
  // screen's buttons go.
  int pips = 24;
  size_t size = watch.replay.recording.size();
  int lit = size ? (int)((int64_t)pips * watch.at / size) : 0;
  float x = corner[0] + 38, y = corner[1] + VIEWER_OVER_BUTTONS_Y + 8;
  for (int i = 0; i < pips; ++i)
    viewer_quad(i < lit ? viewer.pip_on : viewer.pip_off, x + i * VIEWER_PIP_W, y, VIEWER_PIP_W, VIEWER_PIP_H, 0, 0, 1, 1,
                i < lit ? 1.0f : 0.5f);
}

// The run's end as the original ends one: the game over screen (a quest's
// results or failure) with the run's card, whether it played as recorded where
// the original says a score is too low, and its buttons.
static void viewer_end(float dt) {
  viewer.end = fminf(1.0f, viewer.end + dt * 2.5f);
  float ease = 1 - (1 - viewer.end) * (1 - viewer.end), corner[2];
  viewer_over_panel(-(1 - ease) * 560, corner);
  // A run left before its end has no banner of the original's: it says so.
  const std::string &outcome = watch.replay.outcome;
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  if (outcome == "quest_completed" || outcome == "death")
    ui_draw_textured_quad((int)(corner[0] - 2), (int)corner[1], 256, 64,
                          outcome == "death" ? ui_text_reaper_texture : ui_text_well_done_texture);
  else
    viewer_text(corner[0] + 38, corner[1] + 30, "The run was left here.", 1, 1, 1, 1);
  const char *verdict = !watch.stopped.empty() ? watch.stopped.c_str()
                        : watch.played         ? "Played as recorded."
                                               : "This run played differently.";
  if (watch.played)
    viewer_text(corner[0] + 38, corner[1] + 62, verdict, 0.7f, 1, 0.7f, 0.9f);
  else
    viewer_text(corner[0] + 38, corner[1] + 62, verdict, 1, 0.5f, 0.5f, 0.9f);
  float card[2] = {corner[0] + 30, corner[1] + VIEWER_OVER_CARD_Y};
  ui_text_input_render(card, &watch.run.record, 1.0f, watch.run.rank);
  float at[2] = {corner[0] + 52, corner[1] + VIEWER_OVER_BUTTONS_Y};
  if (ui_button_update(at, &viewer.again))
    watch_ask(1), watch.paused = false;
  at[1] += 32;
  if (ui_button_update(at, &viewer.leave))
    watch.leave = true;
}

static void viewer_draw(float dt) {
  if (watch.phase == WATCH_PREPARING)
    return viewer_preparing();
  viewer_card(dt);
  if (watch.phase == WATCH_ENDED)
    viewer_end(dt);
  else
    viewer.end = 0;
  if (viewer.shown > 0)
    viewer_bar();
  if (viewer.shown > 0 || watch.phase == WATCH_ENDED)
    ui_cursor_render();
}
