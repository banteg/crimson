#include "game.h"
#include <algorithm>
#include <cstring>
#include <fstream>

namespace freeware {
// 0x4211d5 initializes these eight rows, and the frame callback at 0x418190 owns their input.
const char *const main_labels[] = {"Begin game.", "Players: one",  "Game mode: career", "Highscores.",
                                   "Credits.",    "Game options.", "Online options.",   "End."};
static const char *menu_label(const Game &g, int row) {
  if (row == 0 && g.paused)
    return "Resume game.";
  if (row == 1 && g.two_players)
    return "Players: two";
  if (row == 2 && g.survival)
    return "Game mode: survival";
  if (row == 7 && g.paused)
    return "End current game.";
  return main_labels[row];
}
MenuRow menu_row(const Game &g, int i) { return {menu_label(g, i), width / 2 - 100.f, 200.f + i * 32}; }
int menu_hover(const Game &g) {
  for (int i = 0; i < 8; ++i) {
    const auto row = menu_row(g, i);
    if (g.cursor_x > row.x && g.cursor_y > row.y && g.cursor_y < row.y + 30 &&
        g.cursor_x < row.x + std::strlen(row.label) * 16)
      return i;
  }
  return -1;
}

void Game::update(float dt, const Input &in) {
  decals.clear();
  menu_clock += dt;
  mouse_dx = in.x - cursor_x;
  mouse_dy = in.y - cursor_y;
  if (dt > 0)
    fps = 1 / dt;
  cursor_x = in.x;
  cursor_y = in.y;
  if (screen == Screen::Menu && in.ctrl && in.key) {
    constexpr int tips[] = {23, 12, 19, 22}; // SDL scancodes for Ctrl+TIPS at 0x4197c4.
    if (in.key == tips[tips_sequence] && ++tips_sequence == 4) {
      tips_sequence = 0;
      secret_hints = true;
      play_sound(Sound::Level);
    }
  }
  if (screen == Screen::Playing) {
    if (in.escape) {
      paused = true;
      selected = 0;
      screen = Screen::Menu;
    } else if (run.pending && !survival &&
               (in.level_up || (in.click && in.x > width - 190 && in.y > height - 58))) {
      open_perks();
    } else
      tick(dt, in);
    return;
  }
  if (screen == Screen::Dying) {
    finish_death(dt);
    return;
  }
  if (screen == Screen::Death) {
    death_clock += dt;
    if (in.backspace && !name.empty())
      name.pop_back();
    for (char c : in.text)
      if (c >= 32 && c < 127 && name.size() < 31)
        name += c;
    if (in.accept || in.escape) {
      record_score();
      screen = Screen::Scores;
      selected = 0;
    }
    return;
  }
  if (screen == Screen::Message) {
    if (in.level_up || in.click || in.accept)
      screen = Screen::Playing;
    return;
  }
  if (screen == Screen::Perks) {
    if (in.escape) {
      screen = Screen::Playing;
      return;
    }
    int count = int(run.choices.size());
    if (in.previous)
      selected = std::max(0, selected - 1);
    if (in.next)
      selected = std::min(count - 1, selected + 1);
    int hover = (in.x >= 145 && in.x <= 500 && in.y >= 94) ? int((in.y - 94) / 27) : -1;
    if (hover >= 0 && hover < count && (mouse_dx || mouse_dy || in.click))
      selected = hover;
    if (in.accept || (in.click && hover >= 0 && hover < count))
      choose_perk(selected);
    return;
  }
  if (screen == Screen::Options && rebind >= 0) {
    if (in.escape)
      rebind = -1;
    else if (in.key) {
      keys[rebind / 5][rebind % 5] = in.key;
      if (++rebind == 10)
        rebind = -1;
    }
    if (rebind < 0)
      save_options();
    return;
  }
  if (screen == Screen::Options && !in.escape) {
    constexpr int count = 9;
    if (in.previous)
      selected = (selected + count - 1) % count;
    if (in.next)
      selected = (selected + 1) % count;
    int hover = (in.x >= 170 && in.x < 650 && in.y >= 170) ? int((in.y - 170) / 30) : -1;
    if (hover >= 0 && hover < count && (mouse_dx || mouse_dy || in.click))
      selected = hover;
    if (!in.accept && !(in.click && hover >= 0 && hover < count))
      return;
    switch (selected) {
    case 0:
      configuring = 1 - configuring;
      break;
    case 1:
      movement[configuring] = (movement[configuring] + 1) % 3;
      break;
    case 2:
      aiming[configuring] = (aiming[configuring] + 1) % 4;
      break;
    case 3:
      rebind = 0;
      break;
    case 4:
      music_enabled = !music_enabled;
      break;
    case 5:
      smooth = !smooth;
      break;
    case 6:
      show_fps = !show_fps;
      break;
    case 7:
      effects = !effects;
      break;
    case 8:
      screen = Screen::Menu;
      selected = 0;
      break;
    }
    save_options();
    return;
  }
  if (screen != Screen::Menu) {
    if (in.accept || in.click || in.escape) {
      screen = Screen::Menu;
      selected = 0;
    }
    return;
  }
  if (in.previous)
    selected = std::max(0, selected - 1);
  if (in.next)
    selected = std::min(7, selected + 1);
  int row = in.click ? menu_hover(*this) : in.accept ? selected : -1;
  if (in.escape && paused)
    row = 0;
  if (row < 0)
    return;
  selected = row;
  notice = nullptr;
  switch (row) {
  case 0:
    if (paused) {
      screen = Screen::Playing;
      paused = false;
    } else
      start();
    break;
  case 1:
    if (!paused)
      two_players = !two_players;
    break;
  case 2:
    if (!paused)
      survival = !survival;
    break;
  case 3:
    screen = Screen::Scores;
    break;
  case 4:
    screen = Screen::Credits;
    break;
  case 5:
    selected = 0;
    screen = Screen::Options;
    break;
  case 6:
    screen = Screen::Online;
    break;
  case 7:
    if (paused) {
      paused = false;
      selected = 0;
    } else
      quit = true;
    break;
  }
}
std::string Game::option(int row) const {
  static const char *moves[] = {"Control method: kb static", "Control method: kb relative",
                                "Control method: joystick static"};
  static const char *aims[] = {"Aiming device: mouse static", "Aiming device: mouse relative",
                               "Aiming device: keyboard", "Aiming device: joystick hat"};
  switch (row) {
  case 0:
    return configuring ? "Configure for: Player 2" : "Configure for: Player 1";
  case 1:
    return moves[movement[configuring]];
  case 2:
    return aims[aiming[configuring]];
  case 3:
    return "Redefine controls.";
  case 4:
    return music_enabled ? "Music: on" : "Music: off";
  case 5:
    return smooth ? "Background filter: smooth" : "Background filter: sharp";
  case 6:
    return show_fps ? "Show FPS: on" : "Show FPS: off";
  case 7:
    return effects ? "Glow, Smoke & Shadow FX: on" : "Glow, Smoke & Shadow FX: off";
  default:
    return "Done.";
  }
}
void Game::save_options() const {
  if (save_dir.empty())
    return;
  std::ofstream f(save_dir + "freeware-options.cfg");
  f << music_enabled << ' ' << smooth << ' ' << show_fps << ' ' << effects << '\n';
  for (int i = 0; i < 2; ++i) {
    f << movement[i] << ' ' << aiming[i];
    for (int k : keys[i])
      f << ' ' << k;
    f << '\n';
  }
}
void Game::load_options() {
  std::ifstream f(save_dir + "freeware-options.cfg");
  int opts[4], controls[2][7];
  for (auto &v : opts)
    if (!(f >> v) || v < 0 || v > 1)
      return;
  for (auto &row : controls)
    for (auto &v : row)
      if (!(f >> v) || v < 0 || v >= 512)
        return;
  for (auto &row : controls)
    if (row[0] >= 3 || row[1] >= 4)
      return;
  music_enabled = opts[0];
  smooth = opts[1];
  show_fps = opts[2];
  effects = opts[3];
  for (int i = 0; i < 2; ++i) {
    movement[i] = controls[i][0];
    aiming[i] = controls[i][1];
    std::copy_n(controls[i] + 2, 5, keys[i]);
  }
}
} // namespace freeware
