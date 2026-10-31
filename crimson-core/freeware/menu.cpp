#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>

namespace freeware {
// 0x4211d5 initializes these eight rows, and the frame callback at 0x418190 owns their input.
const char *const main_labels[] = {"Begin game.", "Players: one",  "Game mode: career", "Highscores.",
                                   "Credits.",    "Game options.", "Online options.",   "End."};
const char *const online_labels[5] = {"Visit Crimsonland website", "Check for updates", "View online highscores",
                                      "", "back to main menu"};
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

std::string Game::option(int row) const {
  static const char *moves[] = {"Control method: kb static", "Control method: kb relative",
                                "Control method: joystick static"};
  static const char *aims[] = {"Aiming device: mouse static", "Aiming device: mouse relative",
                               "Aiming device: keyboard", "Aiming device: joystickk 'hat'"};
  switch (row) {
  case 0:
    return configuring ? "Configure for: Player 2" : "Configure for: Player 1";
  case 1:
    return moves[movement[configuring]];
  case 2:
    return aims[aiming[configuring]];
  case 3:
    return music_enabled ? "Music: on" : "Music: off";
  case 4:
    return smooth ? "Background filter: smooth" : "Background filter: sharp";
  case 5:
    return show_fps ? "Show FPS: on" : "Show FPS: off";
  case 6:
    return effects ? "Glow, Smoke & Shadow FX: on" : "Glow, Smoke & Shadow FX: off";
  case 7:
    return shell_marks ? "Shell marks: on" : "Shell marks: off";
  case 8:
    return direction_arrow ? "Direction Arrow: on" : "Direction Arrow: off";
  case 9:
    return "Redefine controls";
  case 10:
    return "Calibrate joystick";
  default:
    return "Done";
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
  f << shell_marks << ' ' << direction_arrow << '\n';
  for (int i = 0; i < 2; ++i)
    f << pad_center[i].x << ' ' << pad_center[i].y << ' ' << pad_threshold[i] << '\n';
  for (auto pov : pad_right_pov) {
    double angle = pov / 5729.5779513;
    f << std::sin(angle) << ' ' << -std::cos(angle) << '\n';
  }
  for (int i = 0; i < 2; ++i)
    f << pad_left_pov[i] << ' ' << pad_right_pov[i] << '\n';
}
void Game::load_options() {
  if (save_dir.empty())
    return;
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
  int shells_on, arrow_on;
  if (f >> shells_on >> arrow_on) {
    shell_marks = shells_on != 0;
    direction_arrow = arrow_on != 0;
  }
  for (int i = 0; i < 2; ++i) {
    float x, y, t;
    if (f >> x >> y >> t && x >= -1 && x <= 1 && y >= -1 && y <= 1 && t >= 0 && t <= 65.535f) {
      pad_center[i] = {x, y};
      pad_threshold[i] = t;
    }
  }
  for (int i = 0; i < 2; ++i) {
    float x, y;
    if (f >> x >> y && std::abs(std::hypot(x, y) - 1) < .01f) {
      pad_right_pov[i] = int(std::atan2(x, -y) * 5729.5779513 + 36000.5) % 36000;
      pad_left_pov[i] = (pad_right_pov[i] + 18000) % 36000;
    }
  }
  for (int i = 0; i < 2; ++i) {
    int left, right;
    if (f >> left >> right && left >= -1 && left < 36000 && right >= -1 && right < 36000) {
      pad_left_pov[i] = left;
      pad_right_pov[i] = right;
    }
  }
}
} // namespace freeware
