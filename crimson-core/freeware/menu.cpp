#include "game.h"
#include <algorithm>
#include <cstring>

namespace freeware {
// 0x4211d5 initializes these eight rows, and the frame callback at 0x418190 owns their input.
const char *const main_labels[] = {"Begin game.", "Players: one",  "Game mode: career", "Highscores.",
                                   "Credits.",    "Game options.", "Online options.",   "End."};
const char *menu_label(const Game &g, int row) {
  if (row == 0 && g.paused)
    return "Resume game.";
  if (row == 2 && g.survival)
    return "Game mode: survival";
  if (row == 7 && g.paused)
    return "End current game.";
  return main_labels[row];
}
int menu_hover(const Game &g) {
  for (int i = 0; i < 8; ++i) {
    const float x = width / 2 - 100, y = 200 + i * 32;
    if (g.cursor_x >= x && g.cursor_y >= y && g.cursor_y < y + 30 &&
        g.cursor_x < x + std::strlen(menu_label(g, i)) * 16)
      return i;
  }
  return -1;
}

void Game::update(float dt, const Input &in) {
  menu_clock += dt;
  cursor_x = in.x;
  cursor_y = in.y;
  if (screen == Screen::Playing) {
    if (in.escape) {
      paused = true;
      selected = 0;
      screen = Screen::Menu;
    } else
      tick(dt, in);
    return;
  }
  if (screen == Screen::Death) {
    if (in.backspace && !name.empty())
      name.pop_back();
    for (char c : in.text)
      if (c >= 32 && c < 127 && name.size() < 31)
        name += c;
    if (in.accept || in.escape) {
      best_seconds = std::max(best_seconds, run.seconds);
      best_kills = std::max(best_kills, run.kills);
      screen = Screen::Scores;
      selected = 0;
    }
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
  switch (row) {
  case 0:
    if (paused) {
      screen = Screen::Playing;
      paused = false;
    } else if (survival)
      start();
    else
      selected = 2;
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
} // namespace freeware
