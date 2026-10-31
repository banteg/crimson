#include "game.h"
#include <algorithm>
#include <cstring>

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
      auto place =
          std::find_if(scores.begin(), scores.end(), [&](const Score &s) { return run.seconds > s.seconds; });
      scores.insert(place, {name, run.seconds, run.kills});
      if (scores.size() > 100)
        scores.pop_back();
      screen = Screen::Scores;
      selected = 0;
    }
    return;
  }
  if (screen == Screen::Options && !in.escape) {
    if (in.previous || in.next)
      selected = 1 - selected;
    int row = in.click    ? (in.y >= 198 && in.y < 232   ? 0
                             : in.y >= 236 && in.y < 270 ? 1
                                                         : -1)
              : in.accept ? selected
                          : -1;
    if (row == 0)
      music_enabled = !music_enabled;
    if (row == 1) {
      screen = Screen::Menu;
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
  notice = nullptr;
  switch (row) {
  case 0:
    if (paused) {
      screen = Screen::Playing;
      paused = false;
    } else if (survival && !two_players) {
      start();
    } else {
      selected = two_players ? 1 : 2;
      notice =
          two_players ? "Select Players: one to play Survival." : "Select Game mode: survival, then Begin game.";
    }
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
} // namespace freeware
