// Game commands registered by crimson.exe at 0x420710. The release disables givegun and giveperk.
#include "game.h"
#include <algorithm>
#include <cmath>
#include <sstream>
namespace freeware {
static void push_line(std::vector<std::string> &lines, std::string text) {
  if (lines.size() >= 48)
    lines.erase(lines.begin());
  lines.push_back(std::move(text));
}
void Game::console_input(const Input &in) {
  if (in.console || in.escape) {
    console_open = false;
    return;
  }
  if (in.previous && !history.empty()) {
    history_index = std::max(0, history_index - 1);
    command = history[history_index];
  } else if (in.next && history_index < int(history.size())) {
    ++history_index;
    command = history_index == int(history.size()) ? "" : history[history_index];
  }
  if (in.backspace && !command.empty())
    command.pop_back();
  for (char c : in.text)
    if (c >= 32 && c < 127 && command.size() < 255)
      command += c;
  if (!in.accept || command.empty())
    return;
  if (history.empty() || command != history.back())
    push_line(history, command);
  history_index = int(history.size());
  push_line(console_lines, "> " + command);
  std::istringstream tokens(command);
  command.clear();
  std::string op;
  tokens >> op;
  if (op == "cmdlist" || op == "help") {
    push_line(console_lines, "clear echo quit telltimesurvived spawncreature");
    push_line(console_lines, "setcreaturehealth setcreaturecolor playsample mergehighs givegun giveperk");
  } else if (op == "clear")
    console_lines.clear();
  else if (op == "echo") {
    std::string rest;
    std::getline(tokens >> std::ws, rest);
    push_line(console_lines, rest);
  } else if (op == "quit")
    quit = true;
  else if (op == "telltimesurvived")
    push_line(console_lines, "Survived: " + std::to_string(int(run.seconds)) + " seconds.");
  else if (op == "givegun" || op == "giveperk")
    push_line(console_lines, "Command is disabled.");
  else if (op == "setcreaturehealth") {
    int hp;
    if (tokens >> hp) {
      spawn_health = hp;
      push_line(console_lines, "Next spawned creature will have " + std::to_string(hp) + " health.");
    } else
      push_line(console_lines, "setcreaturehealth <health>");
  } else if (op == "setcreaturecolor") {
    float r, g, b, a;
    if (!(tokens >> r >> g >> b >> a))
      push_line(console_lines, "setcreaturecolor <r> <g> <b> <a>");
    else if (r < 0 || r > 1 || g < 0 || g > 1 || b < 0 || b > 1 || a < 0 || a > 1)
      push_line(console_lines, "rgba color values must be in range 0.0 to 1.0.");
    else
      spawn_color = {r, g, b, a};
  } else if (op == "spawncreature") {
    int x, y;
    if (!(tokens >> x >> y)) {
      push_line(console_lines, "spawncreature <x> <y>");
      return;
    }
    if (screen != Screen::Playing) {
      push_line(console_lines, "Begin a game first.");
      return;
    }
    vec2f_t pos{float(x), float(y)};
    int id = creature_spawn(&pos, &spawn_color, 1);
    creature_pool[id].health = float(spawn_health);
    run.cheated = true;
    push_line(console_lines, "Creature spawned to (" + std::to_string(x) + "," + std::to_string(y) + ")");
    push_line(console_lines, "No highscore entry allowed for this game.");
  } else if (op == "mergehighs") {
    std::string filename;
    tokens >> filename;
    push_line(console_lines, merge_scores(filename) ? "Highscores merged." : "Could not merge score file.");
  } else if (op == "playsample") {
    int n;
    if (tokens >> n && n >= 0 && n < 32)
      play_original_sample(n);
    else
      push_line(console_lines, "playsample <sample>");
  } else
    push_line(console_lines, "Unknown command: " + op);
}
} // namespace freeware
