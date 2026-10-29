// Live play's pace (host/live_pace.h) through displays as Grim's clock reads
// them: in whole milliseconds, up to 0.9 ms after each frame shows. Each run
// starts as a run's bank does, at zero, on a tick's edge, and banks as the
// session does: at 60 Hz every frame runs one tick, two on a frame the display
// missed; at 59 or 61 Hz one frame a second runs two or none, never a burst; at
// 30 Hz two a frame; at 120 Hz one every other frame, at 240 Hz every fourth,
// at 144 Hz every two or three. A pass that comes early banks nothing, even at
// a replay's 32x, and play keeps the clock's time.
//
//   clang++ -std=c++17 -O2 crimson-core/checks/game_pace.cpp -o game_pace && ./game_pace
#include "../host/live_pace.h"
#include <cassert>
#include <cstdio>
#include <regex>
#include <string>

// The pace has seen the display's frames before the run (game_live_frame
// paces every pass, the menus' too); the run's bank starts at zero.
struct Bank {
  LivePace pace{};
  float banked = 0;
  unsigned last;
  // The ticks a pass at `ms` on Grim's clock runs, at a replay's `speed`.
  int pass(unsigned ms, float speed = 1) {
    float paced = pace(fminf((ms - last) * 0.001f, 0.1f));
    last = ms;
    assert(paced >= 0);
    banked += paced * speed;
    int due = (int)(banked * 60.0f + 1e-4f);
    banked -= due / 60.0f;
    return due;
  }
};

// Each frame's ticks once a second of frames has passed; `missed` is a frame
// the display skips, from there.
static std::string display(double hz, int frames, int missed = -1) {
  Bank bank{{}, 0, 1000};
  std::string ran;
  for (int k = -60, shown = 0; k < frames; ++k) {
    shown += k == missed ? 2 : 1;
    double jitter = fmod(k * 0.618 + 60, 1) * 0.9;
    int due = bank.pass((unsigned)floor(1000 + shown * 1000 / hz + jitter));
    if (k >= 0)
      ran += std::to_string(due);
  }
  return ran;
}

int main() {
  struct Case {
    double hz;
    int frames, missed;
    const char *expected;
  } cases[] = {
      {60, 600, -1, "1+"},
      {60, 120, 40, "1{40}21+"},
      {59, 600, -1, "(?!.*(0|2.{0,49}2))[12]+"},
      {61, 600, -1, "(?!.*(2|0.{0,49}0))[01]+"},
      {30, 300, -1, "2+"},
      {120, 600, -1, "(01)+|(10)+"},
      {240, 600, -1, "(0001)+|(0010)+|(0100)+|(1000)+"},
      {144, 600, -1, "(?!.*(11|000))[01]+"},
  };
  for (const Case &c : cases) {
    std::string ran = display(c.hz, c.frames, c.missed);
    if (!std::regex_match(ran, std::regex(c.expected))) {
      fprintf(stderr, "a %g Hz display%s ran %s\n", c.hz, c.missed >= 0 ? " missing a frame" : "", ran.c_str());
      return 1;
    }
  }
  // 16 ms passes run up a debt to the ticks they bank; a pass 2 ms after one
  // banks nothing (the bank asserts no pass banks less), and a replay at 32x
  // runs no more ticks than the clock's time holds.
  unsigned ms = 1000;
  Bank bank{{}, 0, ms};
  int ticks = 0;
  for (int k = 0; k < 600; ++k) {
    ms += k % 10 == 9 ? 2 : 16;
    ticks += bank.pass(ms, 32);
  }
  double owed = (ms - 1000) * 0.06 * 32;
  if (fabs(ticks - owed) > 32) {
    fprintf(stderr, "a 32x replay ran %d ticks in %u ms, not about %.0f\n", ticks, ms - 1000, owed);
    return 1;
  }
  puts("live pace: 30, 59, 60, 61, 120, 144 and 240 Hz, a missed frame, early passes, 32x");
}
