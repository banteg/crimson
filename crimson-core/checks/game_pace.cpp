// Live play's pace (host/live_pace.h) through displays as Grim's clock reads
// them: in whole milliseconds, up to 0.9 ms after each frame shows. Each run
// banks as the session does from a bank at zero, on a tick's edge, as a run's
// starts, after a stall: at 60 Hz every frame runs one tick, two on a frame the
// display missed; at 59 or 61 Hz one frame a second runs two or none, never a
// burst; at 30 Hz two a frame; at 120 Hz one every other frame, at 240 Hz every
// fourth, at 144 Hz every two or three. A replay played fast moves as evenly,
// its display's slips a tick of play each. Every display's frames run the
// ticks of the clock's time, within a couple. A first pass 2 ms after the last
// leaves the pace to settle on the display as a stall's does. A replay back
// at 1x from 32x runs a tick a frame at once. A pass that comes early banks
// nothing, even at 32x.
//
//   clang++ -std=c++17 -O2 crimson-core/checks/game_pace.cpp -o game_pace && ./game_pace
#include "../host/live_pace.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <regex>
#include <string>
#include <vector>

struct Bank {
  LivePace pace;
  float banked = 0;
  unsigned last = 0;
  // The ticks a pass at `ms` on Grim's clock runs, at a replay's `speed`.
  int pass(unsigned ms, float speed = 1) {
    float paced = pace(fminf((ms - last) * 0.001f, 0.1f), speed);
    last = ms;
    assert(paced >= 0);
    banked += paced;
    int due = (int)(banked * 60.0f + 1e-4f);
    banked -= due / 60.0f;
    return due;
  }
};

// Each frame's ticks once 120 frames have passed (the pace settles on the
// display in about 60, from a tick's); `missed` is a frame the display skips,
// from there, and `first` the milliseconds the first pass comes after the last
// (a stall's 1000 otherwise). Each run also holds to the clock's time.
static std::vector<int> display(double hz, int frames, int missed = -1, float speed = 1, unsigned first = 1000) {
  Bank bank;
  std::vector<int> ran;
  unsigned from = 0;
  for (int k = -120, shown = 0; k < frames; ++k) {
    shown += k == missed ? 2 : 1;
    double jitter = fmod(k * 0.618 + 120, 1) * 0.9;
    unsigned ms = (unsigned)floor(1000 + shown * 1000 / hz + jitter);
    if (k == -120)
      bank.last = ms - first;
    if (k == 0)
      from = bank.last;
    int due = bank.pass(ms, speed);
    if (k >= 0)
      ran.push_back(due);
  }
  int ticks = 0;
  for (int due : ran)
    ticks += due;
  double owed = (bank.last - from) * 0.06 * speed;
  if (fabs(ticks - owed) > 2) {
    fprintf(stderr, "a %g Hz display at %gx ran %d ticks in %u ms, not about %.1f\n", hz, speed, ticks,
            bank.last - from, owed);
    exit(1);
  }
  return ran;
}

static std::string digits(const std::vector<int> &ran) {
  std::string out;
  for (int due : ran)
    out += std::to_string(due);
  return out;
}

int main() {
  struct Case {
    double hz;
    int frames, missed;
    const char *expected;
    unsigned first = 1000;
  } cases[] = {
      {60, 600, -1, "1+"},
      {60, 600, -1, "1+", 2},
      {60, 120, 40, "1{40}21+"},
      {59, 600, -1, "(?!.*(0|2.{0,49}2))[12]+"},
      {61, 600, -1, "(?!.*(2|0.{0,49}0))[01]+"},
      {30, 300, -1, "2+"},
      {120, 600, -1, "(01)+|(10)+"},
      {240, 600, -1, "(0001)+|(0010)+|(0100)+|(1000)+"},
      {144, 600, -1, "(?!.*(11|000))[01]+"},
      {125, 600, -1, "(?!.*(11|000))[01]+"},
  };
  for (const Case &c : cases) {
    std::string ran = digits(display(c.hz, c.frames, c.missed, 1, c.first));
    if (!std::regex_match(ran, std::regex(c.expected))) {
      fprintf(stderr, "a %g Hz display%s ran %s\n", c.hz, c.missed >= 0 ? " missing a frame" : "", ran.c_str());
      return 1;
    }
  }
  // At 2x the 59 and 61 Hz displays' slips are a tick a frame, and at 32x a
  // frame runs close to 32, the clock's jitter of a few ticks of play aside:
  // never a frame of none, or of two frames' worth.
  struct Fast {
    double hz;
    float speed;
    int least, most;
  } fast[] = {{59, 2, 2, 3}, {61, 2, 1, 2}, {59, 32, 28, 36}, {61, 32, 28, 36}, {60, 32, 28, 36}};
  for (const Fast &f : fast) {
    std::vector<int> ran = display(f.hz, 600, -1, f.speed);
    auto [least, most] = std::minmax_element(ran.begin(), ran.end());
    if (*least < f.least || *most > f.most) {
      fprintf(stderr, "a %g Hz display at %gx ran from %d to %d ticks a frame\n", f.hz, f.speed, *least, *most);
      return 1;
    }
  }
  // A replay's speed changing between passes: from the pass after a 32x one,
  // a 60 Hz display's frames each run the one tick of 1x, none empty.
  {
    Bank bank;
    std::string ran;
    for (int k = 0; k < 360; ++k) {
      int due = bank.pass((unsigned)floor(1000 + (k + 1) * 1000 / 60.0 + fmod(k * 0.618, 1) * 0.9), k < 240 ? 32 : 1);
      if (k >= 240)
        ran += std::to_string(due);
    }
    if (!std::regex_match(ran, std::regex("1+"))) {
      fprintf(stderr, "a 60 Hz display back at 1x from 32x ran %s\n", ran.c_str());
      return 1;
    }
  }
  // 16 ms passes run up a debt to the ticks they bank; a pass 2 ms after one
  // banks nothing (the bank asserts no pass banks less), and a replay at 32x
  // runs no more ticks than the clock's time holds.
  Bank bank;
  unsigned ms = 1000;
  bank.last = ms;
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
  puts("live pace: 30, 59, 60, 61, 120, 125, 144 and 240 Hz, a missed frame, a short first pass, 2x and 32x and back, early passes");
}
