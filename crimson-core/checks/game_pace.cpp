// Live play's pace (host/live_pace.h) through displays as Grim's clock reads
// them: in whole milliseconds, up to 0.9 ms after each frame shows. The pace
// settles on a display from a cold start (a stall, or a first pass 2 ms after
// the last), and then a run's bank starts at zero, on a tick's edge: at 60 Hz
// every frame runs one tick, two on a frame the display missed and none on a
// stray pass 2 ms after one; at 59 or 61 Hz one frame a second runs two or
// none, never two close together; at 30 Hz two a frame; at 120 Hz one every
// other frame, at 240 Hz every fourth, at 125 and 144 Hz every two or three. A
// display the window moves to (120 to 60 Hz, 240 to 144 Hz) runs as evenly
// once the pace has followed it. A replay played fast moves as evenly, its
// display's slips a tick of play each, and its speed changing either way
// leaves no frame empty or crowded. Every display's frames run the ticks of
// the clock's time, within a couple, and no pass banks less than nothing.
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

// A display's frames: when each shows, in milliseconds after the first.
struct Frames {
  std::vector<double> shown;
  void add(double hz, int frames, int missed = -1) {
    double at = shown.empty() ? 0 : shown.back();
    for (int k = 0; k < frames; ++k)
      shown.push_back(at += (k == missed ? 2 : 1) * 1000 / hz);
  }
};

// The ticks of each frame from frame `from` on, where a run starts its bank
// at zero; the first pass `first` ms after the last (a stall's otherwise), a
// stray pass 2 ms after frame `stray`, and the replay's speed by frame.
static std::vector<int> play(const Frames &f, int from, unsigned first = 1000, int stray = -1,
                             float (*speed)(int) = nullptr) {
  Bank bank;
  std::vector<int> ran;
  for (int k = 0; k < (int)f.shown.size(); ++k) {
    unsigned ms = (unsigned)floor(1000 + f.shown[k] + fmod(k * 0.618, 1) * 0.9);
    if (k == 0)
      bank.last = ms - first;
    if (k == from)
      bank.banked = 0;
    float s = speed ? speed(k) : 1;
    int due = bank.pass(ms, s);
    if (k >= from)
      ran.push_back(due);
    if (k == stray) {
      due = bank.pass(ms + 2, s);
      if (k >= from)
        ran.push_back(due);
    }
  }
  return ran;
}

static std::string digits(const std::vector<int> &ran) {
  std::string out;
  for (int due : ran)
    out += std::to_string(due);
  return out;
}

static int total(const std::vector<int> &ran) {
  int sum = 0;
  for (int due : ran)
    sum += due;
  return sum;
}

// The frames' ticks match `pattern` and add up to about the clock's `ticks`.
static void expect(const char *what, const std::vector<int> &ran, const char *pattern, double ticks) {
  std::string got = digits(ran);
  if (!std::regex_match(got, std::regex(pattern)) || fabs(total(ran) - ticks) > 2) {
    fprintf(stderr, "%s ran %s (%d ticks, not about %.1f)\n", what, got.c_str(), total(ran), ticks);
    exit(1);
  }
}

// `frames` frames at `hz` after 120 the pace settles in.
static Frames display(double hz, int frames, int missed = -1) {
  Frames f;
  f.add(hz, 120 + frames, missed < 0 ? -1 : 120 + missed);
  return f;
}

// The clock's ticks over `frames` frames at `hz`, `missed` of them skipped.
static double owed(double hz, int frames, int missed = 0) { return (frames + missed) * 60 / hz; }

int main() {
  expect("a 60 Hz display", play(display(60, 600), 120), "1+", owed(60, 600));
  expect("a 60 Hz display after a 2 ms first pass", play(display(60, 600), 120, 2), "1+", owed(60, 600));
  expect("a 60 Hz display missing a frame", play(display(60, 120, 40), 120), "1{40}21+", owed(60, 120, 1));
  expect("a 60 Hz display with a stray pass", play(display(60, 120), 120, 1000, 160), "1{41}01+", owed(60, 120));
  expect("a 59 Hz display", play(display(59, 600), 120), "(?!.*(0|2.{0,49}2))[12]+", owed(59, 600));
  expect("a 61 Hz display", play(display(61, 600), 120), "(?!.*(2|0.{0,49}0))[01]+", owed(61, 600));
  expect("a 30 Hz display", play(display(30, 300), 120), "2+", owed(30, 300));
  expect("a 120 Hz display", play(display(120, 600), 120), "(01)+|(10)+", owed(120, 600));
  expect("a 240 Hz display", play(display(240, 600), 120), "(0001)+|(0010)+|(0100)+|(1000)+", owed(240, 600));
  expect("a 125 Hz display", play(display(125, 600), 120), "(?!.*(11|000))[01]+", owed(125, 600));
  expect("a 144 Hz display", play(display(144, 600), 120), "(?!.*(11|000))[01]+", owed(144, 600));
  // A burst of 2.2 ms passes (an unthrottled moment), then the 60 Hz display.
  Frames burst;
  burst.add(450, 60);
  burst.add(60, 720);
  expect("a 60 Hz display after a burst of 2.2 ms passes", play(burst, 180), "1+", owed(60, 600));
  // A window moving to another display, once the pace has followed it.
  Frames moved;
  moved.add(120, 240);
  moved.add(60, 720);
  expect("a 120 Hz display's window on a 60 Hz one", play(moved, 360), "1+", owed(60, 600));
  moved = {};
  moved.add(240, 480);
  moved.add(144, 840);
  expect("a 240 Hz display's window on a 144 Hz one", play(moved, 600), "(?!.*(11|000))[01]+", owed(144, 720));
  // A replay at 2x: a 59 or 61 Hz display's slips are a tick; at 32x a frame
  // runs about 32, the clock's jitter of a few ticks of play aside.
  struct Fast {
    double hz;
    float speed;
    int least, most;
  } fast[] = {{59, 2, 2, 3}, {61, 2, 1, 2}, {59, 32, 28, 36}, {61, 32, 28, 36}, {60, 32, 28, 36}};
  for (const Fast &c : fast) {
    static float speed;
    speed = c.speed;
    std::vector<int> ran = play(display(c.hz, 600), 120, 1000, -1, [](int) { return speed; });
    auto [least, most] = std::minmax_element(ran.begin(), ran.end());
    if (*least < c.least || *most > c.most || fabs(total(ran) - owed(c.hz, 600) * c.speed) > 2) {
      fprintf(stderr, "a %g Hz display at %gx ran from %d to %d ticks a frame, %d in all\n", c.hz, c.speed, *least,
              *most, total(ran));
      return 1;
    }
  }
  // The speed changing between passes: 32x after 1x on a 61 Hz display,
  // whatever the clock's time held at 1x when it changes, and 1x after 32x.
  for (static int at = 240; at < 300; ++at) {
    std::vector<int> ran = play(display(61, 300), 120, 1000, -1, [](int k) { return k < at ? 1.0f : 32.0f; });
    auto [least, most] = std::minmax_element(ran.begin() + (at - 120), ran.end());
    if (*least < 28 || *most > 36) {
      fprintf(stderr, "a 61 Hz display at 32x from 1x at frame %d ran from %d to %d ticks a frame\n", at, *least,
              *most);
      return 1;
    }
  }
  expect("a 60 Hz display back at 1x from 32x",
         play(display(60, 360), 240, 1000, -1, [](int k) { return k < 240 ? 32.0f : 1.0f; }), "1+", owed(60, 240));
  // The clock's time owed from the lattice when a pass comes early off it.
  LivePace pace;
  pace.period = 1 / 75.0f;
  pace.held = -0.010f;
  if (pace(0.002f) != 0 || fabsf(pace.held + 0.008f) > 1e-6f) {
    fprintf(stderr, "an early pass off the lattice, owing the clock, left %g held\n", pace.held);
    return 1;
  }
  puts("live pace: 30 to 240 Hz, a missed frame, a stray pass, a short first pass, a moved window, 2x and 32x and "
       "back, an early pass owing the clock");
}
