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
// Co-op's catch-up (CatchUp) between two machines, each pacing its run and
// learning the other's head from packets a one-way trip late: with the
// partner's display at 60 or 144 Hz and 40 to 120 ms each way, a 60 Hz
// display's frames run a tick each, a 59.94 Hz partner's slips aside, never
// two catch-up frames within a second, and the runs stay within two ticks;
// started eight ticks apart, they come together in 5 to 15 s, a tick at a
// time, the run ahead slowing and the one behind speeding up. The catch-up
// itself comes in whole ticks of the lead's sign, at its rate.
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
  void add(double hz, int frames, std::vector<int> missed = {}) {
    double at = shown.empty() ? 0 : shown.back();
    for (int k = 0; k < frames; ++k)
      shown.push_back(at += (std::count(missed.begin(), missed.end(), k) ? 2 : 1) * 1000 / hz);
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

// A co-op machine: its display's frames, its pace and bank, its catch-up, and
// the heads its packets carry.
struct Machine {
  double hz, phase, spread;
  Bank bank;
  CatchUp catch_up;
  int next = 0, k = 0;
  std::vector<std::pair<double, int>> heads; // when each frame showed, and the run's head after it
  std::vector<int> ran;
  double at(int frame) const { return phase + frame * 1000 / hz; }
  // A pass at the frame's time on Grim's clock, as coop_frame and coop_render
  // take it: the ticks its paced time banks run, then the catch-up for the
  // next pass, by how far `ahead` the partner's run seems of this one's after
  // them. The pace has seen the display's frames before the run starts.
  template <typename Ahead> void pass(Ahead ahead) {
    unsigned ms = (unsigned)floor(1000 + at(k) + fmod(k * spread, 1) * 0.9);
    if (k == 0)
      bank.last = ms - (unsigned)lround(1000 / hz);
    float paced = bank.pace(fminf((ms - bank.last) * 0.001f, 0.1f));
    bank.last = ms;
    bank.banked += paced;
    int due = std::max((int)(bank.banked * 60.0f + 1e-4f), 0);
    bank.banked -= due / 60.0f;
    next += due;
    ran.push_back(due);
    heads.push_back({at(k), next});
    bank.banked += catch_up(paced, ahead(*this));
    ++k;
  }
};

// Co-op's two machines: the first at 60 Hz, `start` ticks ahead, the partner at
// `partner` Hz, `latency` ms one way; a machine's head estimate is the newest
// its partner sent a trip ago, plus the trip in ticks (coop_ahead).
struct Coop {
  double partner, latency;
  int start;
  double most; // catch-up frames a minute the first may run
};
struct Pair {
  Machine a, b;
  double latency;
  std::vector<int> gaps; // the first's head less the partner's, after each of its frames
  explicit Pair(const Coop &c) : a{60, 0, 0.618}, b{c.partner, 3.7, 0.414}, latency(c.latency) { a.next = c.start; }
  static double ahead(const Machine &me, const Machine &other, double at, double latency) {
    int head = -1;
    for (auto &[shown, next] : other.heads)
      if (shown <= at - latency)
        head = next;
    return head < 0 ? 0 : head - me.next + latency * 60 / 1000;
  }
  void play(double seconds) {
    while (a.at(a.k) < seconds * 1000 || b.at(b.k) < seconds * 1000) {
      bool first = a.at(a.k) <= b.at(b.k);
      Machine &me = first ? a : b, &other = first ? b : a;
      double at = me.at(me.k), trip = latency;
      me.pass([&](const Machine &self) { return ahead(self, other, at, trip); });
      if (first)
        gaps.push_back(a.next - b.next);
    }
  }
};
static const Coop coop[] = {
    {60, 60, 0, 1}, {60, 120, 0, 1}, {60, 40, 0, 1}, {144, 60, 0, 1}, {59.94, 20, 0, 4}, {60, 60, 8, 1},
};

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

// The frames' ticks match `pattern` and add up to the clock's `ticks` within
// `slack` (a change of speed drops what the pace held, less than a tick).
static void expect(const char *what, const std::vector<int> &ran, const char *pattern, double ticks, double slack = 2) {
  std::string got = digits(ran);
  if (!std::regex_match(got, std::regex(pattern)) || fabs(total(ran) - ticks) > slack) {
    fprintf(stderr, "%s ran %s (%d ticks, not about %.1f)\n", what, got.c_str(), total(ran), ticks);
    exit(1);
  }
}

// `frames` frames at `hz` after 120 the pace settles in.
static Frames display(double hz, int frames, std::vector<int> missed = {}) {
  Frames f;
  for (int &k : missed)
    k += 120;
  f.add(hz, 120 + frames, missed);
  return f;
}

// The clock's ticks over `frames` frames at `hz`, `missed` of them skipped.
static double owed(double hz, int frames, int missed = 0) { return (frames + missed) * 60 / hz; }

int main() {
  expect("a 60 Hz display", play(display(60, 600), 120), "1+", owed(60, 600));
  expect("a 60 Hz display after a 2 ms first pass", play(display(60, 600), 120, 2), "1+", owed(60, 600));
  // A missed frame, or a stray pass, wherever it falls against the clock's
  // milliseconds; and a missed frame on a display already off the lattice.
  for (int at = 30; at < 50; ++at) {
    std::string missed = "1{" + std::to_string(at) + "}21+", stray = "1{" + std::to_string(at + 1) + "}01+";
    expect("a 60 Hz display missing a frame", play(display(60, 120, {at}), 120), missed.c_str(), owed(60, 120, 1));
    expect("a 60 Hz display with a stray pass", play(display(60, 120), 120, 1000, 120 + at), stray.c_str(),
           owed(60, 120));
    expect("a 59 Hz display missing a frame", play(display(59, 120, {at}), 120), "(?!.*2.?2)[12]+", owed(59, 120, 1));
    std::string twice = "1{" + std::to_string(at) + "}212" + "1+";
    expect("a 60 Hz display missing two frames", play(display(60, 120, {at, at + 2}), 120), twice.c_str(),
           owed(60, 120, 2));
  }
  expect("a 59 Hz display", play(display(59, 600), 120), "(?!.*(0|2.{0,49}2))[12]+", owed(59, 600));
  expect("a 61 Hz display", play(display(61, 600), 120), "(?!.*(2|0.{0,49}0))[01]+", owed(61, 600));
  expect("a 30 Hz display", play(display(30, 300), 120), "2+", owed(30, 300));
  expect("a 120 Hz display", play(display(120, 600), 120), "(01)+|(10)+", owed(120, 600));
  expect("a 240 Hz display", play(display(240, 600), 120), "(0001)+|(0010)+|(0100)+|(1000)+", owed(240, 600));
  expect("a 125 Hz display", play(display(125, 600), 120), "(?!.*(11|000))[01]+", owed(125, 600));
  expect("a 118 Hz display", play(display(118, 600), 120), "(?!.*(111|000))[01]+", owed(118, 600));
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
  // runs its share of the second, the clock's jitter and the pace's catching
  // up with a display at the lock's edge a few ticks of play aside.
  struct Fast {
    double hz;
    float speed;
    int least, most;
  } fast[] = {{59, 2, 2, 3}, {61, 2, 1, 2}, {59, 32, 28, 36}, {61, 32, 28, 36}, {60, 32, 28, 36},
              {57, 32, 29, 38}, {29, 32, 60, 72}};
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
  // The speed changing between passes: 32x after 1x on a 59 or 61 Hz display,
  // whatever play was held at 1x when it changes, and 1x after 32x.
  for (double hz : {59.0, 61.0})
    for (int at = 240; at < 300; ++at) {
      static int faster;
      faster = at;
      std::vector<int> ran = play(display(hz, 300), 120, 1000, -1, [](int k) { return k < faster ? 1.0f : 32.0f; });
      auto [least, most] = std::minmax_element(ran.begin() + (at - 120), ran.end());
      double ticks = owed(hz, at - 120) + owed(hz, 420 - at) * 32;
      if (*least < 28 || *most > 36 || fabs(total(ran) - ticks) > 3) {
        fprintf(stderr, "a %g Hz display at 32x from 1x at frame %d ran from %d to %d ticks a frame, %d in all, not about "
                "%.1f\n", hz, at, *least, *most, total(ran), ticks);
        return 1;
      }
    }
  for (double hz : {60.0, 120.0})
    for (int at = 240; at < 300; ++at) {
      static int slower;
      slower = at;
      std::string what = "a " + std::to_string((int)hz) + " Hz display back at 1x from 32x at frame " + std::to_string(at);
      expect(what.c_str(),
             play(display(hz, 300), at, 1000, -1, [](int k) { return k >= 120 && k < slower ? 32.0f : 1.0f; }),
             hz == 60 ? "1+" : "(01)*0?|(10)*1?", owed(hz, 420 - at), 3);
    }
  // The clock's time owed from the lattice when a pass comes early off it.
  LivePace pace;
  pace.period = 1 / 75.0f;
  pace.held = -0.010f;
  if (pace(0.002f) != 0 || fabsf(pace.held + 0.008f) > 1e-6f) {
    fprintf(stderr, "an early pass off the lattice, owing the clock, left %g held\n", pace.held);
    return 1;
  }
  // The catch-up itself, over ten seconds of 60 Hz passes: whole ticks or
  // none, the lead's sign, a tick each 50 passes (2%) for a lead past three
  // ticks, each 200 for a tick and a half, none within a tick.
  for (auto [ahead, ticks] : {std::pair{5.0f, 12}, {-5.0f, -12}, {1.5f, 3}, {-1.5f, -3}, {0.8f, 0}, {-0.8f, 0}}) {
    CatchUp catch_up;
    int sum = 0;
    for (int k = 0; k < 600; ++k) {
      float tick = catch_up(1 / 60.0f, ahead);
      if (tick != 0 && fabsf(fabsf(tick) - 1 / 60.0f) > 1e-7f) {
        fprintf(stderr, "a catch-up %g ticks ahead returned %g of a tick\n", ahead, tick * 60);
        return 1;
      }
      sum += (int)roundf(tick * 60);
    }
    if (abs(sum - ticks) > 1) {
      fprintf(stderr, "a catch-up %g ticks ahead ran %d ticks in 600 passes, not %d\n", ahead, sum, ticks);
      return 1;
    }
  }
  for (const Coop &c : coop) {
    Pair pair(c);
    pair.play(120);
    std::vector<int> &ran = pair.a.ran;
    int since = 1 << 30, close = 0, events = 0, wide = 0, together = -1, rushed = 0, last = -(1 << 30);
    for (size_t k = 0; k < ran.size(); ++k) {
      if (together < 0 && abs(pair.gaps[k]) <= 1)
        together = (int)k;
      // Closing a gap, a tick at a time and 2% at most: an extra frame's
      // tick at most every 50 frames.
      if (together < 0 && ran[k] != 1) {
        rushed += (int)k - last < 40;
        last = (int)k;
      }
      if (k < 600)
        continue;
      if (abs(pair.gaps[k]) > 2 && together >= 0)
        ++wide;
      if (ran[k] == 1) {
        ++since;
        continue;
      }
      ++events;
      close += since < 60;
      since = 0;
    }
    double minutes = (ran.size() - 600) / 3600.0;
    // Started apart, the run ahead slows and the one behind speeds up.
    if (c.start) {
      auto before = [&](const std::vector<int> &frames, int due) {
        return std::count(frames.begin(), frames.begin() + std::max(together, 0), due);
      };
      if (!before(ran, 0) || !before(pair.b.ran, 2)) {
        fprintf(stderr, "co-op %d ticks apart: the run ahead skipped %ld ticks, the one behind ran %ld more\n", c.start,
                before(ran, 0), before(pair.b.ran, 2));
        return 1;
      }
    }
    if (close || wide || rushed || together < 0 || together > 900 || (c.start && together < 300) ||
        events / minutes > c.most) {
      fprintf(stderr, "co-op with a %g Hz partner %g ms away, %d ticks apart: %.1f catch-up frames a minute, %d within a "
              "second of another, %d frames over two ticks apart, together after %d frames, %d rushed\n", c.partner,
              c.latency, c.start, events / minutes, close, wide, together, rushed);
      return 1;
    }
  }
  puts("live pace: 30 to 240 Hz, a missed frame, a stray pass, a short first pass, a moved window, 2x and 32x and "
       "back, an early pass owing the clock; co-op's catch-up");
}
