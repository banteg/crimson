#pragma once
#include <math.h>
// The play a pass banks toward a run's ticks, paced to the display. Grim's
// clock reads whole milliseconds a little after each frame shows, so a 60 Hz
// display's frames read 16 or 17 ms, or further off with jitter: banked as
// read, the bank sits on a tick's edge, and a third of the frames or more run
// none or two. A pass banks the display frames it spans (a missed one counts
// two) at the display's period, which the passes average; where that period is
// within 5% of whole ticks or of a tick split evenly (30, 60, 120 or 240 Hz),
// at exactly that, so each of that display's frames runs the same ticks. What
// that leaves of the clock's time waits until it comes to a whole tick, which
// one frame then runs or leaves out, so play keeps the clock's time; a pass
// that comes early banks nothing rather than less, and the time it ran ahead
// waits for the next.
struct LivePace {
  float period; // the display's frame time, as the passes average it
  float held;   // the clock's time not yet banked
  // The seconds a pass `dt` seconds after the last banks.
  float operator()(float dt) {
    if (!period)
      period = dt;
    float spans = fmaxf(1, roundf(dt / period));
    period += (dt / spans - period) / 16;
    float ticks = period * 60, even = ticks >= 1 ? roundf(ticks) : 1 / roundf(1 / ticks);
    float step = spans * (fabsf(ticks / even - 1) <= 0.05f ? even / 60 : period);
    held += dt;
    float paced = fmaxf(step + truncf((held - step) * 60) / 60, 0);
    held -= paced;
    return paced;
  }
};
