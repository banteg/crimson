#pragma once
#include <math.h>
// The play a pass banks toward a run's ticks, paced to the display. Grim's
// clock reads whole milliseconds a little after each frame shows, so a 60 Hz
// display's frames read 16 or 17 ms, or further off with jitter: banked as
// read, the bank sits on a tick's edge, and a third of the frames or more run
// none or two. A pass banks the display frames it spans where the display's
// period, which the passes average from a tick's, is within 5% of whole ticks
// or of a tick split evenly (30, 60, 120 or 240 Hz), each at exactly that, so
// each of that display's frames runs the same ticks.
// What that leaves of the clock's time is paid back a frame's share or a tick
// of play at a time, whichever is less, by one frame running it or leaving it
// out, so play keeps the clock's time. Any other display's frames run ticks
// unevenly anyway, and bank the clock's time as it comes. A pass that comes
// early banks nothing rather than less, and the time it ran ahead waits.
struct LivePace {
  float period = 1 / 60.0f; // the display's frame time, as the passes average it
  float held = 0;           // the clock's time not yet banked
  // The seconds of play a pass `dt` seconds after the last banks, at a
  // replay's `speed`: played fast, it fits a tick of play in less of the
  // clock's time.
  float operator()(float dt, float speed = 1) {
    // The display frames this pass spans: two for a missed frame, none for a
    // stray pass early in one. Either moves the average as half a period
    // would, which keeps the display's lock.
    float spans = roundf(dt / period);
    period += (fminf(fmaxf(dt, period / 2), period * 1.5f) - period) / 16;
    float ticks = period * 60, even = ticks >= 1 ? roundf(ticks) : 1 / roundf(1 / ticks);
    float step = spans * even / 60, share = fminf(even / 60, 1 / (60 * fmaxf(speed, 1)));
    held += dt;
    float paced = held;
    if (fabsf(ticks / even - 1) <= 0.05f)
      paced = step + fminf(fmaxf(truncf((held - step) / share), -1), 1) * share;
    paced = fmaxf(paced, 0);
    held -= paced;
    return paced * speed;
  }
};
