#pragma once
#include <math.h>
// The play a pass banks toward a run's ticks, paced to the display. Grim's
// clock reads whole milliseconds a little after each frame shows, so a 60 Hz
// display's frames read 16 or 17 ms, or further off with jitter: banked as
// read, the bank sits on a tick's edge, and a third of the frames or more run
// none or two. A pass banks the display frames it spans where the display's
// period, which the passes average from a tick's, is within 5% of whole ticks
// or of a tick split evenly (30, 60, 120 or 240 Hz), each at exactly that, so
// each of that display's frames runs the same ticks. What that leaves of the
// clock's time is paid back in a frame's share or a tick of play, whichever is
// less, an eighth of a frame's step a pass at most (more than the 5% a display
// drifts), so play keeps the clock's time. Any other display's frames run
// ticks unevenly anyway, and bank the clock's time as it comes. A pass that
// comes early banks nothing rather than less, and the time it ran ahead waits.
struct LivePace {
  float period = 1 / 60.0f; // the display's frame time, as the passes average it
  float held = 0;           // play the clock's time owes, not yet banked
  float played = 1;         // the replay's speed what it holds owes
  // The seconds of play a pass `dt` seconds after the last banks, at a
  // replay's `speed`. A change of speed starts what it holds afresh: less
  // than a tick of play, which the clock's jitter at 32x leaves and which at
  // 1x would be a frame's.
  float operator()(float dt, float speed = 1) {
    if (speed != played)
      held = 0, played = speed;
    // The display frames this pass spans: two for a missed frame, none for a
    // stray pass early in one. Either moves the average as a quarter period
    // would, which keeps the display's lock.
    float spans = roundf(dt / period);
    period += (fminf(fmaxf(dt, period * 0.75f), period * 1.25f) - period) / 16;
    float ticks = period * 60, even = ticks >= 1 ? roundf(ticks) : 1 / roundf(1 / ticks);
    float frame = even / 60 * speed, step = spans * frame, share = fminf(frame, 1 / 60.0f);
    held += dt * speed;
    float paced = held;
    if (fabsf(ticks / even - 1) <= 0.05f) {
      float most = fmaxf(1, truncf(step / share / 8));
      paced = step + fminf(fmaxf(truncf((held - step) / share), -most), most) * share;
    }
    paced = fmaxf(paced, 0);
    held -= paced;
    return paced;
  }
};
