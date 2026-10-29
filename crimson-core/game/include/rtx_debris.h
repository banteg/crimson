#pragma once
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <vector>

// Presentation-only loose ice selection. The 64 transition slots count toward
// the hard draw limit; a retiring quad still costs fragments at low opacity.
class RtxDebrisBudget {
public:
  static constexpr int capacity = 2560, target = 256, maximum = 320;
  static constexpr float fade_seconds = .08f;
  struct Candidate { int slot; float x, y, area; };
  struct State { float alpha = 0; bool seen = false; };
  std::array<State, capacity> states{};
  void reset() { states = {}; }
  void forget(int slot) { if (slot >= 0 && slot < capacity) states[slot] = {}; }
  float alpha(int slot) const { return states[slot].alpha; }

  void select(const std::vector<Candidate> &input, float width, float height, float dt) {
    struct Ranked { Candidate c; uint32_t key; int tile, rank; };
    std::vector<Ranked> ranked;
    std::array<bool, capacity> visible{}, wanted{};
    for (const auto &c : input) {
      if (c.slot < 0 || c.slot >= capacity || !(c.area > 0)) continue;
      visible[c.slot] = true;
      uint32_t key = c.slot;
      key ^= key >> 16; key *= 0x7feb352d;
      key ^= key >> 15; key *= 0x846ca68b; key ^= key >> 16;
      int x = std::clamp(int(c.x * 8 / width), 0, 7);
      int y = std::clamp(int(c.y * 6 / height), 0, 5);
      ranked.push_back({c, key, y * 8 + x, 0});
    }
    std::sort(ranked.begin(), ranked.end(), [](auto &a, auto &b) { return a.key < b.key; });
    std::array<int, 48> occupied{};
    for (auto &r : ranked) r.rank = occupied[r.tile]++;
    // Round-robin across occupied screen tiles, then stable slot hashes. Keep
    // the original draw order: only membership/opacity leaves this selector.
    std::sort(ranked.begin(), ranked.end(), [](auto &a, auto &b) {
      return a.rank != b.rank ? a.rank < b.rank : a.key < b.key;
    });
    float area = 0, screen = width * height;
    int count = 0;
    for (const auto &r : ranked) {
      if (count == target || area + r.c.area > screen * .5f) continue;
      wanted[r.c.slot] = true;
      area += r.c.area;
      ++count;
    }
    float step = std::clamp(dt / fade_seconds, 0.f, 1.f);
    for (int i = 0; i < capacity; ++i) {
      if (!visible[i]) states[i] = {};
      else if (!wanted[i]) states[i].alpha = std::max(0.f, states[i].alpha - step);
    }
    // Reserve actual quads and their entire projected area, not alpha-weighted
    // area. Resizes may temporarily exceed the area reserve while old draws
    // retire, but never the 320-quad cap.
    count = 0; area = 0;
    for (const auto &r : ranked) if (states[r.c.slot].alpha > 0) {
      ++count; area += r.c.area;
    }
    for (const auto &r : ranked) {
      auto &s = states[r.c.slot];
      if (wanted[r.c.slot]) {
        if (s.alpha > 0) s.alpha = std::min(1.f, s.alpha + step);
        else if (count < maximum && area + r.c.area <= screen * .75f) {
          // New particles retain their authored onset. Previously suppressed
          // particles enter smoothly if capacity becomes available later.
          s.alpha = s.seen ? step : 1.f;
          if (s.alpha > 0) { ++count; area += r.c.area; }
        }
      }
      s.seen = true;
    }
  }
};
