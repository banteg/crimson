// Differential check of generated functions. Both sides use the same trig
// implementation; math_oracle.py separately adjudicates the portable math.
#include "crimsonland_gameplay.h"
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <random>

creature_t creature_pool[385];
extern "C" int baseline_plaguebearer_spread_infection(int);
extern "C" int optimized_plaguebearer_spread_infection(int);
static int trig_calls;
extern "C" double portable_cos(double angle) { ++trig_calls; return std::cos(angle); }
extern "C" double portable_sin(double angle) { ++trig_calls; return std::sin(angle); }
#include "orbit-cache.inc"

static creature_t pristine[385], expected[385];
static void plague_case(int origin) {
    memcpy(pristine, creature_pool, sizeof(pristine));
    int found = baseline_plaguebearer_spread_infection(origin);
    memcpy(expected, creature_pool, sizeof(expected));
    memcpy(creature_pool, pristine, sizeof(pristine));
    assert(optimized_plaguebearer_spread_infection(origin) == found);
    assert(!memcmp(expected, creature_pool, sizeof(expected)));
    memcpy(creature_pool, pristine, sizeof(pristine));
    // Only the update caller skips this work: the function's index return stays intact.
    if (creature_pool[origin].plague_infected || creature_pool[origin].health < 150.0f)
        optimized_plaguebearer_spread_infection(origin);
    assert(!memcmp(expected, creature_pool, sizeof(expected)));
}
static unsigned bits(float value) { unsigned out; memcpy(&out, &value, 4); return out; }
int main() {
    std::mt19937 rng(0x425d80);
    std::uniform_real_distribution<float> coord(-1024, 1024);
    const float health[] = {0, 100, std::nextafter(150.0f, 0.0f), 150, std::nextafter(150.0f, INFINITY), 500};
    int plague_cases = 0, orbit_cases = 0;
    for (int test = 0; test < 4096; ++test) {
        memset(creature_pool, 0x5a, sizeof(creature_pool));
        for (int i = 0; i < 384; ++i) {
            auto &c = creature_pool[i];
            c.active = (rng() % 5) != 0; c.plague_infected = rng() % 2; c.health = health[rng() % 6];
            c.death_timer = test % 2 ? 5.0f : 16.0f; // Spread uses active, including corpses.
            c.position = {coord(rng), coord(rng)};
        }
        int origin = test % 384;
        creature_pool[origin].active = 1;
        plague_case(origin); ++plague_cases;
    }
    for (int origin : {0, 17, 383}) {
        for (float delta : {std::nextafter(45.0f, 0.0f), 45.0f, std::nextafter(45.0f, INFINITY)}) {
            for (int axis = 0; axis < 2; ++axis) for (int sign : {-1, 1}) {
                memset(creature_pool, 0, sizeof(creature_pool));
                creature_pool[origin].active = 1; creature_pool[origin].health = 100;
                // Earlier slot wins even when a later slot is closer; the origin itself is eligible.
                int other = origin == 0 ? 17 : 0;
                creature_pool[other].active = 1; creature_pool[other].plague_infected = 1;
                creature_pool[other].health = 100; creature_pool[other].death_timer = 5;
                creature_pool[other].position = {axis == 0 ? sign * delta : 0, axis == 1 ? sign * delta : 0};
                plague_case(origin); ++plague_cases;
            }
        }
    }
    for (int repeat = 0; repeat < 3; ++repeat) for (int i = 0; i < 384; ++i) {
        int seed = repeat == 1 ? 383 - i : i;
        float phase = (float)seed * 3.7f;
        phase = phase * 3.1415927f;
        const auto &cached = optimization_orbit(seed, phase);
        double cosine = std::cos((double)phase), sine = std::sin((double)phase);
        assert(!memcmp(&cached.cosine, &cosine, sizeof(double)));
        assert(!memcmp(&cached.sine, &sine, sizeof(double)));
        for (float distance : {0.0f, std::nextafter(1.0f, 0.0f), 1.0f, 44.999996f, 800.0f, 1024.0f, 2000.0f}) {
            for (float scale : {0.55f, 0.85f, 0.9f}) {
                float x = portable_mul32(cosine, distance) * scale;
                float y = portable_mul32(sine, distance) * scale;
                assert(bits(x) == bits(portable_mul32(cached.cosine, distance) * scale));
                assert(bits(y) == bits(portable_mul32(cached.sine, distance) * scale));
                ++orbit_cases;
            }
        }
        assert(trig_calls <= 768);
    }
    assert(trig_calls == 768); // One pair per seed, including reuse after simulated reset/seek.
    printf("%d Plaguebearer state/return/axis cases; %d orbit products agree; 768 cached trig calls\n", plague_cases, orbit_cases);
}
