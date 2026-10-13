// Exercise the actual client pump against a device that consumes whole buffers.
// Impulses stand in for shot attacks, so their output offsets expose timing loss.
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
using Sint64 = int64_t;
using Uint64 = uint64_t;
using u32 = uint32_t;
struct w2c_game {};
struct SDL_AudioStream {};
struct SDL_AudioSpec { int format, channels, freq; };
constexpr int SDL_AUDIO_S16LE = 1, SDL_INIT_AUDIO = 1, SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK = 1;
constexpr Uint64 SDL_NS_PER_SECOND = 1000000000;
#define SDL_min std::min
#define SDL_max std::max
#define SDL_clamp std::clamp
static Uint64 now = 1;
static Sint64 queued_frames, advanced, submitted, skipped;
static bool no_device, locked, attack;
static int quantum;
static short samples[4096 * 2];
static std::vector<Sint64> attacks;
static SDL_AudioStream device;
bool SDL_InitSubSystem(int) { return !no_device; }
SDL_AudioStream *SDL_OpenAudioDeviceStream(int, const SDL_AudioSpec *, void *, void *) { return &device; }
int SDL_GetAudioStreamDevice(SDL_AudioStream *) { return 1; }
bool SDL_GetAudioDeviceFormat(int, SDL_AudioSpec *spec, int *frames) {
  spec->freq = 44100; *frames = quantum; return true;
}
bool SDL_ResumeAudioStreamDevice(SDL_AudioStream *) { return true; }
const char *SDL_GetError() { return "test: no device"; }
void SDL_SetAudioStreamGain(SDL_AudioStream *, float) {}
Uint64 SDL_GetTicksNS() { return now; }
int SDL_GetAudioStreamQueued(SDL_AudioStream *) { return queued_frames * 4; }
void SDL_PutAudioStreamData(SDL_AudioStream *, const void *data, int bytes) {
  const short *pcm = (const short *)data;
  for (int i = 0; i < bytes / 4; ++i)
    if (pcm[i * 2]) attacks.push_back(submitted + i);
  submitted += bytes / 4;
  queued_frames += bytes / 4;
}
unsigned char *client_memory() { return (unsigned char *)samples; }
u32 w2c_game_game_audio(w2c_game *, int frames) {
  assert(frames > 0 && frames <= 4096);
  std::fill(samples, samples + frames * 2, 0);
  if (attack) samples[0] = 1;
  attack = false;
  advanced += frames;
  return 0;
}
void w2c_game_game_audio_skip(w2c_game *, u32 frames) {
  advanced += frames; skipped += frames; attack = false;
}

#include "audio-under-test.cpp"

int main(int argc, char **argv) {
  assert(argc == 3);
  quantum = atoi(argv[1]);
  int scenario = atoi(argv[2]); // regular, locked, absent, stall, fast/slow device clock
  no_device = scenario == 2;
  locked = scenario == 1;
  w2c_game game;
  audio_init();
  audio_update(&game);
  const Sint64 primed = advanced;
  Sint64 consumed = 0;
  for (int frame = 1; frame <= (scenario >= 4 ? 36000 : 240); ++frame) {
    Sint64 elapsed = (Sint64)frame * 735;
    if (scenario == 3 && frame >= 120) elapsed += 44100 * 30;
    now = 1 + (Uint64)elapsed * SDL_NS_PER_SECOND / 44100;
    if (!no_device && !locked) {
      Sint64 device_elapsed = scenario == 4 ? elapsed * 1001 / 1000
                             : scenario == 5 ? elapsed * 999 / 1000 : elapsed;
      Sint64 due = device_elapsed / quantum * quantum;
      Sint64 drain = due - consumed;
      if (scenario != 3 || frame != 120) assert(queued_frames >= drain);
      queued_frames = std::max<Sint64>(0, queued_frames - drain);
      consumed = due;
    }
    // This is main.cpp's order: advance old audio, then produce this frame's
    // new sound. A long stall must not skip the newly created attack.
    audio_update(&game);
    if (scenario == 0 && frame % 7 == 0) attack = true;
    if (scenario == 3 && frame == 120) attack = true;
    assert(queued_frames <= depth + LAG);
    if (scenario < 3) assert(std::abs(advanced - primed - elapsed) <= 1);
    // A stall changes the device's buffer phase; clock steering is bounded
    // to one sample per subsequent frame.
    if (scenario == 3) assert(std::abs(advanced - primed - elapsed) <= frame);
  }
  if (scenario == 0) {
    assert(attacks.size() == 34);
    for (size_t i = 1; i < attacks.size(); ++i)
      assert(std::abs(attacks[i] - attacks[i - 1] - 7 * 735) <= 1);
  }
  if (scenario == 3) { assert(skipped > 29 * 44100); assert(attacks.size() == 1); }
  if (scenario >= 4) { assert(!skipped); assert(submitted == advanced); assert(queued_frames < depth * 2); }
  printf("audio quantum=%d scenario=%d: passed\n", quantum, scenario);
}
