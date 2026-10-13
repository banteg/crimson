// Audio output. The module mixes its DirectSound buffers (game_audio); an SDL
// stream plays the mix, kept a few frames deep. Mixing follows elapsed time,
// not device refills: a browser drains whole buffers, and filling each hole
// in one pull would snap every new sound to those buffer boundaries.
// The mix never falls more than a quarter second behind the wall clock: with
// no output device, or one that stops draining (a failure, the browser's
// autoplay lock), the surplus is
// dropped (game_audio_skip moves the voices on unmixed), so the game's play
// cursors and voice status move as they would with sound. CRIMSON_MUTE silences
// the device only: the game mixes and the device drains as they would aloud.
#include "client.h"
#include <SDL3/SDL.h>
#include <stdio.h>
#include <stdlib.h>

namespace {
// The module's mix: 16-bit stereo at 44.1 kHz, at most 4096 frames a pull.
constexpr int RATE = 44100, CHANNELS = 2, FRAME_BYTES = CHANNELS * 2, PULL = 4096, LAG = RATE / 4;
SDL_AudioStream *stream;
// Frames kept queued: about four 60 Hz frames, and at least two of the device's
// buffers, which it drains whole.
Sint64 depth = RATE / 15;
// The wall clock, with the initial queue depth ahead of it.
Uint64 anchor;
Uint64 last_drain;
Sint64 mixed, last_queued, correction;
} // namespace

void audio_init() {
  SDL_AudioSpec spec = {SDL_AUDIO_S16LE, CHANNELS, RATE};
  if (SDL_InitSubSystem(SDL_INIT_AUDIO))
    stream = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, nullptr, nullptr);
  SDL_AudioSpec device;
  int device_frames;
  if (stream && SDL_GetAudioDeviceFormat(SDL_GetAudioStreamDevice(stream), &device, &device_frames))
    depth = SDL_max(depth, (Sint64)device_frames * RATE / device.freq * 2);
  if (!stream || !SDL_ResumeAudioStreamDevice(stream))
    fprintf(stderr, "crimson: no audio output (%s)\n", SDL_GetError());
  else if (getenv("CRIMSON_MUTE"))
    SDL_SetAudioStreamGain(stream, 0);
}

void audio_update(w2c_game *game) {
  Uint64 now = SDL_GetTicksNS();
  Sint64 queued = stream ? SDL_GetAudioStreamQueued(stream) / FRAME_BYTES : 0;
  if (!anchor)
    anchor = now;
  Sint64 due = depth + (Sint64)((now - anchor) * RATE / SDL_NS_PER_SECOND) + correction;
  if (stream && queued < last_queued)
    last_drain = now;
  // Device and wall clocks can drift. Outside a whole buffer of slack, nudge
  // by one sample per update, never by a refill-sized block. A stalled device
  // must keep advancing unheard, so it does not steer this clock.
  if (last_drain && now - last_drain < SDL_NS_PER_SECOND / 4 && due - mixed <= LAG) {
    Sint64 projected = queued + due - mixed;
    int adjust = projected < depth ? 1 : projected > depth * 3 / 2 && due > mixed ? -1 : 0;
    correction += adjust;
    due += adjust;
  }
  // Leave room for the device's chunked consumption, but bound a locked or
  // failed device's queue. Its unplayed surplus still advances the voices.
  Sint64 room = stream ? SDL_max((Sint64)0, depth + LAG - queued) : 0;
  // What no one will hear is skipped, not mixed: a long stall costs one call.
  // Refill only the normal depth afterwards, without adding lasting latency.
  for (Sint64 unheard = due - mixed - SDL_min(depth, (Sint64)LAG); unheard > 0;) {
    Sint64 skip = SDL_min(unheard, (Sint64)INT32_MAX);
    w2c_game_game_audio_skip(game, (u32)skip);
    mixed += skip;
    unheard -= skip;
  }
  for (Sint64 frames = due - mixed; frames > 0;) {
    int pull = (int)SDL_min(frames, (Sint64)PULL);
    const void *mix = client_memory() + w2c_game_game_audio(game, pull);
    int played = (int)SDL_clamp(room, (Sint64)0, (Sint64)pull);
    if (played)
      SDL_PutAudioStreamData(stream, mix, played * FRAME_BYTES);
    room -= played;
    mixed += pull;
    frames -= pull;
  }
  last_queued = stream ? SDL_GetAudioStreamQueued(stream) / FRAME_BYTES : 0;
}
