// Audio output. The module mixes its DirectSound buffers (game_audio); an SDL
// stream plays the mix, kept a few frames deep. The mix never falls more than a
// quarter second behind the wall clock: with no output device, or one that
// stops draining (a failure, the browser's autoplay lock), the surplus is
// dropped (game_audio_skip moves the voices on unmixed), so the game's play
// cursors and voice status move as they would with sound.
#include "client.h"
#include <SDL3/SDL.h>
#include <stdio.h>

namespace {
// The module's mix: 16-bit stereo at 44.1 kHz, at most 4096 frames a pull.
constexpr int RATE = 44100, CHANNELS = 2, FRAME_BYTES = CHANNELS * 2, PULL = 4096, LAG = RATE / 4;
SDL_AudioStream *stream;
// Frames kept queued: about four 60 Hz frames, and at least two of the device's
// buffers, which it drains whole.
Sint64 depth = RATE / 15;
// The wall clock, in mixed frames: a draining device resets it to the mix.
Uint64 anchor;
Sint64 mixed, last_queued;
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
}

void audio_update(w2c_game *game) {
  Uint64 now = SDL_GetTicksNS();
  Sint64 queued = stream ? SDL_GetAudioStreamQueued(stream) / FRAME_BYTES : 0;
  // The first pull, or a device keeping up within the slack: the wall clock is
  // where the mix is, which absorbs the device's drift but keeps a stall's debt.
  Sint64 due = anchor ? (Sint64)((now - anchor) * RATE / SDL_NS_PER_SECOND) : 0;
  if (!anchor || (stream && (queued < last_queued || queued < depth) && due - mixed <= LAG)) {
    anchor = now - (Uint64)mixed * SDL_NS_PER_SECOND / RATE;
    due = mixed;
  }
  Sint64 room = stream ? depth - queued : 0;
  // What no one will hear is skipped, not mixed: a long stall costs one call.
  for (Sint64 unheard = due - mixed - LAG - room; unheard > 0;) {
    Sint64 skip = SDL_min(unheard, (Sint64)INT32_MAX);
    w2c_game_game_audio_skip(game, (u32)skip);
    mixed += skip;
    unheard -= skip;
  }
  for (Sint64 frames = SDL_max(room, due - mixed - LAG); frames > 0;) {
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
