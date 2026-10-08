// Audio output. The module mixes its DirectSound buffers (game_audio); an SDL
// stream plays the mix, kept a few frames deep. Without an output device the
// mix still advances at wall-clock pace, so the game's play cursors and voice
// status move as they would with sound.
#include "client.h"
#include <SDL3/SDL.h>
#include <stdio.h>

namespace {
// The module's mix: 16-bit stereo at 44.1 kHz, at most 4096 frames a pull.
constexpr int RATE = 44100, CHANNELS = 2, PULL = 4096;
SDL_AudioStream *stream;
// Frames kept queued: about four 60 Hz frames, and at least two of the device's
// buffers, which it drains whole.
int queued = RATE / 15;
Uint64 start, mixed;
} // namespace

void audio_init() {
  SDL_AudioSpec spec = {SDL_AUDIO_S16LE, CHANNELS, RATE};
  if (SDL_InitSubSystem(SDL_INIT_AUDIO))
    stream = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, nullptr, nullptr);
  SDL_AudioSpec device;
  int device_frames;
  if (stream && SDL_GetAudioDeviceFormat(SDL_GetAudioStreamDevice(stream), &device, &device_frames))
    queued = SDL_max(queued, (int)((Sint64)device_frames * RATE / device.freq) * 2);
  if (stream)
    SDL_ResumeAudioStreamDevice(stream);
  else
    fprintf(stderr, "crimson: no audio output (%s)\n", SDL_GetError());
  start = SDL_GetTicksNS();
}

void audio_update(w2c_game *game) {
  Uint64 due = (SDL_GetTicksNS() - start) * RATE / SDL_NS_PER_SECOND;
  Sint64 frames = stream ? queued - SDL_GetAudioStreamQueued(stream) / (CHANNELS * 2) : (Sint64)(due - mixed);
  while (frames > 0) {
    int pull = frames < PULL ? (int)frames : PULL;
    const void *mix = client_memory() + w2c_game_game_audio(game, pull);
    if (stream)
      SDL_PutAudioStreamData(stream, mix, pull * CHANNELS * 2);
    mixed += pull;
    frames -= pull;
  }
}
