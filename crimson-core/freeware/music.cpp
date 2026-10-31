// The three 1.4.0 SFX music slots (0x405760), decoded by the classic port's Vorbis library.
#include "game.h"
#include <SDL3/SDL.h>
#define STB_VORBIS_NO_PUSHDATA_API
#include "../game/vendor/stb_vorbis.c"

namespace freeware {
void update_music(const Game &g, const std::string &folder) {
  static const char *current;
  static stb_vorbis *decoder;
  static SDL_AudioStream *output;
  static int channels, rate;
  const char *wanted = "alqvol";
  if (g.screen == Screen::Death)
    wanted = "survo41";
  else if (g.screen == Screen::Dying)
    wanted = nullptr;
  else if (g.screen == Screen::Playing || g.paused)
    wanted = g.run.hits ? "3cwonder" : nullptr;
  if (!g.music_enabled || g.quit)
    wanted = nullptr;
  if (wanted != current) {
    if (output)
      SDL_DestroyAudioStream(output);
    if (decoder)
      stb_vorbis_close(decoder);
    output = nullptr;
    decoder = nullptr;
    current = wanted;
    if (wanted) {
      int error;
      decoder = stb_vorbis_open_filename((folder + "/" + wanted + ".ogg").c_str(), &error, nullptr);
      if (!decoder)
        return;
      auto info = stb_vorbis_get_info(decoder);
      channels = info.channels;
      rate = int(info.sample_rate);
      SDL_AudioSpec spec{SDL_AUDIO_S16, channels, rate};
      output = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, nullptr, nullptr);
      if (output) {
        SDL_SetAudioStreamGain(output, .4f);
        SDL_ResumeAudioStreamDevice(output);
      }
    }
  }
  if (!output)
    return;
  short samples[4096];
  while (SDL_GetAudioStreamQueued(output) < rate * channels / 2) {
    int frames = stb_vorbis_get_samples_short_interleaved(decoder, channels, samples, 4096);
    if (!frames) {
      stb_vorbis_seek_start(decoder);
      break;
    }
    if (!SDL_PutAudioStreamData(output, samples, frames * channels * int(sizeof(short))))
      break;
  }
}
} // namespace freeware
