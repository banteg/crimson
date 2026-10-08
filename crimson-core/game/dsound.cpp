// DirectSound, mixed inside the module. Buffers, cursors and status stay here,
// so the host interface gains nothing to query: the host pulls the mix
// (game_audio) as its output drains, and a host with no output pulls it at
// wall-clock pace into nothing.
#include "com_defaults.h"
#include <algorithm>
#include <math.h>
#include <memory>
#include <string.h>
#include <vector>

namespace {

// The primary format sfx_system_init sets: 44.1 kHz, stereo, 16-bit.
constexpr int RATE = 44100, MAX_FRAMES = 4096;

// hundredths of a decibel to gain; -10000 is silence.
float attenuation(LONG hundredths) { return hundredths <= DSBVOLUME_MIN ? 0 : powf(10, hundredths / 2000.0f); }

struct Buffer;
std::vector<Buffer *> buffers; // the secondary buffers, which the mix plays

struct Buffer final : UnimplementedIDirectSoundBuffer {
  ULONG refs = 1;
  bool primary;
  WAVEFORMATEX format{};
  // Duplicates share their original's samples.
  std::shared_ptr<std::vector<unsigned char>> data;
  DWORD frequency = 0;
  double frame = 0; // the play cursor, in frames of the buffer's format
  bool playing = false, looping = false;
  float volume = 1, left = 1, right = 1;

  explicit Buffer(bool p) : primary(p) {
    if (!primary)
      buffers.push_back(this);
  }
  ~Buffer() {
    if (!primary)
      buffers.erase(std::find(buffers.begin(), buffers.end(), this));
  }
  DWORD frames() const { return data->size() / format.nBlockAlign; }

  STDMETHOD_(ULONG, AddRef)(THIS) override { return ++refs; }
  STDMETHOD_(ULONG, Release)(THIS) override {
    if (--refs)
      return refs;
    delete this;
    return 0;
  }
  STDMETHOD(SetFormat)(THIS_ LPCWAVEFORMATEX) override { return DS_OK; }
  STDMETHOD(GetStatus)(THIS_ LPDWORD status) override {
    *status = playing ? DSBSTATUS_PLAYING | (looping ? DSBSTATUS_LOOPING : 0) : 0;
    return DS_OK;
  }
  STDMETHOD(Restore)(THIS) override { return DS_OK; }
  STDMETHOD(Lock)(THIS_ DWORD offset, DWORD bytes, LPVOID *first, LPDWORD first_bytes, LPVOID *second,
                  LPDWORD second_bytes, DWORD) override {
    DWORD size = data->size();
    *first = data->data() + offset;
    *first_bytes = bytes < size - offset ? bytes : size - offset;
    if (second) {
      *second = bytes > *first_bytes ? data->data() : nullptr;
      *second_bytes = bytes - *first_bytes;
    }
    return DS_OK;
  }
  STDMETHOD(Unlock)(THIS_ LPVOID, DWORD, LPVOID, DWORD) override { return DS_OK; }
  STDMETHOD(Play)(THIS_ DWORD, DWORD, DWORD flags) override {
    playing = true;
    looping = flags & DSBPLAY_LOOPING;
    return DS_OK;
  }
  // Stopping keeps the cursor; a one-shot buffer that plays to its end rewinds.
  STDMETHOD(Stop)(THIS) override {
    playing = false;
    return DS_OK;
  }
  STDMETHOD(GetCurrentPosition)(THIS_ LPDWORD play, LPDWORD write) override {
    DWORD at = (DWORD)frame * format.nBlockAlign;
    if (play)
      *play = at;
    if (write)
      *write = at;
    return DS_OK;
  }
  STDMETHOD(SetCurrentPosition)(THIS_ DWORD position) override {
    frame = position / format.nBlockAlign;
    return DS_OK;
  }
  STDMETHOD(SetFrequency)(THIS_ DWORD hz) override {
    frequency = hz == DSBFREQUENCY_ORIGINAL ? format.nSamplesPerSec : hz;
    return DS_OK;
  }
  STDMETHOD(SetVolume)(THIS_ LONG hundredths) override {
    volume = attenuation(hundredths);
    return DS_OK;
  }
  // Panning attenuates the far side only.
  STDMETHOD(SetPan)(THIS_ LONG pan) override {
    left = attenuation(pan > 0 ? -pan : 0);
    right = attenuation(pan < 0 ? pan : 0);
    return DS_OK;
  }

  // A sample of one channel at a whole frame, as a float in [-1, 1).
  float sample(DWORD at, int channel) const {
    const unsigned char *p = data->data() + at * format.nBlockAlign;
    if (format.wBitsPerSample == 8)
      return (p[channel] - 128) / 128.0f;
    return (short)(p[channel * 2] | p[channel * 2 + 1] << 8) / 32768.0f;
  }
  // Adds this buffer's next frames, resampled linearly to the output rate.
  void mix(float *out, int count) {
    DWORD length = frames();
    double step = (double)frequency / RATE;
    int stereo = format.nChannels > 1;
    for (int i = 0; i < count && playing; ++i) {
      DWORD at = (DWORD)frame, next = at + 1 < length ? at + 1 : looping ? 0 : at;
      float t = (float)(frame - at);
      float l = sample(at, 0) + (sample(next, 0) - sample(at, 0)) * t;
      float r = stereo ? sample(at, 1) + (sample(next, 1) - sample(at, 1)) * t : l;
      out[i * 2] += l * volume * left;
      out[i * 2 + 1] += r * volume * right;
      advance(step);
    }
  }
  // Moves the cursor on, as playing does: a looping buffer wraps, a one-shot
  // stops and rewinds.
  void advance(double frames_played) {
    DWORD length = frames();
    frame += frames_played;
    if (frame >= length) {
      if (looping) {
        frame = fmod(frame, length);
      } else {
        playing = false;
        frame = 0;
      }
    }
  }
};

struct Device final : UnimplementedIDirectSound8 {
  ULONG refs = 1;
  STDMETHOD_(ULONG, AddRef)(THIS) override { return ++refs; }
  STDMETHOD_(ULONG, Release)(THIS) override {
    if (--refs)
      return refs;
    delete this;
    return 0;
  }
  STDMETHOD(SetCooperativeLevel)(THIS_ HWND, DWORD) override { return DS_OK; }
  STDMETHOD(CreateSoundBuffer)(THIS_ LPCDSBUFFERDESC desc, LPLPDIRECTSOUNDBUFFER output, IUnknown *) override {
    auto *buffer = new Buffer(desc->dwFlags & DSBCAPS_PRIMARYBUFFER);
    if (!buffer->primary) {
      buffer->format = *desc->lpwfxFormat;
      buffer->data = std::make_shared<std::vector<unsigned char>>(desc->dwBufferBytes);
      buffer->frequency = buffer->format.nSamplesPerSec;
    }
    *output = buffer;
    return DS_OK;
  }
  STDMETHOD(DuplicateSoundBuffer)(THIS_ LPDIRECTSOUNDBUFFER original, LPLPDIRECTSOUNDBUFFER output) override {
    auto *source = (Buffer *)original;
    auto *buffer = new Buffer(false);
    buffer->format = source->format;
    buffer->data = source->data;
    buffer->frequency = source->frequency;
    *output = buffer;
    return DS_OK;
  }
};

short output[MAX_FRAMES * 2];

} // namespace

extern "C" HRESULT WINAPI DirectSoundCreate8(LPCGUID, LPDIRECTSOUND8 *device, LPUNKNOWN) {
  *device = new Device;
  return DS_OK;
}

// The next frames of the mix (at most MAX_FRAMES), as interleaved 16-bit stereo
// at 44.1 kHz.
// Frames of the mix that would be dropped unheard: the voices move on without
// mixing (a host that could not play for a while).
extern "C" __attribute__((export_name("game_audio_skip"))) void game_audio_skip(int frames) {
  for (Buffer *buffer : buffers)
    if (buffer->playing)
      buffer->advance((double)buffer->frequency / RATE * frames);
}

extern "C" __attribute__((export_name("game_audio"))) short *game_audio(int frames) {
  static float mix[MAX_FRAMES * 2];
  frames = frames < MAX_FRAMES ? frames : MAX_FRAMES;
  memset(mix, 0, frames * 2 * sizeof(float));
  for (Buffer *buffer : buffers)
    buffer->mix(mix, frames);
  for (int i = 0; i < frames * 2; ++i) {
    float v = mix[i] * 32768.0f;
    output[i] = (short)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
  }
  return output;
}
