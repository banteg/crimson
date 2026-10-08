// vorbisfile over stb_vorbis. The original opens samples and music through its
// own memory callbacks (vorbis_mem_*) and reads 16-bit little-endian signed
// PCM; the decoder takes a copy of the whole stream.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vorbis/vorbisfile.h>
// stb_vorbis 1.22, public domain (nothings/stb f1c79c0).
#include "vendor/stb_vorbis.c"

namespace {
// vf->vi points at the stream's info, as ov_info returns it.
struct Stream {
  vorbis_info info;
  stb_vorbis *decoder;
  unsigned char data[];
};
Stream *stream(OggVorbis_File *vf) { return (Stream *)vf->vi; }
} // namespace

extern "C" {
int ov_open_callbacks(void *datasource, OggVorbis_File *vf, char *, long, ov_callbacks callbacks) {
  memset(vf, 0, sizeof *vf);
  callbacks.seek_func(datasource, 0, SEEK_END);
  long size = callbacks.tell_func(datasource);
  callbacks.seek_func(datasource, 0, SEEK_SET);
  auto *s = (Stream *)calloc(1, sizeof(Stream) + size);
  int error;
  if (callbacks.read_func(s->data, 1, size, datasource) != (size_t)size ||
      !(s->decoder = stb_vorbis_open_memory(s->data, (int)size, &error, nullptr))) {
    free(s);
    return OV_ENOTVORBIS;
  }
  stb_vorbis_info info = stb_vorbis_get_info(s->decoder);
  s->info.channels = info.channels;
  s->info.rate = info.sample_rate;
  vf->datasource = datasource;
  vf->callbacks = callbacks;
  vf->seekable = 1;
  vf->links = 1;
  vf->vi = &s->info;
  vf->ready_state = OPENED;
  return 0;
}
vorbis_info *ov_info(OggVorbis_File *vf, int) { return vf->vi; }
ogg_int64_t ov_pcm_total(OggVorbis_File *vf, int) { return stb_vorbis_stream_length_in_samples(stream(vf)->decoder); }
int ov_clear(OggVorbis_File *vf) {
  if (Stream *s = stream(vf)) {
    stb_vorbis_close(s->decoder);
    free(s);
  }
  if (vf->datasource && vf->callbacks.close_func)
    vf->callbacks.close_func(vf->datasource);
  memset(vf, 0, sizeof *vf);
  return 0;
}
// The original's read callback wraps to the start of its memory at the end, so
// vorbisfile reads on into the stream again: that is how music loops.
long ov_read(OggVorbis_File *vf, char *buffer, int length, int, int, int, int *bitstream) {
  Stream *s = stream(vf);
  *bitstream = 0;
  int channels = s->info.channels;
  int frames = stb_vorbis_get_samples_short_interleaved(s->decoder, channels, (short *)buffer, length / 2);
  if (!frames && stb_vorbis_seek_start(s->decoder))
    frames = stb_vorbis_get_samples_short_interleaved(s->decoder, channels, (short *)buffer, length / 2);
  return frames * channels * 2;
}
int ov_pcm_seek(OggVorbis_File *vf, ogg_int64_t sample) {
  return stb_vorbis_seek(stream(vf)->decoder, (unsigned)sample) ? 0 : OV_EINVAL;
}
}
