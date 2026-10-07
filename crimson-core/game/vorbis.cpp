// vorbisfile, which the original loads for music and samples. Until the host
// mixer lands, every stream fails to open and the recovered audio code runs silent.
#include <vorbis/vorbisfile.h>

extern "C" {
int ov_open_callbacks(void *, OggVorbis_File *, char *, long, ov_callbacks) { return -1; }
vorbis_info *ov_info(OggVorbis_File *, int) { return nullptr; }
ogg_int64_t ov_pcm_total(OggVorbis_File *, int) { return 0; }
int ov_clear(OggVorbis_File *) { return 0; }
long ov_read(OggVorbis_File *, char *, int, int, int, int, int *) { return 0; }
int ov_pcm_seek(OggVorbis_File *, ogg_int64_t) { return -1; }
}
