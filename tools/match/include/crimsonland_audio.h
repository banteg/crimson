#ifndef CRIMSONLAND_AUDIO_H
#define CRIMSONLAND_AUDIO_H

#include <windows.h>
#include <dsound.h>

#include "crimsonland_types.h"

struct dsbufferdesc8_t {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwBufferBytes;
    DWORD dwReserved;
    LPWAVEFORMATEX lpwfxFormat;
    GUID guid3DAlgorithm;
};

extern LPDIRECTSOUND dsound_iface;
extern sfx_entry_t sfx_entry_table[];
extern music_entry_t music_entry_table[];

#ifdef __cplusplus
struct vorbis_stream_t {
    unsigned char _opaque0[0x2e4];
    unsigned int total_pcm_bytes;
    unsigned int source_data_offset;
    void *memory_source;
    int info_version;
    int channels;
    int sample_rate;
    int bitrate_upper;
    int bitrate_nominal;
    int bitrate_lower;
    int bitrate_window;
    void *codec_setup;

    unsigned char open(void *buffer, unsigned int size);
    int read_pcm16(char *dst, int bytes);
    int pcm_seek(unsigned int sample_offset);
    void close(void);
};

struct sfx_entry_cpp_t : sfx_entry_t {
    sfx_entry_cpp_t *reset_runtime_state(void);
};

struct console_queue_t {
    unsigned char flush_log(char *filename);
};

extern console_queue_t console_log_queue;

#else

typedef struct console_queue_t console_queue_t;
extern console_queue_t console_log_queue;

#endif

#ifdef __cplusplus
extern "C" {
#endif

extern crimson_cfg_t config_blob;
extern cvar_float_t *cv_verbose;
extern unsigned char audio_suspend_flag;
extern unsigned char sfx_unmuted_flag;
extern sfx_mute_flags_t sfx_mute_flags;
extern music_playlist_t music_playlist;
extern int music_playlist_entry_count;

unsigned char console_printf(console_queue_t *queue, char *format, ...);
void crt_free(void *ptr);
void dsound_shutdown(void);
unsigned char dsound_restore_buffer(LPDIRECTSOUNDBUFFER buffer);
void sfx_release_entry(sfx_entry_t *entry);
unsigned char sfx_release_sample(int sfx_id);
void sfx_release_all(void);
unsigned char music_release_track(int track_id);
void music_release_all(void);
void music_queue_track(int track_id);
unsigned char sfx_is_unmuted(int sfx_id);
void sfx_entry_resume(sfx_entry_t *entry);
void sfx_entry_seek(sfx_entry_t *entry, unsigned int sample_offset);
void sfx_entry_stop(sfx_entry_t *entry);
void sfx_entry_set_volume(sfx_entry_t *entry, float volume);
unsigned char sfx_entry_upload_buffer(sfx_entry_t *entry);
unsigned char sfx_entry_create_buffers(sfx_entry_t *entry);
unsigned char wav_parse_into_entry(
    sfx_entry_t *entry,
    void *data,
    unsigned int size);
unsigned char sfx_entry_load_wav(sfx_entry_t *entry, char *path);
unsigned char sfx_entry_load_ogg(sfx_entry_t *entry, char *path);
unsigned char music_entry_load_ogg(music_entry_t *entry, char *path);
unsigned char music_stream_fill(music_entry_t *entry);
void music_stream_update(music_entry_t *entry);
void audio_suspend_channels(void);
void audio_resume_channels(void);
unsigned char audio_resume_all(void);
unsigned char audio_suspend_all(void);

#ifdef __cplusplus
}
#endif

#endif
