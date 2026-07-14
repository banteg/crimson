#ifndef CRIMSONLAND_AUDIO_H
#define CRIMSONLAND_AUDIO_H

#include <windows.h>
#include <dsound.h>

#include "crimsonland_console.h"
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
extern sfx_voice_table_t sfx_voice_table;

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

#endif

#ifdef __cplusplus
extern "C" {
#endif

extern crimson_cfg_t config_blob;
extern cvar_float_t *cv_verbose;
extern cvar_float_t *cv_silentloads;
extern unsigned char audio_suspend_flag;
extern unsigned char sfx_unmuted_flag;
extern unsigned char music_playlist_randomized_latch;
extern unsigned char audio_resource_pack_available;
extern unsigned char plugin_runtime_active_latch;
extern unsigned char demo_mode_active;
extern int audio_assets_loaded_count;
extern float bonus_reflex_boost_timer;
extern float camera_offset_x;
extern float frame_dt_copy;
extern float frame_dt;
extern DWORD sfx_rate_scale;
extern sfx_cooldown_table_t sfx_cooldown_table;
extern sfx_volume_table_t sfx_volume_table;
extern sfx_mute_flags_t sfx_mute_flags;
extern music_playlist_t music_playlist;
extern int music_playlist_entry_count;
extern int music_track_intro_id;
extern int music_track_shortie_monk_id;
extern int music_track_crimson_theme_id;
extern int music_track_extra_0;
extern int music_track_extra_1;
extern int music_track_crimsonquest_id;
extern int sfx_flamer_fire_01;
extern int sfx_flamer_fire_02;
extern int audio_asset_id_table[83];

int crt_sprintf(char *dst, const char *format, ...);
int crt_rand(void);
void crt_free(void *ptr);
HRESULT WINAPI DirectSoundCreate8(
    GUID *guid,
    LPDIRECTSOUND *iface_out,
    LPUNKNOWN outer);
unsigned char dsound_init(
    HWND hwnd,
    DWORD coop_level,
    int channels,
    DWORD sample_rate,
    int bits_per_sample);
void dsound_shutdown(void);
unsigned char dsound_restore_buffer(LPDIRECTSOUNDBUFFER buffer);
void sfx_release_entry(sfx_entry_t *entry);
unsigned char sfx_release_sample(int sfx_id);
int sfx_load_sample(char *path);
void sfx_release_all(void);
unsigned char music_release_track(int track_id);
void music_release_all(void);
void music_queue_track(int track_id);
unsigned char sfx_is_unmuted(int sfx_id);
void sfx_entry_resume(sfx_entry_t *entry);
void sfx_entry_seek(sfx_entry_t *entry, unsigned int sample_offset);
void sfx_entry_stop(sfx_entry_t *entry);
int sfx_entry_start_playback(sfx_entry_t *entry);
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
int music_load_track(char *path);
void sfx_entry_table_init(void);
void sfx_entry_table_init_thunk(void);
void audio_asset_id_table_init(void);
void audio_asset_id_table_init_thunk(void);
void music_entry_table_init(void);
void music_entry_table_init_thunk(void);
unsigned char music_stream_fill(music_entry_t *entry);
void music_stream_update(music_entry_t *entry);
void audio_update(void);
void sfx_mute_all(int sfx_id);
void sfx_update_mute_fades(void);
void sfx_play_exclusive(int sfx_id);
int sfx_play(int sfx_id, float volume);
int sfx_play_panned(int sfx_id, float *pos, float volume);
unsigned char sfx_system_init(void);
void audio_init_sfx(void);
void audio_init_music(void);
void audio_suspend_channels(void);
void audio_resume_channels(void);
unsigned char audio_resume_all(void);
unsigned char audio_suspend_all(void);

#ifdef __cplusplus
}
#endif

#endif
