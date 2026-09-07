// Recovered zero-initialized declarations; this grouping is not an original translation unit.
#include "crimsonland_audio.h"

float frame_dt_copy;
crimson_cfg_t config_blob;
unsigned char plugin_runtime_active_latch;
unsigned char audio_suspend_flag;
LPDIRECTSOUND dsound_iface;
sfx_cooldown_table_t sfx_cooldown_table;
sfx_voice_table_t sfx_voice_table;
int audio_asset_id_table[83];
int sfx_flamer_fire_01;
int sfx_flamer_fire_02;
int music_track_intro_id;
int music_track_extra_1;
int music_track_crimsonquest_id;
sfx_volume_table_t sfx_volume_table;
music_entry_t music_entry_table[128];
sfx_mute_flags_t sfx_mute_flags;
sfx_entry_t sfx_entry_table[128];
music_playlist_t music_playlist;
int music_playlist_entry_count;
unsigned char music_playlist_randomized_latch;
unsigned char audio_resource_pack_available;
int audio_assets_loaded_count;
