#include "crimsonland_audio.h"

extern "C" unsigned char music_release_track(int track_id)
{
    if (track_id < 0 || track_id >= 128) {
        return 0;
    }
    if (music_entry_table[track_id].pcm_data == 0) {
        return 0;
    }
    sfx_release_entry(&music_entry_table[track_id]);
    return 1;
}
