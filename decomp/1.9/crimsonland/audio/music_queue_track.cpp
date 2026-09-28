#include "crimsonland_audio.h"

extern "C" void music_queue_track(int track_id)
{
    if (track_id < 0) {
        return;
    }
    music_playlist[music_playlist_entry_count] = track_id;
    ++music_playlist_entry_count;
}
