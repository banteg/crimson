#include "music_tracks.h"

static __forceinline void start_track(freeware_music_track track)
{
    if (freeware_music_volume[track] <= 0.0f) {
        freeware_music_tracks[track]->run();
        freeware_music_tracks[track]->seek(0);
        freeware_music_tracks[track]->set_volume(1.0f);
        freeware_music_volume[track] = 1.0f;
    }
    freeware_music_fading[track] = 0;
}

extern "C" void freeware_music_start(int sample)
{
    if (freeware_music_unavailable || freeware_music_disabled || freeware_audio_disabled)
        return;
    switch (sample) {
    case 29: start_track(intro_track); break;
    case 30: start_track(title_track); break;
    case 31: start_track(game_track); break;
    }
}

extern "C" void freeware_music_stop(int sample)
{
    if (freeware_music_unavailable || freeware_music_disabled || freeware_audio_disabled)
        return;
    switch (sample) {
    case 29: freeware_music_fading[intro_track] = 1; break;
    case 30: freeware_music_fading[title_track] = 1; break;
    case 31: freeware_music_fading[game_track] = 1; break;
    }
}
