#include "music_tracks.h"

extern "C" float frame_dt;

static __forceinline void update_track(freeware_music_track track)
{
    if (freeware_music_fading[track]) {
        if (freeware_music_volume[track] > 0.0f) {
            freeware_music_volume[track] -= frame_dt;
            if (freeware_music_volume[track] <= 0.0f)
                freeware_music_tracks[track]->stop();
            else
                freeware_music_tracks[track]->set_volume(freeware_music_volume[track]);
        }
        if (freeware_music_volume[track] < 0.0f)
            freeware_music_volume[track] = 0.0f;
    } else {
        if (freeware_music_volume[track] < 1.0f) {
            // The title fade loads the time step onto the x87 stack first.
            if (track == title_track) {
                float volume = frame_dt;
                volume += freeware_music_volume[track];
                freeware_music_volume[track] = volume;
            } else {
                freeware_music_volume[track] += frame_dt;
            }
            if (freeware_music_volume[track] >= 1.0f)
                freeware_music_tracks[track]->set_volume(1.0f);
            else
                freeware_music_tracks[track]->set_volume(freeware_music_volume[track]);
        }
        if (freeware_music_volume[track] > 1.0f)
            freeware_music_volume[track] = 1.0f;
        if (freeware_music_volume[track] == 1.0f &&
            freeware_music_tracks[track]->position() == freeware_music_tracks[track]->duration()) {
            freeware_music_tracks[track]->seek(0);
            freeware_music_tracks[track]->run();
        }
    }
}

extern "C" void music_update_fades()
{
    update_track(title_track);
    update_track(game_track);
    update_track(intro_track);
}
