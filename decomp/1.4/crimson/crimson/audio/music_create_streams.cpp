#include "music_tracks.h"

extern "C" void freeware_music_create_streams()
{
    if (!freeware_music_unavailable) {
        freeware_music_tracks[game_track] = new freeware_music_stream;
        freeware_music_tracks[intro_track] = new freeware_music_stream;
        freeware_music_tracks[title_track] = new freeware_music_stream;
        freeware_music_tracks[game_track]->init();
        freeware_music_tracks[intro_track]->init();
        freeware_music_tracks[title_track]->init();
    }
}
