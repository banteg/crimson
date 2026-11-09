#ifndef FREEWARE_MUSIC_TRACKS_H
#define FREEWARE_MUSIC_TRACKS_H

#include "../../music_stream/music_stream.h"

enum freeware_music_track { intro_track, title_track, game_track };
extern "C" {
extern unsigned char freeware_audio_disabled, freeware_music_disabled, freeware_music_unavailable;
extern freeware_music_stream *freeware_music_tracks[3];
extern unsigned char freeware_music_fading[3];
extern float freeware_music_volume[3];
}

#endif
