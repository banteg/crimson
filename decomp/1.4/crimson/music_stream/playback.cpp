#include "music_stream.h"
#include <windows.h>
#include <strmif.h>
#include <control.h>

freeware_music_stream::freeware_music_stream() {}

void freeware_music_stream::init() {
    unknown_00 = 0;
    graph = 0;
    control = 0;
    unknown_0c = 0;
    seeking = 0;
    unknown_14 = 0;
    audio = 0;
    loaded = 0;
    CoInitialize(0);
}

void freeware_music_stream::set_volume(float level) {
    if (loaded && audio)
        audio->put_Volume((long)((1.f - (level + 2.f) / 3.f) * -10000.f));
}

void freeware_music_stream::run() {
    if (loaded && control)
        control->Run();
}

void freeware_music_stream::pause() {
    if (loaded && control)
        control->Pause();
}

void freeware_music_stream::stop() {
    if (loaded && control)
        control->Stop();
}

// Both getters leave the output slot uninitialized if DirectShow fails to fill it.

__int64 freeware_music_stream::duration() {
    if (!loaded)
        return 0;
    __int64 value;
    if (seeking)
        seeking->GetDuration(&value);
    return value;
}

__int64 freeware_music_stream::position() {
    if (!loaded)
        return 0;
    __int64 value;
    if (seeking)
        seeking->GetCurrentPosition(&value);
    return value;
}

__int64 freeware_music_stream::seek(__int64 value) {
    if (!loaded)
        return 0;
    seeking->SetPositions(&value, AM_SEEKING_AbsolutePositioning, 0, AM_SEEKING_NoPositioning);
    return value;
}
