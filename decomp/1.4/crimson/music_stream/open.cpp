#include "music_stream.h"
#include <windows.h>
#include <strmif.h>
#include <control.h>
#include <uuids.h>

bool freeware_music_stream::open(const char *filename) {
    WCHAR wide_filename[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, filename, -1, wide_filename, MAX_PATH);
    if (SUCCEEDED(CoCreateInstance(CLSID_FilterGraph, 0, CLSCTX_INPROC_SERVER, IID_IGraphBuilder, (void **)&graph))) {
        graph->QueryInterface(IID_IMediaControl, (void **)&control);
        graph->QueryInterface(IID_IMediaSeeking, (void **)&seeking);
        graph->QueryInterface(IID_IBasicAudio, (void **)&audio);
        if (SUCCEEDED(graph->RenderFile(wide_filename, 0))) {
            loaded = true;
            LONGLONG start = 0;
            if (seeking) {
                seeking->SetTimeFormat(&TIME_FORMAT_MEDIA_TIME);
                seeking->SetPositions(&start, AM_SEEKING_AbsolutePositioning, 0, AM_SEEKING_NoPositioning);
            }
            return true;
        }
    }
    return false;
}
