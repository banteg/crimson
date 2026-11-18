#ifndef FREEWARE_MUSIC_STREAM_H
#define FREEWARE_MUSIC_STREAM_H

struct IGraphBuilder;
struct IMediaControl;
struct IMediaSeeking;
struct IBasicAudio;

class freeware_music_stream {
public:
    freeware_music_stream();
    void init();
    bool open(const char *filename);
    void set_volume(float level);
    void run();
    void pause();
    void stop();
    __int64 duration();
    __int64 position();
    __int64 seek(__int64 position);

private:
    void *unknown_00;
    IGraphBuilder *graph;
    IMediaControl *control;
    void *unknown_0c;
    IMediaSeeking *seeking;
    void *unknown_14;
    IBasicAudio *audio;
    unsigned char loaded;
};

#endif
