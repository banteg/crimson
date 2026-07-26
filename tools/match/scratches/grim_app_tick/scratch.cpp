#include <windows.h>
#include <mmsystem.h>

class MyApp {
public:
    unsigned char active;
    unsigned char padding_01[3];
    int last_tick_ms;
    int tick_remainder_ms;

    bool tick(void);
};

bool MyApp::tick(void)
{
    DWORD now = timeGetTime();
    if (last_tick_ms < 0) {
        last_tick_ms = now;
        return false;
    }

    int elapsed_ms = now - last_tick_ms;
    last_tick_ms = now;
    tick_remainder_ms += elapsed_ms;
    if (tick_remainder_ms < 30) {
        return false;
    }

    tick_remainder_ms %= 30;
    return true;
}
