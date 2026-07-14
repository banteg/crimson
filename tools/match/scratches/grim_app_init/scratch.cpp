#include <windows.h>
#include <string.h>

extern "C" __declspec(dllimport) char *__cdecl _getcwd(
    char *buffer, int max_length);

class MyApp {
public:
    bool active;
    unsigned char padding_01[3];
    int last_tick_ms;
    int tick_remainder_ms;
    int height;
    int width;
    void *field_14;
    void *field_18;
    HGDIOBJ bitmap;
    void *field_20;
    void *field_24;
    bool field_28;
    bool field_29;

    bool init(void);
};

extern HWND grim_main_window_hwnd;
extern int grim_backbuffer_width;
extern int grim_backbuffer_height;
extern char grim_working_dir[260];

union GrimClientRect {
    RECT rect;
    struct {
        bool enabled;
        unsigned char padding[3];
        LONG top;
        LONG right;
        LONG bottom;
    } state;
};

extern GrimClientRect grim_client_rect;

extern "C" void grim_noop(char *message, int value);

bool MyApp::init(void)
{
    grim_noop("MyApp::Init()\n", 0);

    active = false;
    last_tick_ms = -1;
    tick_remainder_ms = 0;
    bitmap = 0;
    field_24 = 0;
    field_29 = false;
    field_28 = false;
    field_14 = 0;

    GrimClientRect rect;
    GetClientRect(grim_main_window_hwnd, &rect.rect);
    width = rect.rect.right;
    height = rect.rect.bottom;
    width = grim_backbuffer_width;
    height = grim_backbuffer_height;

    memset(grim_working_dir, 0, sizeof(grim_working_dir));
    _getcwd(grim_working_dir, sizeof(grim_working_dir));

    rect.state.enabled = false;
    grim_client_rect = rect;
    return true;
}
