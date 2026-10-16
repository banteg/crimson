#include "cl_build.h"

#if CL_BUILD == 10908
#include <windows.h>

#include "grim2d_cpp.h"
#include "reflexive_arcade.h"
#endif

class MyApp {
public:
#if CL_BUILD == 10908
    unsigned char reserved_00[0x20];
    int menu_pitch;
    void *menu_bits;
    bool menu_session_active;
    bool menu_session_started;
#endif

    bool tick(void);
    void on_tick(void);
    void cleanup(void);
    void pump(void);
};

extern MyApp grim_app;

#if CL_BUILD == 10908
extern unsigned char grim_input_cached;
extern unsigned char grim_timing_frozen;
extern bool grim_dc_mode_active;
extern grim_config_value_t grim_config_values[128];

HRESULT grim_try_reset_device(void);
#endif

void MyApp::pump(void)
{
    if (tick()) {
#if CL_BUILD == 10908
        // 1.9.8 draws the Reflexive Arcade menu into the app bitmap until the
        // session ends, then resets the device and drops the bitmap.
        if (menu_session_active) {
            int first_frame = 1;
            if (menu_session_started) {
                menu_session_started = false;
                first_frame = 0;
            }
            RA_DrawNextFrameIntoBuffer(menu_bits, menu_pitch, 3, first_frame);
            if (RA_IsTheMenuSessionComplete()) {
                if (grim_input_cached) {
                    ShowCursor(FALSE);
                }
                void (*on_device_restore)(void) =
                    (void (*)(void))grim_config_values[6].words[3];
                if (on_device_restore != 0) {
                    on_device_restore();
                }
                grim_timing_frozen = 0;
                grim_dc_mode_active = false;
                menu_session_active = false;
                grim_try_reset_device();
                grim_app.cleanup();
                return;
            }
        }
#endif
        grim_app.on_tick();
    }
}
