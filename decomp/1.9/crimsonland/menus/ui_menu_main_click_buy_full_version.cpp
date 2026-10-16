#include <windows.h>
#include <shellapi.h>

#include "cl_build.h"

#if CL_BUILD == 10908
// 1.9.8 only raises a request; the frame loop opens Reflexive Arcade's
// purchase dialog through Grim.
extern "C" unsigned char full_version_recheck_pending_slot_1;

extern "C" void ui_menu_main_click_buy_full_version(void)
{
    full_version_recheck_pending_slot_1 = 1;
}
#else
extern "C" unsigned char quit_requested;
extern "C" unsigned char shareware_offer_seen_latch;

extern "C" void ui_menu_main_click_buy_full_version(void)
{
    quit_requested = 1;
    shareware_offer_seen_latch = 1;
    ShellExecuteA(
        0,
        "open",
        "http://buy.crimsonland.com",
        0,
        0,
        SW_SHOWNORMAL);
}
#endif
