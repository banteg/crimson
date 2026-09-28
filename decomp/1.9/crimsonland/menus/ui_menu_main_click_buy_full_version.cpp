#include <windows.h>
#include <shellapi.h>

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
