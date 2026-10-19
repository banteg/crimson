#include <windows.h>

#include "crimsonland_console.h"

extern "C" int console_cmd_argc_get(void);
extern "C" HRESULT WINAPI HlinkNavigateString(
    IUnknown *unknown,
    LPCWSTR target);

extern "C" void console_cmd_open_url(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(&console_log_queue, "openurl <url>\n");
        return;
    }

    WCHAR target[260];
    MultiByteToWideChar(
        0,
        0,
        console_cmd_arg_get(1),
        -1,
        target,
        260);
    if (HlinkNavigateString(0, target) < 0) {
        console_printf(
            &console_log_queue,
            "Failed to launch web browser.\n");
        return;
    }

    console_printf(
        &console_log_queue,
        "Launching web browser (%s)..\n",
        console_cmd_arg_get(1));
}
