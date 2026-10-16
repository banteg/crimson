#ifndef REFLEXIVE_ARCADE_H
#define REFLEXIVE_ARCADE_H

#include <windows.h>

// Reflexive Arcade client API statically linked into the 1.9.8 grim.dll.
// Each entry forwards to the matching `radll_*` export of
// ReflexiveArcade.dll; the library's own error text names RA_Initialize.
extern "C" {
unsigned short RA_Initialize(
    int application_id,
    char *application_name,
    int version,
    float price,
    unsigned short flags);
void RA_ShutDown(void);
bool RA_HasTheProductBeenPurchased(void);
void RA_DrawNextFrameIntoBuffer(
    void *buffer, int pitch, int pixel_format, int first_frame);
bool RA_IsTheMenuSessionComplete(void);
bool RA_HandleWindowsMessage(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
int RA_GetValueAsInt(char *name, int default_value);
}

#endif
