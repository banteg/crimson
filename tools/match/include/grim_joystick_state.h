#ifndef GRIM_JOYSTICK_STATE_H
#define GRIM_JOYSTICK_STATE_H

// DIJOYSTATE2 prefix through the POV and button fields used by Grim2D.
struct GrimJoystickState {
    long lX;
    long lY;
    long lZ;
    long lRx;
    long lRy;
    long lRz;
    long rglSlider[2];
    unsigned long rgdwPOV[4];
    unsigned char rgbButtons[128];
};

extern GrimJoystickState grim_joystick_state;

#endif
