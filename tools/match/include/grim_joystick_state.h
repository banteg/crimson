#ifndef GRIM_JOYSTICK_STATE_H
#define GRIM_JOYSTICK_STATE_H

// Full DirectInput DIJOYSTATE2 layout used by Grim2D.
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
    long lVX;
    long lVY;
    long lVZ;
    long lVRx;
    long lVRy;
    long lVRz;
    long rglVSlider[2];
    long lAX;
    long lAY;
    long lAZ;
    long lARx;
    long lARy;
    long lARz;
    long rglASlider[2];
    long lFX;
    long lFY;
    long lFZ;
    long lFRx;
    long lFRy;
    long lFRz;
    long rglFSlider[2];
};

extern GrimJoystickState grim_joystick_state;

#endif
