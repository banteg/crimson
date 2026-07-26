extern "C" unsigned char grim_input_cached;
extern "C" float grim_mouse_wheel_delta;
extern "C" float grim_mouse_wheel_delta_cached;

extern "C" float grim_get_mouse_wheel_delta(void)
{
    if (grim_input_cached) {
        return grim_mouse_wheel_delta_cached;
    }
    return grim_mouse_wheel_delta;
}
