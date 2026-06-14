extern "C" float grim_mouse_x_cached;

extern "C" float grim_get_mouse_x(void)
{
    return grim_mouse_x_cached;
}
