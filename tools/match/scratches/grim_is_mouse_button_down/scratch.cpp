extern "C" unsigned char grim_input_cached;
extern "C" unsigned char grim_mouse_button_cache[];

extern "C" unsigned char grim_mouse_button_down(int button);

extern "C" unsigned char __stdcall grim_is_mouse_button_down(int button)
{
    if (grim_input_cached) {
        return grim_mouse_button_cache[button];
    }
    return grim_mouse_button_down(button);
}
