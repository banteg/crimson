extern unsigned char grim_mouse_buttons[8];

unsigned char grim_mouse_button_down(int button)
{
    unsigned char result = grim_mouse_buttons[button];
    result >>= 7;
    return result;
}
