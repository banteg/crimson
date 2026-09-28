extern unsigned char grim_keyboard_state[256];

unsigned char grim_keyboard_key_down(unsigned char key)
{
    unsigned char result = grim_keyboard_state[key];
    result >>= 7;
    return result;
}
