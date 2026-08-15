extern unsigned char grim_keyboard_state[256];

unsigned char grim_keyboard_key_down(unsigned int key)
{
    unsigned char result = grim_keyboard_state[(unsigned char)key];
    result >>= 7;
    return result;
}
