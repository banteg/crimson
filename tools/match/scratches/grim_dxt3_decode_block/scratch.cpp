extern "C" int grim_dxt1_decode_color_block(float *rgba, unsigned short *block);

extern "C" int grim_dxt3_decode_block(float *rgba, unsigned int *block)
{
    int result = grim_dxt1_decode_color_block(rgba, (unsigned short *)block + 4);
    if (result >= 0) {
        unsigned int alpha_bits = block[0];
        int remaining = 8;
        float *alpha = rgba + 3;
        do {
            *alpha = (float)(alpha_bits & 0x0f) * (1.0f / 15.0f);
            alpha_bits >>= 4;
            alpha += 4;
        } while (--remaining != 0);

        alpha_bits = block[1];
        remaining = 8;
        alpha = rgba + 35;
        do {
            *alpha = (float)(alpha_bits & 0x0f) * (1.0f / 15.0f);
            alpha_bits >>= 4;
            alpha += 4;
        } while (--remaining != 0);
        return 0;
    }
    return result;
}
