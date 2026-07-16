extern "C" int __fastcall grim_dxt_unpremultiply_rgba_block(float *rgba)
{
    int remaining = 16;
    do {
        if (0.0f == rgba[3]) {
            rgba[0] = 0.0f;
            rgba[1] = 0.0f;
            rgba[2] = 0.0f;
        } else if (1.0f > rgba[3]) {
            float inverse_alpha = 1.0f / rgba[3];
            rgba[0] = rgba[0] < rgba[3] ? rgba[0] * inverse_alpha : 1.0f;
            rgba[1] = rgba[1] < rgba[3] ? rgba[1] * inverse_alpha : 1.0f;
            rgba[2] = rgba[2] < rgba[3] ? rgba[2] * inverse_alpha : 1.0f;
        }
        rgba += 4;
    } while (--remaining != 0);
    return 0;
}
