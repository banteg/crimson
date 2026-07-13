int vec2_add(float *dst, float *delta)
{
    dst[0] = dst[0] + delta[0];
    dst[1] = delta[1] + dst[1];
    return 0;
}
