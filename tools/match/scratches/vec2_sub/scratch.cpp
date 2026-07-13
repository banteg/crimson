struct vec2_t {
    float x;
    float y;

    float *vec2_sub(float *dst, float *rhs);
};

float *vec2_t::vec2_sub(float *dst, float *rhs)
{
    float y = this->y - rhs[1];
    dst[0] = this->x - rhs[0];
    dst[1] = y;
    return dst;
}
