struct vec2_t {
    float x;
    float y;

    float *vec2_add_out(float *dst, float *rhs);
};

float *vec2_t::vec2_add_out(float *dst, float *rhs)
{
    float y = rhs[1] + this->y;
    dst[0] = rhs[0] + this->x;
    dst[1] = y;
    return dst;
}
