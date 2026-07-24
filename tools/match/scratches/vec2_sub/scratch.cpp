struct vec2_t {
    float x;
    float y;

    float *vec2_sub(float *dst, float *rhs);
};

float *vec2_t::vec2_sub(float *dst, float *rhs)
{
    vec2_t *dst_vec = (vec2_t *)dst;
    const vec2_t *rhs_vec = (const vec2_t *)rhs;
    float y = this->y - rhs_vec->y;
    dst_vec->x = this->x - rhs_vec->x;
    dst_vec->y = y;
    return dst;
}
