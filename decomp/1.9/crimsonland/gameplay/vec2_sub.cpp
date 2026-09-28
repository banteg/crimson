struct vec2_t {
    float x;
    float y;

    vec2_t() {}
    vec2_t(float _x, float _y) { x = _x; y = _y; }

    vec2_t vec2_sub(const vec2_t &v);
};

vec2_t vec2_t::vec2_sub(const vec2_t &v)
{
    return vec2_t(x - v.x, y - v.y);
}
