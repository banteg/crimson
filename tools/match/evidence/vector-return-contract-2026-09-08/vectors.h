struct explicit_vec2_t {
    float x, y;
    float *sub(float *dst, float *rhs);
    float *add(float *dst, float *rhs);
};
struct value_vec2_t {
    float x, y;
    value_vec2_t() {}
    value_vec2_t(float a, float b): x(a), y(b) {}
    value_vec2_t operator-(const value_vec2_t &rhs) const;
    value_vec2_t operator+(const value_vec2_t &rhs) const;
};
