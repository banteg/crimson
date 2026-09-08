#include "vectors.h"
float *explicit_vec2_t::sub(float *dst, float *rhs) {
    explicit_vec2_t *d=(explicit_vec2_t *)dst;
    const explicit_vec2_t *r=(const explicit_vec2_t *)rhs;
    float y=this->y-r->y; d->x=this->x-r->x; d->y=y; return dst;
}
float *explicit_vec2_t::add(float *dst, float *rhs) {
    explicit_vec2_t *d=(explicit_vec2_t *)dst;
    const explicit_vec2_t *r=(const explicit_vec2_t *)rhs;
    float y=r->y+this->y; d->x=r->x+this->x; d->y=y; return dst;
}
value_vec2_t value_vec2_t::operator-(const value_vec2_t &rhs) const {
    return value_vec2_t(x-rhs.x,y-rhs.y);
}
value_vec2_t value_vec2_t::operator+(const value_vec2_t &rhs) const {
    return value_vec2_t(rhs.x+x,rhs.y+y);
}
