#include "vectors.h"
extern "C" float consume(float *pair);
extern "C" float explicit_caller(explicit_vec2_t *self, explicit_vec2_t *rhs) {
    explicit_vec2_t result;
    return consume(self->sub((float *)&result,(float *)rhs));
}
extern "C" float value_caller(value_vec2_t *self, value_vec2_t *rhs) {
    value_vec2_t result=*self-*rhs;
    return consume((float *)&result);
}

#include <math.h>
inline float value_angle(const value_vec2_t &v) {
    return (float)atan2(v.y,v.x);
}
inline float pointer_angle(const float *v) {
    return (float)atan2(v[1],v[0]);
}
extern "C" float value_expression_angle(value_vec2_t *self, value_vec2_t *rhs) {
    return value_angle(*self-*rhs);
}
extern "C" float explicit_expression_angle(explicit_vec2_t *self, explicit_vec2_t *rhs) {
    explicit_vec2_t result;
    return pointer_angle(self->sub((float *)&result,(float *)rhs));
}
inline float consume_value(const value_vec2_t &v) {
    return consume((float *)&v);
}
extern "C" float value_expression_consume(value_vec2_t *self, value_vec2_t *rhs) {
    return consume_value(*self-*rhs);
}
