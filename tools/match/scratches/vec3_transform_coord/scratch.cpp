#include <mm3dnow.h>

struct vec3_t {
    float x;
    float y;
    float z;
};

struct mat4_t {
    float m[4][4];
};

extern "C" vec3_t *__stdcall vec3_transform_coord(
    vec3_t *out, const vec3_t *vec, const mat4_t *mat)
{
    _m_femms();

    __m64 xy = *(__m64 *)&vec->x;
    __m64 x = _m_punpckldq(xy, xy);
    __m64 y = _m_punpckhdq(xy, xy);
    __m64 z = _m_from_int(*(const int *)&vec->z);
    z = _m_punpckldq(z, z);

    __m64 result_xy = _m_pfmul(x, *(__m64 *)&mat->m[0][0]);
    __m64 y_xy = _m_pfmul(y, *(__m64 *)&mat->m[1][0]);
    __m64 z_xy = _m_pfmul(z, *(__m64 *)&mat->m[2][0]);
    result_xy = _m_pfadd(result_xy, *(__m64 *)&mat->m[3][0]);

    __m64 result_zw = _m_pfmul(x, *(__m64 *)&mat->m[0][2]);
    y_xy = _m_pfadd(y_xy, z_xy);
    __m64 y_zw = _m_pfmul(y, *(__m64 *)&mat->m[1][2]);
    __m64 z_zw = _m_pfmul(z, *(__m64 *)&mat->m[2][2]);
    result_zw = _m_pfadd(result_zw, *(__m64 *)&mat->m[3][2]);
    result_xy = _m_pfadd(result_xy, y_xy);
    y_zw = _m_pfadd(y_zw, z_zw);
    result_zw = _m_pfadd(result_zw, y_zw);

    __m64 w = _m_punpckhdq(result_zw, result_zw);
    __m64 reciprocal = _m_pfrcp(w);
    w = _m_pfrcpit1(w, reciprocal);
    w = _m_pfrcpit2(w, reciprocal);

    result_xy = _m_pfmul(result_xy, w);
    result_zw = _m_pfmul(result_zw, w);
    *(__m64 *)&out->x = result_xy;
    *(int *)&out->z = _m_to_int(result_zw);

    _m_femms();
    return out;
}
