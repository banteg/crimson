#include "grim2d_cpp.h"

struct GrimLineVector {
    float x;
    float y;

    ~GrimLineVector() {}
};

extern "C" GrimLineVector *__stdcall D3DXVec2Normalize(
    GrimLineVector *out, GrimLineVector *input);

void IGrim2D_cpp::grim_draw_line(float *p0, float *p1, float thickness)
{
    static GrimLineVector half_vector;

    half_vector.x = p1[0] - p0[0];
    half_vector.y = p1[1] - p0[1];
    D3DXVec2Normalize(&half_vector, &half_vector);
    half_vector.x = half_vector.y * thickness;
    half_vector.y = half_vector.x * thickness;
    grim_draw_line_quad(p0, p1, &half_vector.x);
}

void IGrim2D_cpp::grim_draw_line_quad(
    float *p0, float *p1, float *half_vector)
{
    grim_draw_quad_points(
        p0[0] - half_vector[0],
        p0[1] - half_vector[1],
        p0[0] + half_vector[0],
        p0[1] + half_vector[1],
        p1[0] + half_vector[0],
        p1[1] + half_vector[1],
        p1[0] - half_vector[0],
        p1[1] - half_vector[1]);
}
