#include <math.h>

#include "grim2d_cpp.h"

extern float grim_rotation_radians;
extern float grim_rotation_cos;
extern float grim_rotation_sin;
extern float grim_rotation_m00;
extern float grim_rotation_m01;
extern float grim_rotation_m10;
extern float grim_rotation_m11;

void IGrim2D_cpp::grim_set_rotation(float radians)
{
    grim_rotation_radians = radians;
    grim_rotation_cos = (float)cos(radians + 0.7853982f);
    grim_rotation_sin = (float)sin(radians + 0.7853982f);
    grim_rotation_m00 = grim_rotation_cos;
    grim_rotation_m01 = grim_rotation_sin;
    grim_rotation_m10 = -grim_rotation_sin;
    grim_rotation_m11 = grim_rotation_cos;
}
