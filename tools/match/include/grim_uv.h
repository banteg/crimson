#ifndef GRIM_UV_H
#define GRIM_UV_H

// Shared with the recovered state initializer; two floats per atlas coordinate.
struct GrimUV {
    float u;
    float v;

    GrimUV() {}
    GrimUV(float u_value, float v_value) : u(u_value), v(v_value) {}
};

#endif
