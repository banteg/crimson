struct rgba_t {
    float r;
    float g;
    float b;
    float a;
};

extern "C" rgba_t unused_fx_rotated_scale_prefix_color;

extern "C" void unused_fx_rotated_scale_prefix_color_global_init(void)
{
    unused_fx_rotated_scale_prefix_color.r = 0.5f;
    unused_fx_rotated_scale_prefix_color.g = 0.5f;
    unused_fx_rotated_scale_prefix_color.b = 0.5f;
    unused_fx_rotated_scale_prefix_color.a = 1.0f;
}
