struct rgba_t {
    float r;
    float g;
    float b;
    float a;
};

extern "C" rgba_t unused_aim64_prefix_color;

extern "C" void unused_aim64_prefix_color_global_init(void)
{
    unused_aim64_prefix_color.r = 0.0f;
    unused_aim64_prefix_color.g = 0.0f;
    unused_aim64_prefix_color.b = 0.0f;
    unused_aim64_prefix_color.a = 1.0f;
}
