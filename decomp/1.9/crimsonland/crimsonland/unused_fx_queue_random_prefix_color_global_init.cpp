struct rgba_t {
    float r;
    float g;
    float b;
    float a;
};

extern "C" rgba_t unused_fx_queue_random_prefix_color;

extern "C" void unused_fx_queue_random_prefix_color_global_init(void)
{
    unused_fx_queue_random_prefix_color.r = 1.0f;
    unused_fx_queue_random_prefix_color.g = 1.0f;
    unused_fx_queue_random_prefix_color.b = 1.0f;
    unused_fx_queue_random_prefix_color.a = 1.0f;
}
