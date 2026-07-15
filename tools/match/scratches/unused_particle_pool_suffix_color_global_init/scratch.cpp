struct rgba_t {
    float r;
    float g;
    float b;
    float a;
};

extern "C" rgba_t unused_particle_pool_suffix_color;

extern "C" void unused_particle_pool_suffix_color_global_init(void)
{
    unused_particle_pool_suffix_color.r = 0.6f;
    unused_particle_pool_suffix_color.g = 0.6f;
    unused_particle_pool_suffix_color.b = 0.6f;
    unused_particle_pool_suffix_color.a = 0.5f;
}
