struct unused_vec2_t {
    float x;
    float y;
};

extern "C" unused_vec2_t unused_effect_uv16_prefix_vec2;

extern "C" void unused_effect_uv16_prefix_vec2_global_init(void)
{
    unused_effect_uv16_prefix_vec2.x = 0.0f;
    unused_effect_uv16_prefix_vec2.y = 0.0f;
}
