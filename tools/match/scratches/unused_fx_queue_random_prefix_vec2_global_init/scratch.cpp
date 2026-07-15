struct unused_vec2_t {
    float x;
    float y;
};

extern "C" unused_vec2_t unused_fx_queue_random_prefix_vec2;

extern "C" void unused_fx_queue_random_prefix_vec2_global_init(void)
{
    unused_fx_queue_random_prefix_vec2.x = 0.0f;
    unused_fx_queue_random_prefix_vec2.y = 0.0f;
}
