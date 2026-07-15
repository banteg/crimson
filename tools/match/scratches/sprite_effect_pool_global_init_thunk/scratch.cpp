extern "C" void sprite_effect_pool_global_init(void);

extern "C" void sprite_effect_pool_global_init_thunk(void)
{
    sprite_effect_pool_global_init();
}
