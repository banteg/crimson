extern "C" void creature_pool_global_init(void);

extern "C" void creature_pool_global_init_thunk(void)
{
    creature_pool_global_init();
}
