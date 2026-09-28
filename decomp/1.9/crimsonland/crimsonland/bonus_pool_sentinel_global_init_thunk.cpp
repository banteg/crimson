extern "C" void bonus_pool_sentinel_global_init(void);

extern "C" void bonus_pool_sentinel_global_init_thunk(void)
{
    bonus_pool_sentinel_global_init();
}
