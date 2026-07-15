extern "C" void secondary_projectile_pool_global_init(void);

extern "C" void secondary_projectile_pool_global_init_thunk(void)
{
    secondary_projectile_pool_global_init();
}
