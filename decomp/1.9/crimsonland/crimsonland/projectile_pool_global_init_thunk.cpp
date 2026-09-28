extern "C" void projectile_pool_global_init(void);

extern "C" void projectile_pool_global_init_thunk(void)
{
    projectile_pool_global_init();
}
