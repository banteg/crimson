extern "C" void particle_pool_global_init(void);

extern "C" void particle_pool_global_init_thunk(void)
{
    particle_pool_global_init();
}
