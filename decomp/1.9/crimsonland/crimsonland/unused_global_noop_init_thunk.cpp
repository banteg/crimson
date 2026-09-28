extern "C" void unused_global_noop_init(void);

extern "C" void unused_global_noop_init_thunk(void)
{
    unused_global_noop_init();
}
