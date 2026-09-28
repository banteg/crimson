extern "C" void fx_queue_global_init(void);

extern "C" void fx_queue_global_init_thunk(void)
{
    fx_queue_global_init();
}
