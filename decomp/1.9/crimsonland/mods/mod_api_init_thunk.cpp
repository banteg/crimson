extern "C" void mod_api_init(void);

extern "C" void mod_api_init_thunk(void)
{
    mod_api_init();
}
