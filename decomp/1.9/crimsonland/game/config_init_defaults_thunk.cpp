extern "C" void config_init_defaults(void);

extern "C" void config_init_defaults_thunk(void)
{
    config_init_defaults();
}
