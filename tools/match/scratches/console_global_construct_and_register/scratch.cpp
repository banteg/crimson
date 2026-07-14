extern "C" void console_global_init(void);
extern "C" void console_register_global_destructor_atexit(void);

extern "C" void console_global_construct_and_register(void)
{
    console_global_init();
    console_register_global_destructor_atexit();
}
