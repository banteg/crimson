extern "C" int crt_atexit(void (*callback)(void));
extern "C" void console_global_destroy(void);

extern "C" void console_register_global_destructor_atexit(void)
{
    crt_atexit(console_global_destroy);
}
