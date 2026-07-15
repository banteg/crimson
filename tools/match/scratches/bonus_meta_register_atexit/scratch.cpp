extern "C" int crt_atexit(void (*callback)(void));
extern "C" void bonus_meta_table_destroy(void);

extern "C" void bonus_meta_register_atexit(void)
{
    crt_atexit(bonus_meta_table_destroy);
}
