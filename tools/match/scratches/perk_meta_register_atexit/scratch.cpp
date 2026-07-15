extern "C" int crt_atexit(void (*callback)(void));
extern "C" void perk_meta_table_destroy(void);

extern "C" void perk_meta_register_atexit(void)
{
    crt_atexit(perk_meta_table_destroy);
}
