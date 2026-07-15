extern "C" int crt_atexit(void (*callback)(void));
extern "C" void quest_meta_table_destroy(void);

extern "C" void quest_meta_register_atexit(void)
{
    crt_atexit(quest_meta_table_destroy);
}
