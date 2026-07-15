extern "C" void bonus_meta_table_init(void);
extern "C" void bonus_meta_register_atexit(void);

extern "C" void bonus_meta_global_construct_and_register(void)
{
    bonus_meta_table_init();
    bonus_meta_register_atexit();
}
