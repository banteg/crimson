extern "C" void perk_meta_table_init(void);
extern "C" void perk_meta_register_atexit(void);

extern "C" void perk_meta_global_construct_and_register(void)
{
    perk_meta_table_init();
    perk_meta_register_atexit();
}
