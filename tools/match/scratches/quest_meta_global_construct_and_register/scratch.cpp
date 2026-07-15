extern "C" void quest_meta_init(void);
extern "C" void quest_meta_register_atexit(void);

extern "C" void quest_meta_global_construct_and_register(void)
{
    quest_meta_init();
    quest_meta_register_atexit();
}
