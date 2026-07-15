extern "C" void ui_element_globals_init(void);

extern "C" void ui_element_globals_init_thunk(void)
{
    ui_element_globals_init();
}
