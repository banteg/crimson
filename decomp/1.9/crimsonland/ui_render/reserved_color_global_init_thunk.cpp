extern "C" void reserved_color_global_init(void);

extern "C" void reserved_color_global_init_thunk(void)
{
    reserved_color_global_init();
}
