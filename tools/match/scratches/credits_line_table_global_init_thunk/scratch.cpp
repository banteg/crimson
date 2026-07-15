extern "C" void credits_line_table_global_init(void);

extern "C" void credits_line_table_global_init_thunk(void)
{
    credits_line_table_global_init();
}
