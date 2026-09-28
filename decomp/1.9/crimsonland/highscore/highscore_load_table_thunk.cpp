extern "C" void highscore_load_table(void);

extern "C" void highscore_load_table_thunk(void)
{
    highscore_load_table();
}
