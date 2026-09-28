extern "C" int gameplay_run_state_init(void);

extern "C" int gameplay_run_state_init_thunk(void)
{
    return gameplay_run_state_init();
}
