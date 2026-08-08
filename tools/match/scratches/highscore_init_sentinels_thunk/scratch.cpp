extern "C" int highscore_init_sentinels(void);

extern "C" int highscore_init_sentinels_thunk(void)
{
    return highscore_init_sentinels();
}
