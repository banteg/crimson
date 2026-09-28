extern "C" void terrain_generate_random(void);

extern "C" void console_cmd_generate_terrain(void)
{
    terrain_generate_random();
}
