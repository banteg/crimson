extern "C" int console_height_px;

extern "C" void console_cmd_minimize(void)
{
    console_height_px = 300;
}
