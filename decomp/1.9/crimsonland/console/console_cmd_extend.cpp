extern "C" float screen_height_f;
extern "C" int console_height_px;

extern "C" void console_cmd_extend(void)
{
    console_height_px = (int)screen_height_f;
}
