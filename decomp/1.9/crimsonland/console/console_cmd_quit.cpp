extern "C" unsigned char quit_requested;

extern "C" void console_cmd_quit(void)
{
    quit_requested = 1;
}
