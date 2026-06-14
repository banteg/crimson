extern "C" char console_input_buf[];
extern "C" int console_input_cursor;
extern "C" unsigned char console_input_ready;

extern "C" void console_input_clear(void)
{
    console_input_ready = 0;
    console_input_cursor = 0;
    console_input_buf[0] = 0;
}
