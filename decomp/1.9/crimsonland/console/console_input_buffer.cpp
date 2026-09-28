extern "C" char console_input_buf[];

extern "C" char *console_input_buffer(void)
{
    return console_input_buf;
}
