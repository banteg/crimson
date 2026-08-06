extern "C" __declspec(noreturn) void __cdecl longjmp(
    void *jump_buffer, int value);
extern "C" void __cdecl free(void *allocation);
extern "C" void __cdecl png_free(void *png, void *allocation);
extern "C" void *__cdecl memset(void *destination, int value, unsigned int size);

extern "C" __declspec(noreturn) void grim_png_error_longjmp(
    void *jump_buffer, const char *)
{
    longjmp(jump_buffer, 1);
}

extern "C" void grim_png_free_thunk(void *png, void *allocation)
{
    png_free(png, allocation);
}

extern "C" void grim_png_free_ptr(void *allocation)
{
    if (allocation == 0) {
        return;
    }
    free(allocation);
}

extern "C" void grim_png_info_clear(void *, void *info)
{
    memset(info, 0, 0x40);
}
