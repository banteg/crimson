extern "C" void *__cdecl calloc(unsigned int count, unsigned int size);
extern "C" void __cdecl free(void *allocation);

extern "C" void *grim_zcalloc(
    void *, unsigned int item_count, unsigned int item_size)
{
    return calloc(item_count, item_size);
}

extern "C" void grim_zcfree(void *, void *allocation)
{
    free(allocation);
}
