void *__cdecl operator new(unsigned int size);

extern "C" int zlib_uncompress(
    unsigned char *output,
    unsigned long *output_size,
    const unsigned char *source,
    unsigned long source_size);
extern "C" bool grim_zlib_status_is_error(int status);

struct GrimJazDecodeScope {
    bool decompress_alloc(
        unsigned char **output,
        unsigned int output_size,
        const unsigned char *source,
        unsigned int source_size);
};

bool GrimJazDecodeScope::decompress_alloc(
    unsigned char **output,
    unsigned int output_size,
    const unsigned char *source,
    unsigned int source_size)
{
    unsigned char *buffer = (unsigned char *)operator new(output_size);
    unsigned long available_size = output_size;
    *output = buffer;
    if (grim_zlib_status_is_error(
            zlib_uncompress(buffer, &available_size, source, source_size))) {
        return false;
    }
    return true;
}
