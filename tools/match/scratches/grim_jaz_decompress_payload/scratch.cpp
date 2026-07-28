void *__cdecl operator new(unsigned int size);

extern "C" int zlib_uncompress(
    unsigned char *output,
    unsigned long *output_size,
    const unsigned char *source,
    unsigned long source_size);

struct GrimJazDecodeScope {
    GrimJazDecodeScope();
    bool decompress_alloc(
        unsigned char **output,
        unsigned int output_size,
        const unsigned char *source,
        unsigned int source_size);
    unsigned char *unpack(
        unsigned char *source,
        unsigned int *output_size);
};

GrimJazDecodeScope::GrimJazDecodeScope()
{
}

extern "C" bool grim_zlib_status_is_error(int status)
{
    bool is_error;
    switch (status) {
    case 0:
        is_error = false;
        break;
    case 1:
        is_error = false;
        break;
    case 2:
        is_error = false;
        break;
    default:
        is_error = true;
        break;
    }
    return is_error;
}

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

unsigned char *GrimJazDecodeScope::unpack(
    unsigned char *source,
    unsigned int *output_size)
{
    unsigned char version = *source++;
    if (version != 1) {
        return 0;
    }

    unsigned int compressed_size = *(unsigned int *)source;
    source += sizeof(compressed_size);
    unsigned int unpacked_size = *(unsigned int *)source;
    source += sizeof(unpacked_size);

    *output_size = unpacked_size;
    unsigned char *output = 0;
    decompress_alloc(
        &output,
        unpacked_size,
        source,
        compressed_size);
    return output;
}
