struct GrimJazDecodeScope {
    bool decompress_alloc(
        unsigned char **output,
        unsigned int output_size,
        const unsigned char *source,
        unsigned int source_size);
    unsigned char *unpack(
        unsigned char *source,
        unsigned int *output_size);
};

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
