extern "C" unsigned __int64 dx_version_pack_4x16(
    unsigned short major,
    unsigned short minor,
    unsigned short patch_major,
    unsigned short patch_minor)
{
    union packed_version_t {
        unsigned __int64 value;
        struct {
            unsigned int ls;
            unsigned int ms;
        } words;
    } result;

    result.words.ms = (major << 16) | minor;
    result.words.ls = (patch_major << 16) | patch_minor;
    return result.value;
}
