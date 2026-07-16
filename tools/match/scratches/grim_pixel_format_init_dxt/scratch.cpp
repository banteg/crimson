typedef int (__cdecl *grim_dxt_codec_t)(void *block, float *pixels);

extern "C" int grim_dxt1_encode_block(void *block, float *pixels);
extern "C" int grim_dxt1_decode_color_block(void *block, float *pixels);
extern "C" int grim_dxt2_encode_block(void *block, float *pixels);
extern "C" int grim_dxt2_decode_block(void *block, float *pixels);
extern "C" int grim_dxt3_encode_block(void *block, float *pixels);
extern "C" int grim_dxt3_decode_block(void *block, float *pixels);
extern "C" int grim_dxt4_encode_block(void *block, float *pixels);
extern "C" int grim_dxt4_decode_block(void *block, float *pixels);
extern "C" int grim_dxt5_encode_block(void *block, float *pixels);
extern "C" int grim_dxt5_decode_block(void *block, float *pixels);

class grim_pixel_format_base_t {
public:
    virtual void placeholder(void);

    grim_pixel_format_base_t(
        unsigned int *desc,
        unsigned int bits_per_pixel,
        unsigned int coord_mode);

protected:
    unsigned int format;
    unsigned char fields_08[0x1028];
    unsigned int left;
    unsigned int top;
    unsigned int right;
    unsigned int bottom;
    unsigned int depth_first;
    unsigned int depth_last;
    unsigned char fields_1048[0x2c];
};

class grim_pixel_format_dxt_t : public grim_pixel_format_base_t {
public:
    virtual void placeholder(void);

    grim_pixel_format_dxt_t(unsigned int *desc);

private:
    unsigned int has_partial_blocks;
    unsigned int x_mask;
    unsigned int y_mask;
    unsigned int block_bytes;
    grim_dxt_codec_t decode_block;
    grim_dxt_codec_t encode_block;
    unsigned int aligned_left;
    unsigned int aligned_top;
    unsigned int aligned_right;
    unsigned int aligned_bottom;
    unsigned int cache_depth_first;
    unsigned int cache_depth_last;
    unsigned int block_width;
    unsigned int block_height;
    unsigned int cache_depth_count;
    int cached_x;
    int cached_y;
    void *cache_rows;
    unsigned int cache_row_count;
    void *cache_entries;
};

grim_pixel_format_dxt_t::grim_pixel_format_dxt_t(unsigned int *desc)
    : grim_pixel_format_base_t(desc, 0, 1)
{
    switch (desc[6]) {
    case 1:
        x_mask = 0;
        break;
    case 2:
        x_mask = 1;
        break;
    default:
        x_mask = 3;
        break;
    }

    switch (desc[7]) {
    case 1:
        y_mask = 0;
        break;
    case 2:
        y_mask = 1;
        break;
    default:
        y_mask = 3;
        break;
    }

    unsigned int partial_blocks;
    if (x_mask == 3 && y_mask == 3) {
        partial_blocks = 0;
    } else {
        partial_blocks = 1;
    }
    has_partial_blocks = partial_blocks;

    switch (format) {
    case 0x31545844:
        block_bytes = 8;
        encode_block = grim_dxt1_encode_block;
        decode_block = grim_dxt1_decode_color_block;
        break;
    case 0x32545844:
        block_bytes = 16;
        encode_block = grim_dxt2_encode_block;
        decode_block = grim_dxt2_decode_block;
        break;
    case 0x33545844:
        block_bytes = 16;
        encode_block = grim_dxt3_encode_block;
        decode_block = grim_dxt3_decode_block;
        break;
    case 0x34545844:
        block_bytes = 16;
        encode_block = grim_dxt4_encode_block;
        decode_block = grim_dxt4_decode_block;
        break;
    case 0x35545844:
        block_bytes = 16;
        encode_block = grim_dxt5_encode_block;
        decode_block = grim_dxt5_decode_block;
        break;
    }

    cached_x = -1;
    cached_y = -1;
    cache_depth_first = depth_first;
    aligned_right = (right + 3) & ~3u;
    aligned_left = left & ~3u;
    aligned_top = top & ~3u;
    aligned_bottom = (bottom + 3) & ~3u;
    cache_depth_last = depth_last;
    block_width = (aligned_right - aligned_left) >> 2;
    block_height = (aligned_bottom - aligned_top) >> 2;
    cache_depth_count = cache_depth_last - cache_depth_first;
    cache_rows = 0;
    cache_row_count = 0;
    cache_entries = 0;
}
