struct grim_dxt_cache_entry_t {
    unsigned int rows_present;
    unsigned char *pixels;
};

class grim_pixel_format_base_t {
public:
    virtual ~grim_pixel_format_base_t();

protected:
    unsigned char fields[0x1068];
};

class grim_pixel_format_dxt_t : public grim_pixel_format_base_t {
public:
    virtual ~grim_pixel_format_dxt_t();

private:
    float alpha_max;
    float alpha_scale;
    unsigned int has_partial_blocks;
    unsigned int x_mask;
    unsigned int y_mask;
    unsigned int block_bytes;
    void *decode_block;
    void *encode_block;
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
    unsigned char *cache_rows;
    unsigned int cache_row_count;
    grim_dxt_cache_entry_t *cache_entries;
};

grim_pixel_format_dxt_t::~grim_pixel_format_dxt_t()
{
    if (cache_row_count != 0 && cache_entries != 0) {
        grim_dxt_cache_entry_t *entry = cache_entries;
        for (unsigned int depth = cache_depth_first;
             depth < cache_depth_last;
             ++depth) {
            for (unsigned int y = aligned_top;
                 y < aligned_bottom;
                 ++entry, y += 4) {
                delete[] entry->pixels;
            }
        }
    }

    delete[] cache_rows;
    delete[] cache_entries;
}
