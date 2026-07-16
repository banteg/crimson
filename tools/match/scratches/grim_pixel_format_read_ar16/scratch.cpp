class grim_pixel_format_ar16_t {
public:
    virtual ~grim_pixel_format_ar16_t();
    virtual void read_pixel(unsigned int row, unsigned int depth, float *pixels);
    virtual void write_pixel(unsigned int row, unsigned int depth, float *pixels);
    virtual void quantize_color_key();

protected:
    void apply_color_key(float *pixels);

    unsigned int format;
    unsigned int coordinate_mode;
    unsigned int has_pixel_buffer;
    unsigned int color_key_enabled;
    unsigned int field_14;
    unsigned char *pixel_buffer;
    float color_key[4];
    float *dither_pattern;
    unsigned char palette[0x1000];
    unsigned int left;
    unsigned int top;
    unsigned int right;
    unsigned int bottom;
    unsigned int depth_first;
    unsigned int depth_last;
    unsigned int conversion_mode;
    float *conversion_source;
    unsigned int row_offset;
    unsigned int depth_offset;
    unsigned int width;
};

void grim_pixel_format_ar16_t::read_pixel(
    unsigned int row,
    unsigned int depth,
    float *pixels)
{
    unsigned __int64 *source =
        (unsigned __int64 *)(pixel_buffer + row_offset * row + depth_offset * depth);
    unsigned __int64 *end = source + width;
    const float scale = 1.0f / 65535.0f;
    while (source < end) {
        pixels[0] = (float)((unsigned int)(*source >> 32) & 0xffff) * scale;
        pixels[1] = (float)((unsigned int)(*source >> 16) & 0xffff) * scale;
        pixels[2] = (float)((unsigned int)*source & 0xffff) * scale;
        pixels[3] = (float)(*source++ >> 48) * scale;
        pixels += 4;
    }

    if (color_key_enabled != 0) {
        apply_color_key(pixels - width * 4);
    }
}
