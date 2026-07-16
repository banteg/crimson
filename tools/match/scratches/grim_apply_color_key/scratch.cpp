class grim_pixel_format_t {
public:
    virtual ~grim_pixel_format_t();
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

void grim_pixel_format_t::apply_color_key(float *pixels)
{
    float *begin = pixels;
    float *end = begin + width * 4;
    if (begin < end) {
        float *channel = begin + 2;
        unsigned int remaining =
            ((unsigned char *)end - (unsigned char *)begin - 1)
                / (sizeof(float) * 4)
            + 1;
        do {
            if (channel[-2] == color_key[0]
                && channel[-1] == color_key[1]
                && channel[0] == color_key[2]
                && channel[1] == color_key[3]) {
                channel[1] = 0.0f;
                channel[0] = 0.0f;
                channel[-1] = 0.0f;
                channel[-2] = 0.0f;
            }
            channel += 4;
        } while (--remaining != 0);
    }
}
