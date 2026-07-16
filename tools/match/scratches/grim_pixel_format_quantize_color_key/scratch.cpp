extern "C" float grim_dither_half_pattern[32];

class grim_pixel_format_t {
public:
    virtual ~grim_pixel_format_t();
    virtual void read_pixel(unsigned int x, unsigned int y, float *rgba);
    virtual void write_pixel(unsigned int x, unsigned int y, float *rgba);
    virtual void quantize_color_key();

protected:
    float *convert_vertex_space(float *source);

    unsigned int format;
    unsigned int coordinate_mode;
    unsigned int has_pixel_buffer;
    unsigned int pixel_offset;
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
    unsigned int bytes_per_row;
    unsigned int bytes_per_pixel;
    unsigned int width;
    unsigned int height;
    unsigned int depth;
    unsigned int row_pitch;
    unsigned int slice_pitch;
};

void grim_pixel_format_t::quantize_color_key()
{
    unsigned int saved_width = width;
    unsigned int saved_row_pitch = row_pitch;
    unsigned char *saved_pixel_buffer = pixel_buffer;
    float *saved_dither_pattern = dither_pattern;
    unsigned int saved_pixel_offset = pixel_offset;

    row_pitch = slice_pitch;
    width = 1;
    unsigned char pixel[8];
    pixel_buffer = pixel;
    dither_pattern = grim_dither_half_pattern;
    pixel_offset = 0;

    if (coordinate_mode != 1) {
        unsigned int saved_conversion_mode = conversion_mode;
        float *saved_conversion_source = conversion_source;
        conversion_mode = 1;
        conversion_source = color_key;
        convert_vertex_space(color_key);
        conversion_mode = saved_conversion_mode;
        conversion_source = saved_conversion_source;
    }

    write_pixel(0, 0, color_key);
    read_pixel(0, 0, color_key);

    width = saved_width;
    row_pitch = saved_row_pitch;
    pixel_buffer = saved_pixel_buffer;
    dither_pattern = saved_dither_pattern;
    pixel_offset = saved_pixel_offset;
}
