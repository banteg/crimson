#include <setjmp.h>

struct GrimJpegDecompress;
typedef unsigned char *GrimJpegRow;
typedef GrimJpegRow *GrimJpegRows;

struct GrimJpegMemoryManager {
    void *alloc_small;
    void *alloc_large;
    GrimJpegRows(__cdecl *alloc_sarray)(
        void *context, int pool, unsigned int samples, unsigned int rows);
};

struct GrimJpegErrorManager {
    void(__cdecl *error_exit)(void *context);
    void *emit_message;
    void *output_message;
    void(__cdecl *format_message)(void *context, char *message);
    unsigned char remaining_fields[116];
};

struct GrimJpegDecompress {
    GrimJpegErrorManager *err;
    GrimJpegMemoryManager *mem;
    unsigned char fields_before_output[0x54];
    unsigned int output_width;
    unsigned int output_height;
    int out_color_components;
    int output_components;
    int rec_outbuf_height;
    int actual_number_of_colors;
    GrimJpegRows colormap;
    unsigned int output_scanline;
    unsigned char remaining_fields[0x12c];
};

struct GrimJazDecodeScope {
    GrimJazDecodeScope();
    ~GrimJazDecodeScope();
    unsigned char *unpack(unsigned char *source, unsigned int *unpacked_size);
};

struct GrimJazJpegError {
    GrimJpegErrorManager base;
    jmp_buf jump_buffer;
};

struct GrimJazPayload {
    unsigned int jpeg_size;
    unsigned char jpeg_data[1];
};

#pragma pack(push, 1)
struct GrimTgaHeader {
    unsigned char id_length;
    unsigned char color_map_type;
    unsigned char image_type;
    unsigned int color_map_start_and_length;
    unsigned char color_map_bits;
    unsigned short x_origin;
    unsigned short y_origin;
    unsigned short width;
    unsigned short height;
    unsigned char pixel_bits;
    unsigned char descriptor;
};
#pragma pack(pop)

extern "C" void grim_jpeg_memory_src(
    GrimJpegDecompress *context, unsigned char *data, unsigned int size);
extern "C" void grim_jaz_jpeg_error_exit(void *context);
extern "C" GrimJpegErrorManager *jpeg_std_error(GrimJpegErrorManager *error);
extern "C" void jpeg_CreateDecompress(
    GrimJpegDecompress *context, int version, unsigned int size);
extern "C" void jpeg_destroy_decompress(GrimJpegDecompress *context);
extern "C" int jpeg_read_header(GrimJpegDecompress *context, int require_image);
extern "C" int jpeg_start_decompress(GrimJpegDecompress *context);
extern "C" unsigned int jpeg_read_scanlines(
    GrimJpegDecompress *context, GrimJpegRows scanlines, unsigned int rows);
extern "C" int jpeg_finish_decompress(GrimJpegDecompress *context);

unsigned char *grim_decode_jaz_texture(
    unsigned char *source,
    unsigned int source_size,
    unsigned int *image_size,
    int *width,
    int *height)
{
    GrimJazDecodeScope scope;
    unsigned int unpacked_size;
    unsigned char *image = 0;
    unsigned char *unpacked = scope.unpack(source, &unpacked_size);

    *width = 0;
    *height = 0;

    GrimJazPayload *payload = (GrimJazPayload *)unpacked;
    unsigned char *jpeg_data = payload->jpeg_data;
    unsigned int jpeg_size = payload->jpeg_size;
    if (jpeg_data != 0) {
        GrimJpegDecompress context;
        GrimJazJpegError error;
        context.err = jpeg_std_error(&error.base);
        error.base.error_exit = grim_jaz_jpeg_error_exit;

        if (setjmp(error.jump_buffer)) {
            jpeg_destroy_decompress(&context);
            if (image != 0) {
                delete image;
            }
            return 0;
        }

        jpeg_CreateDecompress(&context, 61, sizeof(context));
        grim_jpeg_memory_src(&context, jpeg_data, jpeg_size);
        jpeg_read_header(&context, 1);
        jpeg_start_decompress(&context);

        *image_size = context.output_width * context.output_height * 4 +
                      sizeof(GrimTgaHeader);
        image = new unsigned char[*image_size];
        if (image == 0) {
            jpeg_destroy_decompress(&context);
            return 0;
        }

        *width = context.output_width;
        *height = context.output_height;
        image += sizeof(GrimTgaHeader);

        GrimJpegRows scanline = (*context.mem->alloc_sarray)(
            &context,
            1,
            context.output_width * context.output_components,
            1);
        while (context.output_scanline < context.output_height) {
            jpeg_read_scanlines(&context, scanline, 1);
            unsigned int destination_offset =
                (*height - context.output_scanline) * *width * 4;
            unsigned int x = 0;
            if ((unsigned int)*width > 0) {
                unsigned int source_offset = 0;
                do {
                    image[destination_offset + x * 4 + 3] = 255;
                    image[destination_offset + x * 4 + 2] =
                        scanline[0][source_offset];
                    image[destination_offset + x * 4 + 1] =
                        scanline[0][source_offset + 1];
                    image[destination_offset + x * 4] =
                        scanline[0][source_offset + 2];
                    ++x;
                    source_offset += 3;
                } while (x < (unsigned int)*width);
            }
        }

        image -= sizeof(GrimTgaHeader);
        jpeg_finish_decompress(&context);
        jpeg_destroy_decompress(&context);

        GrimTgaHeader *header = (GrimTgaHeader *)image;
        header->id_length = 0;
        header->color_map_type = 0;
        header->image_type = 2;
        header->color_map_start_and_length = 0;
        header->color_map_bits = 0;
        header->x_origin = 0;
        header->y_origin = 0;
        header->width = (unsigned short)*width;
        header->height = (unsigned short)*height;
        header->pixel_bits = 32;
        header->descriptor = 8;

        unsigned char *alpha = unpacked + jpeg_size + 4;
        int alpha_offset = 0;
        int run_remaining = 0;
        int alpha_value;
        for (int y = header->height - 1; y >= 0; --y) {
            for (int x = 0; x < header->width; ++x) {
                if (run_remaining > 0) {
                    image[(y * header->width + x) * 4 +
                          sizeof(GrimTgaHeader) + 3] =
                        (unsigned char)alpha_value;
                    --run_remaining;
                } else {
                    run_remaining = alpha[alpha_offset];
                    alpha_offset += 2;
                    alpha_value = alpha[alpha_offset - 1];
                    --x;
                }
            }
        }

        if (unpacked != 0) {
            delete unpacked;
        }
        return image;
    }

    return 0;
}
