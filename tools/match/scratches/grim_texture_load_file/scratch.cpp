#include <stdio.h>

#include "grim_d3dx8.h"
#include "grim_texture.h"

extern unsigned char grim_lookup_blob_loaded;

extern "C" bool grim_path_has_extension(char *path, char *extension);
unsigned char *grim_lookup_blob_find(char *path);
unsigned int grim_lookup_blob_size_for_path(char *path);
unsigned char *grim_decode_jaz_texture(
    unsigned char *source,
    unsigned int source_size,
    unsigned int *image_size,
    int *width,
    int *height);

bool GrimTexture::grim_texture_load_file(char *path)
{
    if (path == 0) {
        return false;
    }

    if (this->texture != 0) {
        this->texture->Release();
    }
    this->texture = 0;

    unsigned char *lookup_data = 0;
    bool found_in_lookup = false;
    if (grim_lookup_blob_loaded) {
        lookup_data = grim_lookup_blob_find(path);
        found_in_lookup = lookup_data != 0;
    }

    int image_width;
    int image_height;
    unsigned int image_size;
    GrimD3dxImageInfo source_info;
    if (grim_path_has_extension(path, "jaz")) {
        bool result = true;
        unsigned int source_size;
        unsigned char *source_data;

        if (grim_lookup_blob_loaded && found_in_lookup) {
            source_size = grim_lookup_blob_size_for_path(path);
            source_data = lookup_data;
        } else {
            FILE *file = fopen(path, "rb");
            if (file == 0) {
                return false;
            }

            fseek(file, 0, SEEK_END);
            source_size = ftell(file);
            fseek(file, 0, SEEK_SET);
            source_data = new unsigned char[source_size];
            fread(source_data, source_size, 1, file);
            fclose(file);
        }

        unsigned char *image = grim_decode_jaz_texture(
            source_data,
            source_size,
            &image_size,
            &image_width,
            &image_height);
        if (image != 0) {
            this->width = image_width;
            this->height = image_height;
            if (D3DXCreateTextureFromFileInMemoryEx(
                    grim_d3d_device,
                    image,
                    image_size,
                    0xffffffff,
                    0xffffffff,
                    1,
                    0,
                    grim_preferred_texture_format,
                    D3DPOOL_MANAGED,
                    0xffffffff,
                    0xffffffff,
                    0,
                    &source_info,
                    0,
                    &this->texture) < 0) {
                result = false;
                this->texture = 0;
            } else {
                result = true;
            }
        }
        return result;
    }

    if (grim_lookup_blob_loaded && found_in_lookup) {
        unsigned int source_size = grim_lookup_blob_size_for_path(path);
        if (D3DXCreateTextureFromFileInMemoryEx(
                grim_d3d_device,
                lookup_data,
                source_size,
                0xffffffff,
                0xffffffff,
                1,
                0,
                grim_preferred_texture_format,
                D3DPOOL_MANAGED,
                0xffffffff,
                0xffffffff,
                0,
                &source_info,
                0,
                &this->texture) < 0) {
            this->texture = 0;
            return false;
        }
        this->width = source_info.width;
        this->height = source_info.height;
        return true;
    }

    if (D3DXCreateTextureFromFileExA(
            grim_d3d_device,
            path,
            0xffffffff,
            0xffffffff,
            1,
            0,
            grim_preferred_texture_format,
            D3DPOOL_MANAGED,
            0xffffffff,
            0xffffffff,
            0,
            &source_info,
            0,
            &this->texture) < 0) {
        this->texture = 0;
        return false;
    }
    this->width = source_info.width;
    this->height = source_info.height;
    return true;
}
