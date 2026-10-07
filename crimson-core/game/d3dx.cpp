// The D3DX 8 texture helpers Grim uses: image files decoded into device
// textures. Grim's JAZ codec hands over a 32-bit TGA; the game also loads TGA,
// BMP and JPEG files. JPEG goes through the same IJG 6a library the JAZ codec
// links.
#include "com_defaults.h"
#include "grim_d3dx8.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Grim's libjpeg was built under windows.h, whose boolean is a byte; the JAZ
// codec's view of the decompressor depends on that layout.
#define HAVE_BOOLEAN
typedef unsigned char boolean;
extern "C" {
#include <jpeglib.h>
}

namespace {

// Top-down rows of 0xAARRGGBB texels.
struct Image {
  int width = 0, height = 0;
  bool alpha = false;
  unsigned *texels = nullptr;
  ~Image() { free(texels); }
  bool allocate(int w, int h) {
    width = w;
    height = h;
    texels = (unsigned *)calloc((size_t)w * h, 4);
    return texels != nullptr;
  }
};

unsigned read16(const unsigned char *p) { return p[0] | p[1] << 8; }
unsigned read32(const unsigned char *p) { return p[0] | p[1] << 8 | p[2] << 16 | (unsigned)p[3] << 24; }

// A truecolor TGA texel: 15/16-bit A1R5G5B5, 24-bit BGR or 32-bit BGRA.
unsigned tga_color(const unsigned char *p, int bits) {
  switch (bits) {
  case 15:
  case 16: {
    unsigned v = read16(p);
    unsigned r = (v >> 10 & 31) * 255 / 31, g = (v >> 5 & 31) * 255 / 31, b = (v & 31) * 255 / 31;
    unsigned a = bits == 16 && !(v & 0x8000) ? 0 : 255;
    return a << 24 | r << 16 | g << 8 | b;
  }
  case 24:
    return 0xff000000u | p[2] << 16 | p[1] << 8 | p[0];
  default:
    return read32(p);
  }
}

bool decode_tga(const unsigned char *data, size_t size, Image &image) {
  if (size < 18)
    return false;
  int id_length = data[0], color_map_type = data[1], type = data[2];
  int palette_start = read16(data + 3), palette_length = read16(data + 5), palette_bits = data[7];
  int width = read16(data + 12), height = read16(data + 14), bits = data[16], descriptor = data[17];
  bool rle = type >= 9;
  int base = rle ? type - 8 : type;
  if ((base != 1 && base != 2 && base != 3) || !width || !height)
    return false;
  if (base == 2 ? bits != 15 && bits != 16 && bits != 24 && bits != 32 : bits != 8)
    return false;
  size_t offset = 18 + id_length;
  // Colour-mapped images index entries palette_start onwards, each a whole number of bytes.
  const unsigned char *palette = nullptr;
  int entry_bytes = (palette_bits + 7) / 8;
  if (color_map_type == 1) {
    if (palette_bits != 15 && palette_bits != 16 && palette_bits != 24 && palette_bits != 32)
      return false;
    palette = data + offset;
    offset += (size_t)palette_length * entry_bytes;
    if (offset > size)
      return false;
  }
  if (base == 1 && !palette)
    return false;
  if (!image.allocate(width, height))
    return false;
  image.alpha = base == 1 ? palette_bits == 16 || palette_bits == 32 : bits == 16 || bits == 32;
  int stride = (bits + 7) / 8;
  bool top_down = descriptor & 0x20;
  for (int i = 0, count = width * height; i < count;) {
    if (offset >= size)
      return false;
    int run = 1;
    bool repeat = false;
    if (rle) {
      int header = data[offset++];
      run = (header & 0x7f) + 1;
      repeat = header & 0x80;
    }
    for (int k = 0; k < run && i < count; ++k, ++i) {
      if (offset + stride > size)
        return false;
      unsigned texel;
      if (base == 1) {
        int index = data[offset] - palette_start;
        if (index < 0 || index >= palette_length)
          return false;
        texel = tga_color(palette + index * entry_bytes, palette_bits);
      } else if (base == 3) {
        texel = 0xff000000u | data[offset] * 0x010101u;
      } else {
        texel = tga_color(data + offset, bits);
      }
      if (!repeat || k == run - 1)
        offset += stride;
      int x = i % width, y = i / width;
      image.texels[(top_down ? y : height - 1 - y) * width + x] = texel;
    }
  }
  return true;
}

bool decode_bmp(const unsigned char *data, size_t size, Image &image) {
  if (size < 54 || data[0] != 'B' || data[1] != 'M')
    return false;
  unsigned pixels = read32(data + 10), header = read32(data + 14);
  int width = (int)read32(data + 18), height = (int)read32(data + 22);
  int bits = read16(data + 28), compression = read32(data + 30);
  if (compression != 0 || width <= 0 || !height || (bits != 8 && bits != 24 && bits != 32))
    return false;
  bool top_down = height < 0;
  if (top_down)
    height = -height;
  // An 8-bit image's palette holds biClrUsed entries, or all 256 when zero;
  // an index past them reads black.
  unsigned colors = bits == 8 ? read32(data + 46) ? read32(data + 46) : 256 : 0;
  unsigned long long stride = ((unsigned long long)width * bits / 8 + 3) & ~3ull;
  if (colors > 256 || 14ull + header + colors * 4 > size || pixels > size || stride * height > size - pixels ||
      !image.allocate(width, height))
    return false;
  const unsigned char *palette = data + 14 + header;
  static const unsigned char black[4] = {};
  for (int y = 0; y < height; ++y) {
    const unsigned char *row = data + pixels + stride * y;
    unsigned *out = image.texels + (top_down ? y : height - 1 - y) * width;
    for (int x = 0; x < width; ++x) {
      const unsigned char *p = bits != 8 ? row + x * (bits / 8) : row[x] < colors ? palette + row[x] * 4 : black;
      out[x] = 0xff000000u | p[2] << 16 | p[1] << 8 | p[0];
    }
  }
  return true;
}

struct JpegError {
  jpeg_error_mgr base;
  jmp_buf jump;
};
void jpeg_fail(j_common_ptr context) { longjmp(((JpegError *)context->err)->jump, 1); }
void jpeg_noop(j_decompress_ptr) {}
boolean jpeg_fill(j_decompress_ptr context) {
  static const JOCTET eoi[2] = {0xff, JPEG_EOI};
  context->src->next_input_byte = eoi;
  context->src->bytes_in_buffer = 2;
  return TRUE;
}
void jpeg_skip(j_decompress_ptr context, long count) {
  size_t skip = count < 0 ? 0 : (size_t)count;
  if (skip > context->src->bytes_in_buffer)
    skip = context->src->bytes_in_buffer;
  context->src->next_input_byte += skip;
  context->src->bytes_in_buffer -= skip;
}

bool decode_jpeg(const unsigned char *data, size_t size, Image &image) {
  if (size < 3 || data[0] != 0xff || data[1] != 0xd8)
    return false;
  jpeg_decompress_struct context;
  JpegError error;
  jpeg_source_mgr source = {data, size, jpeg_noop, jpeg_fill, jpeg_skip, jpeg_resync_to_restart, jpeg_noop};
  context.err = jpeg_std_error(&error.base);
  error.base.error_exit = jpeg_fail;
  if (setjmp(error.jump)) {
    jpeg_destroy_decompress(&context);
    return false;
  }
  jpeg_create_decompress(&context);
  context.src = &source;
  jpeg_read_header(&context, TRUE);
  context.out_color_space = JCS_RGB;
  jpeg_start_decompress(&context);
  if (!image.allocate(context.output_width, context.output_height)) {
    jpeg_destroy_decompress(&context);
    return false;
  }
  JSAMPARRAY row = (*context.mem->alloc_sarray)((j_common_ptr)&context, JPOOL_IMAGE,
                                                 context.output_width * context.output_components, 1);
  while (context.output_scanline < context.output_height) {
    unsigned *out = image.texels + context.output_scanline * image.width;
    jpeg_read_scanlines(&context, row, 1);
    for (int x = 0; x < image.width; ++x)
      out[x] = 0xff000000u | row[0][x * 3] << 16 | row[0][x * 3 + 1] << 8 | row[0][x * 3 + 2];
  }
  jpeg_finish_decompress(&context);
  jpeg_destroy_decompress(&context);
  return true;
}

bool decode(const unsigned char *data, size_t size, Image &image) {
  return decode_jpeg(data, size, image) || decode_bmp(data, size, image) || decode_tga(data, size, image);
}

int create_texture(IDirect3DDevice8 *device, Image &image, D3DFORMAT format, GrimD3dxImageInfo *info,
                   IDirect3DTexture8 **texture) {
  if (format != D3DFMT_X8R8G8B8)
    format = D3DFMT_A8R8G8B8;
  if (device->CreateTexture(image.width, image.height, 1, 0, format, D3DPOOL_MANAGED, texture) < 0)
    return D3DERR_INVALIDCALL;
  D3DLOCKED_RECT locked;
  (*texture)->LockRect(0, &locked, nullptr, 0);
  for (int y = 0; y < image.height; ++y)
    memcpy((unsigned char *)locked.pBits + y * locked.Pitch, image.texels + y * image.width, image.width * 4);
  (*texture)->UnlockRect(0);
  if (info) {
    memset(info, 0, sizeof(*info));
    info->width = image.width;
    info->height = image.height;
    info->depth = 1;
    info->mip_levels = 1;
    info->format = image.alpha ? D3DFMT_A8R8G8B8 : D3DFMT_X8R8G8B8;
    info->resource_type = D3DRTYPE_TEXTURE;
  }
  return D3D_OK;
}

} // namespace

extern "C" {
void platform_longjmp(void) { platform_unimplemented("recovery from a corrupt image"); }

// The memory source Grim's JAZ codec reads its JPEG payload through.
void grim_jpeg_memory_src(j_decompress_ptr context, unsigned char *data, unsigned int size) {
  auto *source = (jpeg_source_mgr *)(*context->mem->alloc_small)((j_common_ptr)context, JPOOL_PERMANENT,
                                                                  sizeof(jpeg_source_mgr));
  *source = {data, size, jpeg_noop, jpeg_fill, jpeg_skip, jpeg_resync_to_restart, jpeg_noop};
  context->src = source;
}

// zlib 1.1.3's uncompress, under the name Grim links it by.
int uncompress(unsigned char *dest, unsigned long *dest_len, const unsigned char *source, unsigned long source_len);
int zlib_uncompress(unsigned char *dest, unsigned long *dest_len, const unsigned char *source,
                    unsigned long source_len) {
  return uncompress(dest, dest_len, source, source_len);
}

int __stdcall D3DXCreateTextureFromFileInMemoryEx(IDirect3DDevice8 *device, const void *data, unsigned int size,
                                                  unsigned int, unsigned int, unsigned int, unsigned long,
                                                  D3DFORMAT format, D3DPOOL, unsigned long, unsigned long, D3DCOLOR,
                                                  void *info, PALETTEENTRY *, IDirect3DTexture8 **texture) {
  Image image;
  if (!decode((const unsigned char *)data, size, image))
    return D3DERR_INVALIDCALL;
  return create_texture(device, image, format, (GrimD3dxImageInfo *)info, texture);
}
int __stdcall D3DXCreateTextureFromFileExA(IDirect3DDevice8 *device, char *path, unsigned int width,
                                           unsigned int height, unsigned int levels, unsigned long usage,
                                           D3DFORMAT format, D3DPOOL pool, unsigned long filter,
                                           unsigned long mip_filter, D3DCOLOR key, GrimD3dxImageInfo *info,
                                           PALETTEENTRY *palette, IDirect3DTexture8 **texture) {
  FILE *fp = platform_fopen(path, "rb");
  if (!fp)
    return D3DERR_INVALIDCALL;
  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  auto *bytes = (unsigned char *)malloc(size);
  fread(bytes, 1, size, fp);
  fclose(fp);
  int result = D3DXCreateTextureFromFileInMemoryEx(device, bytes, size, width, height, levels, usage, format, pool,
                                                   filter, mip_filter, key, info, palette, texture);
  free(bytes);
  return result;
}
int __stdcall D3DXCreateTexture(IDirect3DDevice8 *device, unsigned int width, unsigned int height, unsigned int levels,
                                unsigned long usage, D3DFORMAT format, D3DPOOL pool, IDirect3DTexture8 **texture) {
  if (format != D3DFMT_X8R8G8B8)
    format = D3DFMT_A8R8G8B8;
  return device->CreateTexture(width, height, levels, usage, format, pool, texture);
}
// Grim copies a texture into a recreated one of the same size.
int __stdcall d3dx_copy_texture_filtered(IDirect3DTexture8 *destination, IDirect3DTexture8 *source, void *,
                                         unsigned long, unsigned long, float) {
  D3DSURFACE_DESC to, from;
  destination->GetLevelDesc(0, &to);
  source->GetLevelDesc(0, &from);
  D3DLOCKED_RECT out, in;
  destination->LockRect(0, &out, nullptr, 0);
  source->LockRect(0, &in, nullptr, 0);
  for (UINT y = 0; y < to.Height; ++y)
    for (UINT x = 0; x < to.Width; ++x)
      ((unsigned *)((unsigned char *)out.pBits + y * out.Pitch))[x] =
          ((unsigned *)((unsigned char *)in.pBits + y * from.Height / to.Height * in.Pitch))[x * from.Width / to.Width];
  source->UnlockRect(0);
  destination->UnlockRect(0);
  return D3D_OK;
}
// Screenshots and texture dumps are not written.
int __stdcall D3DXSaveSurfaceToFileA(char *, int, IDirect3DSurface8 *, void *, void *) { return D3DERR_INVALIDCALL; }
int __stdcall D3DXSaveTextureToFileA(char *, int, IDirect3DBaseTexture8 *, void *) { return D3DERR_INVALIDCALL; }
}

// Grim's JAZ decoder declares a scope destructor that its recovered source never
// defines; the scope owns nothing.
struct GrimJazDecodeScope {
  ~GrimJazDecodeScope();
};
GrimJazDecodeScope::~GrimJazDecodeScope() {}
