// The resources Grim loads from its own DLL (the default font and splash
// textures), read from grim.dll's resource section in the game directory.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

namespace {

struct Resource {
  const unsigned char *data;
  DWORD size;
};

unsigned char *image;
long image_size;

unsigned read16(const unsigned char *p) { return p[0] | p[1] << 8; }
unsigned read32(const unsigned char *p) { return p[0] | p[1] << 8 | p[2] << 16 | (unsigned)p[3] << 24; }

bool load_image() {
  if (image)
    return true;
  FILE *fp = fopen("grim.dll", "rb");
  if (!fp)
    return false;
  fseek(fp, 0, SEEK_END);
  image_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  image = (unsigned char *)malloc(image_size);
  bool ok = fread(image, 1, image_size, fp) == (size_t)image_size;
  fclose(fp);
  return ok;
}

// The file offset of a relative virtual address, through the section table.
long file_offset(unsigned rva) {
  unsigned pe = read32(image + 0x3c);
  unsigned sections = read16(image + pe + 6), optional = read16(image + pe + 20);
  const unsigned char *table = image + pe + 24 + optional;
  for (unsigned i = 0; i < sections; ++i) {
    const unsigned char *s = table + i * 40;
    unsigned va = read32(s + 12), size = read32(s + 8), raw = read32(s + 20);
    if (rva >= va && rva < va + size)
      return raw + (rva - va);
  }
  return -1;
}

// The entry for an id in a resource directory, or null.
const unsigned char *find_entry(const unsigned char *root, const unsigned char *directory, unsigned id) {
  unsigned count = read16(directory + 12) + read16(directory + 14);
  for (unsigned i = 0; i < count; ++i) {
    const unsigned char *entry = directory + 16 + i * 8;
    if (id == ~0u || read32(entry) == id)
      return root + (read32(entry + 4) & 0x7fffffff);
  }
  return nullptr;
}

} // namespace

extern "C" {
HRSRC WINAPI FindResourceA(HMODULE, LPCSTR name, LPCSTR type) {
  if (!load_image())
    return nullptr;
  unsigned pe = read32(image + 0x3c);
  unsigned directory_rva = read32(image + pe + 24 + 96 + 2 * 8);
  long offset = file_offset(directory_rva);
  if (offset < 0)
    return nullptr;
  const unsigned char *root = image + offset;
  const unsigned char *by_type = find_entry(root, root, (unsigned)(uintptr_t)type);
  const unsigned char *by_name = by_type ? find_entry(root, by_type, (unsigned)(uintptr_t)name) : nullptr;
  const unsigned char *by_language = by_name ? find_entry(root, by_name, ~0u) : nullptr;
  if (!by_language)
    return nullptr;
  long data = file_offset(read32(by_language));
  if (data < 0)
    return nullptr;
  return (HRSRC) new Resource{image + data, read32(by_language + 4)};
}
HGLOBAL WINAPI LoadResource(HMODULE, HRSRC resource) {
  return resource ? (HGLOBAL)((Resource *)resource)->data : nullptr;
}
LPVOID WINAPI LockResource(HGLOBAL data) { return data; }
DWORD WINAPI SizeofResource(HMODULE, HRSRC resource) { return resource ? ((Resource *)resource)->size : 0; }
}
