// The resources Grim loads from its own DLL (the default font and splash
// textures, device/d3d_init.cpp), read from grim.dll's resource section in the
// game directory. Without grim.dll, which the project's distribution leaves out,
// the font is crimson.paq's load/default_font_courier.tga, the same bytes, read
// here since the executable sets Grim's pack only after its device is up; a
// blank texture stands in for the splash, which nothing draws.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

bool paq_same_path(const char *stored, const char *wanted, bool stems);

namespace {

struct Resource {
  const unsigned char *data;
  DWORD size;
};

unsigned char *image;
long image_size;

// Reads at file offsets; anything past the end reads as zero, which no valid
// structure here contains.
bool inside(unsigned at, unsigned long long size) { return at + size <= (unsigned long long)image_size; }
unsigned read16(unsigned at) { return inside(at, 2) ? image[at] | image[at + 1] << 8 : 0; }
unsigned read32(unsigned at) { return inside(at, 4) ? read16(at) | read16(at + 2) << 16 : 0; }

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
  unsigned pe = read32(0x3c);
  unsigned sections = read16(pe + 6), optional = read16(pe + 20);
  unsigned table = pe + 24 + optional;
  for (unsigned i = 0; i < sections; ++i) {
    unsigned s = table + i * 40;
    unsigned va = read32(s + 12), size = read32(s + 8), raw = read32(s + 20);
    if (rva >= va && rva - va < size && inside(raw, rva - va + 1ull))
      return raw + (rva - va);
  }
  return -1;
}

// The offset of an id's entry in a resource directory, or 0 for none.
unsigned find_entry(unsigned root, unsigned directory, unsigned id) {
  unsigned count = read16(directory + 12) + read16(directory + 14);
  for (unsigned i = 0; i < count; ++i) {
    unsigned entry = directory + 16 + i * 8;
    if (id == ~0u || read32(entry) == id)
      return root + (read32(entry + 4) & 0x7fffffff);
  }
  return 0;
}

// RCDATA ids (grim.dll's resource script).
const unsigned DEFAULT_FONT = 0x6f, SPLASH = 0x71;
// A 1x1 truecolor TGA.
const unsigned char BLANK[] = {0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 24, 0, 0, 0, 0};

HRSRC packed(unsigned id) {
  if (id == SPLASH)
    return (HRSRC) new Resource{BLANK, sizeof BLANK};
  FILE *fp = id == DEFAULT_FONT ? fopen("crimson.paq", "rb") : nullptr;
  if (!fp)
    return nullptr;
  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  unsigned char *pack = (unsigned char *)malloc(size);
  bool read = fread(pack, 1, size, fp) == (size_t)size;
  fclose(fp);
  Resource *found = nullptr;
  // Entries: a NUL-terminated name, a little-endian size, the bytes.
  for (long at = 4; read && !found && at < size;) {
    const char *name = (const char *)pack + at;
    long length = (long)strnlen(name, size - at), data = at + length + 5;
    if (data > size)
      break;
    DWORD entry;
    memcpy(&entry, pack + at + length + 1, 4);
    if (entry > (unsigned long)(size - data))
      break;
    if (paq_same_path(name, "load\\default_font_courier.tga", false)) {
      unsigned char *copy = (unsigned char *)malloc(entry);
      memcpy(copy, pack + data, entry);
      found = new Resource{copy, entry};
    }
    at = data + entry;
  }
  free(pack);
  return (HRSRC)found;
}

} // namespace

extern "C" {
HRSRC WINAPI FindResourceA(HMODULE, LPCSTR name, LPCSTR type) {
  if (!load_image())
    return type == RT_RCDATA ? packed((unsigned)(uintptr_t)name) : nullptr;
  unsigned pe = read32(0x3c);
  long root = file_offset(read32(pe + 24 + 96 + 2 * 8));
  if (root <= 0)
    return nullptr;
  unsigned by_type = find_entry(root, root, (unsigned)(uintptr_t)type);
  unsigned by_name = by_type ? find_entry(root, by_type, (unsigned)(uintptr_t)name) : 0;
  unsigned by_language = by_name ? find_entry(root, by_name, ~0u) : 0;
  if (!by_language)
    return nullptr;
  long data = file_offset(read32(by_language));
  unsigned size = read32(by_language + 4);
  if (data < 0 || size > (unsigned long)(image_size - data))
    return nullptr;
  return (HRSRC) new Resource{image + data, size};
}
HGLOBAL WINAPI LoadResource(HMODULE, HRSRC resource) {
  return resource ? (HGLOBAL)((Resource *)resource)->data : nullptr;
}
LPVOID WINAPI LockResource(HGLOBAL data) { return data; }
DWORD WINAPI SizeofResource(HMODULE, HRSRC resource) { return resource ? ((Resource *)resource)->size : 0; }
}
