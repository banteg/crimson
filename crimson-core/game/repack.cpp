// The crimson.paq the project distributes: Tero's uncompressed art under the
// original names, stored with forward slashes and in each image's own format
// (game/alien.tga where the executable asks for game\alien.jaz). Grim finds an
// entry by its exact name and decodes it by the name's extension
// (texture/load_file.cpp), so it asks for the stored name first. The original
// crimson.paq resolves every name to itself.
#include <ctype.h>
#include <initializer_list>
#include <string.h>

extern char *grim_lookup_blob_magic;
extern char *grim_lookup_blob;
extern int grim_lookup_blob_size;
extern unsigned char grim_lookup_blob_loaded;

// The same path but for separators and case, up to the extensions when `stems`.
bool paq_same_path(const char *stored, const char *wanted, bool stems) {
  const char *stored_dot = strrchr(stored, '.'), *wanted_dot = strrchr(wanted, '.');
  size_t n = stems && stored_dot ? stored_dot - stored : strlen(stored);
  size_t m = stems && wanted_dot ? wanted_dot - wanted : strlen(wanted);
  if (n != m)
    return false;
  for (size_t i = 0; i < n; ++i) {
    char a = stored[i] == '/' ? '\\' : tolower((unsigned char)stored[i]);
    char b = wanted[i] == '/' ? '\\' : tolower((unsigned char)wanted[i]);
    if (a != b)
      return false;
  }
  return true;
}

// The name the entry for `path` is stored under: the same path, else the same
// path in another format; `path` itself when the pack holds neither.
char *grim_lookup_blob_entry(char *path) {
  if (!grim_lookup_blob_loaded)
    return path;
  for (bool stems : {false, true})
    for (int offset = (int)strlen(grim_lookup_blob_magic) + 1; offset < grim_lookup_blob_size;) {
      char *name = grim_lookup_blob + offset;
      int length = (int)strlen(name);
      if (paq_same_path(name, path, stems))
        return name;
      offset += length + 5 + *(int *)(name + length + 1);
    }
  return path;
}
