// Native installs may have music.paq rather than the loose music/ files the
// original opens. Prepare the same layout as the browser before booting it.
#ifndef __EMSCRIPTEN__
#include <SDL3/SDL.h>
#include <string.h>
#include <string>

namespace {
std::string unpack_music(const std::string &directory, const unsigned char *data, size_t size) {
  if (size < 4 || memcmp(data, "paq\0", 4))
    return "Invalid music.paq. Replace it with the game's music archive.";
  for (size_t at = 4; at < size;) {
    const char *name = (const char *)data + at;
    size_t length = strnlen(name, size - at);
    if (length == size - at || size - at - length < 5)
      return "Incomplete music.paq. Replace it with the game's music archive.";
    Uint32 bytes;
    memcpy(&bytes, data + at + length + 1, sizeof bytes);
    bytes = SDL_Swap32LE(bytes);
    at += length + 5;
    if (bytes > size - at)
      return "Incomplete music.paq. Replace it with the game's music archive.";
    // The distributed pack uses bare filenames; also accept path prefixes,
    // as the browser does, without writing outside music/.
    std::string filename(name, length);
    filename = filename.substr(filename.find_last_of("/\\") + 1);
    if (filename.empty() || filename == "." || filename == "..")
      return "Invalid filename in music.paq.";
    const std::string path = directory + "/music/" + filename;
    if (!SDL_GetPathInfo(path.c_str(), nullptr)) {
      if (!SDL_CreateDirectory((directory + "/music").c_str()) ||
          !SDL_SaveFile(path.c_str(), data + at, bytes))
        return "Cannot unpack music.paq: " + std::string(SDL_GetError());
    }
    at += bytes;
  }
  return "";
}
} // namespace

std::string client_prepare_assets(const std::string &directory) {
  for (const char *name : {"crimson.paq", "sfx.paq"})
    if (!SDL_GetPathInfo((directory + "/" + name).c_str(), nullptr))
      return std::string("Missing ") + name + ". Choose the folder containing the game's files.";

  const std::string archive = directory + "/music.paq";
  if (SDL_GetPathInfo(archive.c_str(), nullptr)) {
    size_t size;
    unsigned char *data = (unsigned char *)SDL_LoadFile(archive.c_str(), &size);
    if (!data)
      return "Cannot read music.paq: " + std::string(SDL_GetError());
    std::string error = unpack_music(directory, data, size);
    SDL_free(data);
    if (!error.empty())
      return error;
  }
  for (const char *name : {"intro.ogg", "shortie_monk.ogg", "crimson_theme.ogg", "crimsonquest.ogg"})
    if (!SDL_GetPathInfo((directory + "/music/" + name).c_str(), nullptr))
      return std::string("Missing music/") + name + ". Add music.paq or the game's unpacked music folder.";
  return "";
}
#endif
