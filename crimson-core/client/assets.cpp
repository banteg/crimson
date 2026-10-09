// Native installs may have music.paq rather than the loose music/ files the
// original opens. Prepare the same layout as the browser before booting it.
#ifndef __EMSCRIPTEN__
#include "paths.h"
#include <SDL3/SDL.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
std::string asset_path(const std::string &directory, const std::string &name) {
  return directory + "/" + client_path_name(opendir(directory.c_str()), name);
}

std::string asset_name(int directory, const std::string &name) {
  int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY);
  DIR *dir = fd >= 0 ? fdopendir(fd) : nullptr;
  if (!dir && fd >= 0)
    close(fd);
  return client_path_name(dir, name);
}

// Keep extraction relative to open directories; never follow a music/ link.
int open_music_directory(const std::string &directory) {
  int root = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (root < 0)
    return -1;
  int music = -1;
  std::string name = asset_name(root, "music");
  if (mkdirat(root, name.c_str(), 0777) == 0 || errno == EEXIST)
    music = openat(root, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  int error = errno;
  close(root);
  errno = error;
  return music;
}

// Publish only a complete file, without replacing an existing file or link.
std::string save_music(int music, const std::string &name, const unsigned char *data, size_t size) {
  struct stat st;
  if (fstatat(music, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0)
    return S_ISREG(st.st_mode) ? "" : "Cannot unpack music.paq: music/" + name + " must be a regular file, not a symbolic link.";
  if (errno != ENOENT)
    return "Cannot unpack music.paq: " + std::string(strerror(errno));

  unsigned long long nonce;
  if (getentropy(&nonce, sizeof nonce) != 0)
    return "Cannot create temporary music file: " + std::string(strerror(errno));
  char temporary[40];
  snprintf(temporary, sizeof temporary, ".crimson-%016llx.tmp", nonce);
  int fd = openat(music, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0666);
  if (fd < 0)
    return "Cannot create temporary music file: " + std::string(strerror(errno));
  FILE *file = fdopen(fd, "wb");
  if (!file) {
    int error = errno;
    close(fd);
    unlinkat(music, temporary, 0);
    return "Cannot unpack music.paq: " + std::string(strerror(error));
  }
  bool saved = fwrite(data, 1, size, file) == size;
  if (fclose(file) != 0)
    saved = false;
  std::string error;
  if (!saved)
    error = "Cannot write music/" + name + ".";
  else if (linkat(music, temporary, music, name.c_str(), 0) != 0)
    error = "Cannot publish music/" + name + ": " + strerror(errno);
  unlinkat(music, temporary, 0);
  return error;
}

std::string unpack_music(int music, const unsigned char *data, size_t size) {
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
    filename = asset_name(music, filename);
    std::string error = save_music(music, filename, data + at, bytes);
    if (!error.empty())
      return error;
    at += bytes;
  }
  return "";
}
} // namespace

std::string client_prepare_assets(const std::string &directory) {
  for (const char *name : {"crimson.paq", "sfx.paq"})
    if (!SDL_GetPathInfo(asset_path(directory, name).c_str(), nullptr))
      return std::string("Missing ") + name + ". Choose the folder containing the game's files.";

  const std::string archive = asset_path(directory, "music.paq");
  if (SDL_GetPathInfo(archive.c_str(), nullptr)) {
    size_t size;
    unsigned char *data = (unsigned char *)SDL_LoadFile(archive.c_str(), &size);
    if (!data)
      return "Cannot read music.paq: " + std::string(SDL_GetError());
    int music = open_music_directory(directory);
    std::string error = music < 0 ? "Cannot open music folder (symbolic links are not allowed): " + std::string(strerror(errno))
                                 : unpack_music(music, data, size);
    if (music >= 0)
      close(music);
    SDL_free(data);
    if (!error.empty())
      return error;
  }
  const std::string music = asset_path(directory, "music");
  for (const char *name : {"intro.ogg", "shortie_monk.ogg", "crimson_theme.ogg", "crimsonquest.ogg"})
    if (!SDL_GetPathInfo(asset_path(music, name).c_str(), nullptr))
      return std::string("Missing music/") + name + ". Add music.paq or the game's unpacked music folder.";
  return "";
}
#endif
