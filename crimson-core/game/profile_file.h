// Profile files shared with the Python client. The native WASI host takes a
// flock for the lifetime of a sidecar descriptor; the browser owns its profile
// with a Web Lock. Never unlink a lock that another process may be waiting on.
#pragma once
#include <memory>
#include <stdio.h>
#include <string>
#include <unistd.h>

using ProfileFile = std::unique_ptr<FILE, decltype(&fclose)>;

inline ProfileFile profile_open(const char *path, const char *mode) {
  return ProfileFile(fopen(path, mode), fclose);
}

// The caller owns this destination through a sidecar lock or a reserved replay
// number, so its staging file cannot be another writer's.
inline bool profile_publish(const std::string &path, const void *bytes, size_t size) {
  std::string temp = path + ".writing";
  auto file = profile_open(temp.c_str(), "wb");
  if (!file)
    return false;
  bool written = fwrite(bytes, 1, size, file.get()) == size && fflush(file.get()) == 0 && fsync(fileno(file.get())) == 0;
  if (fclose(file.release()) == 0 && written && rename(temp.c_str(), path.c_str()) == 0)
    return true;
  unlink(temp.c_str());
  return false;
}
