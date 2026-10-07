// The WASI preview1 calls the game module's libc makes: files under the game
// directory (preopened as fd 3), the clock, and console output. Windows paths
// arrive already normalized; names match case-insensitively, as on Windows.
#include "client.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace {

enum : u32 {
  ESUCCESS = 0,
  EACCES_ = 2,
  EBADF_ = 8,
  EINVAL_ = 28,
  EIO_ = 29,
  ENOENT_ = 44,
  ENOSYS_ = 52,
  ENOTDIR_ = 54,
};
enum : u8 { FILETYPE_UNKNOWN = 0, FILETYPE_DIRECTORY = 3, FILETYPE_REGULAR = 4 };

struct File {
  int fd = -1;
  DIR *dir = nullptr;
  std::string path;
};
std::vector<File> files;

u8 *memory() { return client_memory(); }
u32 load32(u32 at) {
  u32 v;
  memcpy(&v, memory() + at, 4);
  return v;
}
void store32(u32 at, u32 v) { memcpy(memory() + at, &v, 4); }
void store64(u32 at, uint64_t v) { memcpy(memory() + at, &v, 8); }

u32 errno_code() {
  switch (errno) {
  case ENOENT:
    return ENOENT_;
  case ENOTDIR:
    return ENOTDIR_;
  case EBADF:
    return EBADF_;
  default:
    return EIO_;
  }
}

File *file(u32 fd) { return fd < files.size() && (files[fd].fd >= 0 || files[fd].dir) ? &files[fd] : nullptr; }

// The real name of each component, matched case-insensitively under the root.
// Paths stay inside the game directory: no "..", and no symbolic links.
bool resolve(const std::string &relative, std::string &path) {
  path = client_game_directory();
  size_t start = 0;
  while (start <= relative.size()) {
    size_t end = relative.find('/', start);
    if (end == std::string::npos)
      end = relative.size();
    std::string part = relative.substr(start, end - start);
    start = end + 1;
    if (part.empty() || part == ".")
      continue;
    if (part == "..")
      return false;
    std::string match = part;
    if (DIR *dir = opendir(path.c_str())) {
      while (dirent *entry = readdir(dir))
        if (!strcasecmp(entry->d_name, part.c_str())) {
          match = entry->d_name;
          break;
        }
      closedir(dir);
    }
    path += "/" + match;
    struct stat st;
    if (lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode))
      return false;
  }
  return true;
}

std::string guest_string(u32 at, u32 length) { return std::string((const char *)memory() + at, length); }

u8 filetype(mode_t mode) { return S_ISDIR(mode) ? FILETYPE_DIRECTORY : S_ISREG(mode) ? FILETYPE_REGULAR : FILETYPE_UNKNOWN; }

void store_filestat(u32 at, const struct stat &st) {
  memset(memory() + at, 0, 64);
  store64(at, st.st_dev);
  store64(at + 8, st.st_ino);
  memory()[at + 16] = filetype(st.st_mode);
  store64(at + 24, st.st_nlink);
  store64(at + 32, st.st_size);
}

} // namespace

void client_wasi_init() {
  files.assign(4, File{});
  files[3].dir = opendir(client_game_directory().c_str());
  files[3].path = "";
}

extern "C" {
void w2c_wasi__snapshot__preview1_proc_exit(struct w2c_wasi__snapshot__preview1 *, u32 code) {
  client_fatal(("the game exited with code " + std::to_string(code)).c_str());
}
u32 w2c_wasi__snapshot__preview1_environ_sizes_get(struct w2c_wasi__snapshot__preview1 *, u32 count, u32 size) {
  store32(count, 0);
  store32(size, 0);
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_environ_get(struct w2c_wasi__snapshot__preview1 *, u32, u32) { return ESUCCESS; }
u32 w2c_wasi__snapshot__preview1_clock_time_get(struct w2c_wasi__snapshot__preview1 *, u32 clock, uint64_t,
                                                u32 result) {
  struct timespec now;
  clock_gettime(clock == 0 ? CLOCK_REALTIME : CLOCK_MONOTONIC, &now);
  store64(result, (uint64_t)now.tv_sec * 1000000000u + now.tv_nsec);
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_fd_prestat_get(struct w2c_wasi__snapshot__preview1 *, u32 fd, u32 result) {
  if (fd != 3)
    return EBADF_;
  store32(result, 0);     // a directory
  store32(result + 4, 1); // named "."
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_fd_prestat_dir_name(struct w2c_wasi__snapshot__preview1 *, u32 fd, u32 path,
                                                     u32 length) {
  if (fd != 3 || length < 1)
    return EBADF_;
  memory()[path] = '.';
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_fd_fdstat_get(struct w2c_wasi__snapshot__preview1 *, u32 fd, u32 result) {
  memset(memory() + result, 0, 24);
  if (fd <= 2) {
    memory()[result] = 2; // character device
  } else if (File *f = file(fd)) {
    memory()[result] = f->dir ? FILETYPE_DIRECTORY : FILETYPE_REGULAR;
  } else {
    return EBADF_;
  }
  store64(result + 8, ~0ull);
  store64(result + 16, ~0ull);
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_fd_fdstat_set_flags(struct w2c_wasi__snapshot__preview1 *, u32, u32) {
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_path_open(struct w2c_wasi__snapshot__preview1 *, u32 dirfd, u32, u32 path_at,
                                           u32 path_length, u32 oflags, uint64_t rights, uint64_t, u32 fdflags,
                                           u32 result) {
  File *dir = file(dirfd);
  if (!dir || !dir->dir)
    return EBADF_;
  std::string relative = dir->path.empty() ? guest_string(path_at, path_length)
                                           : dir->path + "/" + guest_string(path_at, path_length);
  std::string host;
  if (!resolve(relative, host))
    return EACCES_;
  File opened;
  opened.path = relative;
  struct stat st;
  bool exists = stat(host.c_str(), &st) == 0;
  if ((oflags & 2) || (exists && S_ISDIR(st.st_mode))) { // O_DIRECTORY
    if (!(opened.dir = opendir(host.c_str())))
      return errno_code();
  } else {
    bool reads = rights & 1u << 1, writes = rights & 1u << 6; // fd_read, fd_write
    int flags = (oflags & 1 ? O_CREAT : 0) | (oflags & 4 ? O_EXCL : 0) | (oflags & 8 ? O_TRUNC : 0) |
                (fdflags & 1 ? O_APPEND : 0) | (reads && writes ? O_RDWR : writes ? O_WRONLY : O_RDONLY) | O_NOFOLLOW;
    if ((opened.fd = open(host.c_str(), flags, 0644)) < 0)
      return errno_code();
  }
  files.push_back(opened);
  store32(result, (u32)files.size() - 1);
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_fd_close(struct w2c_wasi__snapshot__preview1 *, u32 fd) {
  File *f = file(fd);
  if (!f || fd <= 3)
    return EBADF_;
  if (f->dir)
    closedir(f->dir);
  if (f->fd >= 0)
    close(f->fd);
  *f = File{};
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_fd_read(struct w2c_wasi__snapshot__preview1 *, u32 fd, u32 iovs, u32 count,
                                         u32 result) {
  File *f = file(fd);
  if (!f || f->fd < 0)
    return EBADF_;
  u32 total = 0;
  for (u32 i = 0; i < count; ++i) {
    ssize_t n = read(f->fd, memory() + load32(iovs + i * 8), load32(iovs + i * 8 + 4));
    if (n < 0)
      return errno_code();
    total += (u32)n;
    if ((u32)n < load32(iovs + i * 8 + 4))
      break;
  }
  store32(result, total);
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_fd_write(struct w2c_wasi__snapshot__preview1 *, u32 fd, u32 iovs, u32 count,
                                          u32 result) {
  u32 total = 0;
  for (u32 i = 0; i < count; ++i) {
    const u8 *data = memory() + load32(iovs + i * 8);
    u32 length = load32(iovs + i * 8 + 4);
    if (fd == 1 || fd == 2) {
      fwrite(data, 1, length, fd == 1 ? stdout : stderr);
    } else {
      File *f = file(fd);
      if (!f || f->fd < 0)
        return EBADF_;
      if (write(f->fd, data, length) != (ssize_t)length)
        return errno_code();
    }
    total += length;
  }
  store32(result, total);
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_fd_seek(struct w2c_wasi__snapshot__preview1 *, u32 fd, uint64_t offset, u32 whence,
                                         u32 result) {
  File *f = file(fd);
  if (!f || f->fd < 0)
    return EBADF_;
  off_t at = lseek(f->fd, (off_t)(int64_t)offset, whence == 0 ? SEEK_SET : whence == 1 ? SEEK_CUR : SEEK_END);
  if (at < 0)
    return errno_code();
  store64(result, (uint64_t)at);
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_fd_readdir(struct w2c_wasi__snapshot__preview1 *, u32 fd, u32 buffer, u32 length,
                                            uint64_t cookie, u32 result) {
  File *f = file(fd);
  if (!f || !f->dir)
    return EBADF_;
  rewinddir(f->dir);
  u32 used = 0;
  uint64_t index = 0;
  while (dirent *entry = readdir(f->dir)) {
    if (index++ < cookie)
      continue;
    u32 name_length = (u32)strlen(entry->d_name);
    u8 header[24] = {};
    uint64_t next = index;
    memcpy(header, &next, 8);
    memcpy(header + 16, &name_length, 4);
    header[20] = entry->d_type == DT_DIR ? FILETYPE_DIRECTORY : FILETYPE_REGULAR;
    for (u32 i = 0; i < 24 && used < length; ++i)
      memory()[buffer + used++] = header[i];
    for (u32 i = 0; i < name_length && used < length; ++i)
      memory()[buffer + used++] = (u8)entry->d_name[i];
    if (used >= length)
      break;
  }
  store32(result, used);
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_path_filestat_get(struct w2c_wasi__snapshot__preview1 *, u32 dirfd, u32,
                                                   u32 path_at, u32 path_length, u32 result) {
  File *dir = file(dirfd);
  if (!dir || !dir->dir)
    return EBADF_;
  std::string relative = guest_string(path_at, path_length), host;
  if (!resolve(dir->path.empty() ? relative : dir->path + "/" + relative, host))
    return EACCES_;
  struct stat st;
  if (stat(host.c_str(), &st))
    return errno_code();
  store_filestat(result, st);
  return ESUCCESS;
}
u32 w2c_wasi__snapshot__preview1_path_create_directory(struct w2c_wasi__snapshot__preview1 *, u32 dirfd, u32 path_at,
                                                       u32 path_length) {
  File *dir = file(dirfd);
  if (!dir || !dir->dir)
    return EBADF_;
  std::string relative = guest_string(path_at, path_length), host;
  if (!resolve(dir->path.empty() ? relative : dir->path + "/" + relative, host))
    return EACCES_;
  if (mkdir(host.c_str(), 0755) && errno != EEXIST)
    return errno_code();
  return ESUCCESS;
}
}
