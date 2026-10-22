// Exercise the desktop WASI adapter's real append lock and short-write reporting.
#include <unistd.h>
#include <algorithm>
static ssize_t partial_write(int fd, const void *data, size_t size) {
  usleep(1000);
  return ::write(fd, data, std::min(size, (size_t)3));
}
#define write partial_write
#include "../../crimson-core/client/wasi.cpp"
#undef write

static u8 bytes[4096];
static std::string directory;
u8 *client_memory() { return bytes; }
const std::string &client_game_directory() { return directory; }
[[noreturn]] void client_fatal(const char *) { abort(); }

int main(int argc, char **argv) {
  if (argc != 2)
    return 1;
  directory = argv[1];
  client_wasi_init();
  for (int i = 0; i < 10; ++i) {
    memcpy(bytes, "scores.jsonl", 12);
    if (w2c_wasi__snapshot__preview1_path_open(nullptr, 3, 0, 0, 12, 1, (1 << 1) | (1 << 6), 0, 1, 100))
      return 2;
    u32 fd = load32(100);
    std::string line = "{\"v\":1,\"name\":\"native-" + std::to_string(i) + "\"}\n";
    memcpy(bytes + 256, line.data(), line.size());
    for (size_t at = 0; at < line.size();) {
      store32(128, 256 + at);
      store32(132, line.size() - at);
      if (w2c_wasi__snapshot__preview1_fd_write(nullptr, fd, 128, 1, 140))
        return 3;
      u32 written = load32(140);
      if (!written || written > 3)
        return 4;
      at += written;
    }
    if (w2c_wasi__snapshot__preview1_fd_sync(nullptr, fd) || w2c_wasi__snapshot__preview1_fd_close(nullptr, fd))
      return 5;
  }
}
