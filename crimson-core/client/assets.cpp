#include "assets.h"
#include "assets_version.h"
#include "../game/sha256.h"
#include <cstring>
#include <fstream>
#include <vector>

namespace {
std::string digest(const unsigned char *bytes, size_t size) {
  uint8_t hash[32], empty = 0;
  sha256(size ? bytes : &empty, size, hash);
  std::string result;
  for (uint8_t byte : hash) {
    result += "0123456789abcdef"[byte >> 4];
    result += "0123456789abcdef"[byte & 15];
  }
  return result;
}

bool read_file(const std::string &path, std::vector<uint8_t> &bytes) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  const auto size = file.tellg();
  if (size < 0)
    return false;
  bytes.resize(static_cast<size_t>(size));
  file.seekg(0);
  return bytes.empty() || bool(file.read(reinterpret_cast<char *>(bytes.data()), size));
}

bool valid_paq(const std::vector<uint8_t> &bytes) {
  if (bytes.size() < 4 || std::memcmp(bytes.data(), "paq\0", 4) != 0)
    return false;
  for (size_t at = 4; at < bytes.size();) {
    const uint8_t *end = static_cast<const uint8_t *>(std::memchr(bytes.data() + at, 0, bytes.size() - at));
    if (!end || bytes.data() + bytes.size() - end < 5)
      return false;
    const uint32_t size = uint32_t(end[1]) | uint32_t(end[2]) << 8 | uint32_t(end[3]) << 16 | uint32_t(end[4]) << 24;
    at = static_cast<size_t>(end - bytes.data()) + 5;
    if (size > bytes.size() - at)
      return false;
    at += size;
  }
  return true;
}
} // namespace

const char *pack_sha256(const std::string &name) {
  if (name == "music.paq")
    return MUSIC_PAQ_SHA256;
  if (name == "sfx.paq")
    return SFX_PAQ_SHA256;
  return CRIMSON_PAQ_SHA256;
}

bool pack_is_current(const std::string &name, const std::string &path) {
  std::vector<uint8_t> bytes;
  return read_file(path, bytes) && digest(bytes.data(), bytes.size()) == pack_sha256(name);
}

bool legacy_music_bytes(const unsigned char *data, size_t size) {
  return digest(data, size) == LEGACY_MUSIC_SHA256;
}

PackState pack_state(const std::string &name, const std::string &path) {
  std::vector<uint8_t> bytes;
  if (!read_file(path, bytes))
    return PackState::damaged;
  const std::string hash = digest(bytes.data(), bytes.size());
  if (hash == pack_sha256(name))
    return PackState::usable;
  if (name == "crimson.paq")
    for (const char *previous : PREVIOUS_CRIMSON_PAQ_SHA256)
      if (hash == previous)
        return PackState::outdated;
  return valid_paq(bytes) ? PackState::usable : PackState::damaged;
}
