#include "assets.h"
#include "assets_version.h"
#include "../game/sha256.h"
#include <fstream>
#include <iterator>
#include <vector>

namespace {
std::string file_hash(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file)
    return {};
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  if (file.bad())
    return {};
  uint8_t digest[32];
  uint8_t empty = 0;
  sha256(bytes.empty() ? &empty : bytes.data(), bytes.size(), digest);
  std::string result;
  for (uint8_t byte : digest) {
    result += "0123456789abcdef"[byte >> 4];
    result += "0123456789abcdef"[byte & 15];
  }
  return result;
}
} // namespace

bool artwork_needs_update(const std::string &path) {
  std::string digest = file_hash(path);
  for (const char *previous : PREVIOUS_CRIMSON_PAQ_SHA256)
    if (digest == previous)
      return true;
  return false;
}

bool artwork_is_current(const std::string &path) { return file_hash(path) == CRIMSON_PAQ_SHA256; }
const char *artwork_sha256() { return CRIMSON_PAQ_SHA256; }
