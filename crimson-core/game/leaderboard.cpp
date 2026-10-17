// The leaderboard's digest, envelope and key (leaderboard.h). zstd 1.5.7 and
// Monocypher 4.0.2 are vendored in vendor/.
#include "leaderboard.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern "C" {
#include "vendor/monocypher-ed25519.h"
#include "vendor/zstd.h"
}

// Level 9, as the Python port packs replays (src/crimson/replay/codec.py).
std::vector<uint8_t> zstd_pack(const std::vector<uint8_t> &payload, int level) {
  std::vector<uint8_t> out(ZSTD_compressBound(payload.size()));
  size_t size = ZSTD_compress(out.data(), out.size(), payload.data(), payload.size(), level);
  out.resize(ZSTD_isError(size) ? 0 : size);
  // Kept packings (the viewer's keyframes) would otherwise hold the whole bound.
  out.shrink_to_fit();
  return out;
}

std::vector<uint8_t> zstd_unpack(const uint8_t *data, size_t size, size_t max_size) {
  unsigned long long content = ZSTD_getFrameContentSize(data, size);
  if (content == ZSTD_CONTENTSIZE_UNKNOWN || content == ZSTD_CONTENTSIZE_ERROR || content > max_size)
    return {};
  std::vector<uint8_t> out(content);
  size_t unpacked = ZSTD_decompress(out.data(), out.size(), data, size);
  if (ZSTD_isError(unpacked) || unpacked != content)
    return {};
  return out;
}

bool identity_load(Identity &identity) {
  uint8_t seed[32];
  FILE *fp = fopen("identity.key", "rb");
  bool read = fp && fread(seed, 1, sizeof seed, fp) == sizeof seed;
  if (fp)
    fclose(fp);
  if (!read) {
    if (getentropy(seed, sizeof seed) != 0 || !(fp = fopen("identity.key", "wb")))
      return false;
    bool written = fwrite(seed, 1, sizeof seed, fp) == sizeof seed;
    fclose(fp);
    if (!written)
      return false;
  }
  crypto_ed25519_key_pair(identity.secret, identity.public_key, seed);
  return true;
}

void identity_sign(const Identity &identity, const void *message, size_t size, uint8_t signature[64]) {
  crypto_ed25519_sign(signature, identity.secret, (const uint8_t *)message, size);
}

bool identity_verify(const uint8_t public_key[32], const uint8_t signature[64], const void *message, size_t size) {
  return crypto_ed25519_check(signature, public_key, (const uint8_t *)message, size) == 0;
}

std::string hex(const uint8_t *data, size_t size) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < size; ++i)
    out += digits[data[i] >> 4], out += digits[data[i] & 15];
  return out;
}

std::string base64(const std::vector<uint8_t> &data) {
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  for (size_t i = 0; i < data.size(); i += 3) {
    uint32_t n = data[i] << 16 | (i + 1 < data.size() ? data[i + 1] << 8 : 0) | (i + 2 < data.size() ? data[i + 2] : 0);
    out += alphabet[n >> 18 & 63];
    out += alphabet[n >> 12 & 63];
    out += i + 1 < data.size() ? alphabet[n >> 6 & 63] : '=';
    out += i + 2 < data.size() ? alphabet[n & 63] : '=';
  }
  return out;
}
