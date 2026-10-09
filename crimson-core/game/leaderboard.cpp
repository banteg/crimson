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

namespace {

constexpr uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

uint32_t rotr(uint32_t x, int n) { return x >> n | x << (32 - n); }

void sha256_block(uint32_t state[8], const uint8_t block[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i)
    w[i] = (uint32_t)block[i * 4] << 24 | block[i * 4 + 1] << 16 | block[i * 4 + 2] << 8 | block[i * 4 + 3];
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >> 3;
    uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >> 10;
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6],
           h = state[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i];
    uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
  }
  state[0] += a, state[1] += b, state[2] += c, state[3] += d;
  state[4] += e, state[5] += f, state[6] += g, state[7] += h;
}

} // namespace

void sha256(const void *data, size_t size, uint8_t digest[32]) {
  uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  const uint8_t *bytes = (const uint8_t *)data;
  size_t whole = size / 64 * 64;
  for (size_t at = 0; at < whole; at += 64)
    sha256_block(state, bytes + at);
  // The rest, a one bit, zeros, and the length in bits, over one or two blocks.
  uint8_t tail[128] = {};
  size_t rest = size - whole, blocks = rest < 56 ? 1 : 2;
  memcpy(tail, bytes + whole, rest);
  tail[rest] = 0x80;
  uint64_t bits = (uint64_t)size * 8;
  for (int i = 0; i < 8; ++i)
    tail[blocks * 64 - 1 - i] = (uint8_t)(bits >> (8 * i));
  for (size_t block = 0; block < blocks; ++block)
    sha256_block(state, tail + block * 64);
  for (int i = 0; i < 8; ++i)
    for (int j = 0; j < 4; ++j)
      digest[i * 4 + j] = (uint8_t)(state[i] >> (24 - 8 * j));
}

// Level 9, as the Python port packs replays (src/crimson/replay/codec.py).
std::vector<uint8_t> zstd_pack(const std::vector<uint8_t> &payload, int level) {
  std::vector<uint8_t> out(ZSTD_compressBound(payload.size()));
  size_t size = ZSTD_compress(out.data(), out.size(), payload.data(), payload.size(), level);
  out.resize(ZSTD_isError(size) ? 0 : size);
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
