// What the leaderboard needs from a run's file: its digest, its zstd envelope and
// the player's key (src/crimson/leaderboard/identity.py, src/crimson/replay/codec.py).
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

void sha256(const void *data, size_t size, uint8_t digest[32]);
// The replay envelope: one zstd frame that declares its content size.
std::vector<uint8_t> zstd_pack(const std::vector<uint8_t> &payload);
// The payload of one such frame, at most `max_size` bytes; empty when it is not one.
std::vector<uint8_t> zstd_unpack(const uint8_t *data, size_t size, size_t max_size);

// The player's Ed25519 key: identity.key in the game directory holds its 32-byte
// seed, as the Python port keeps it, and is made on first use.
struct Identity {
  uint8_t secret[64]; // the seed, then the public key (Monocypher's layout)
  uint8_t public_key[32];
};
bool identity_load(Identity &identity);
void identity_sign(const Identity &identity, const void *message, size_t size, uint8_t signature[64]);

std::string hex(const uint8_t *data, size_t size);
std::string base64(const std::vector<uint8_t> &data);
