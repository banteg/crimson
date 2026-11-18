#pragma once
#include <string>

enum class PackState { usable, outdated, damaged };
PackState pack_state(const std::string &name, const std::string &path);
const char *pack_sha256(const std::string &name);
bool pack_is_current(const std::string &name, const std::string &path);
bool legacy_music_bytes(const unsigned char *data, size_t size);
