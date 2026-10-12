#pragma once
#include <string>

bool artwork_needs_update(const std::string &path);
bool artwork_is_current(const std::string &path);
const char *artwork_sha256();
