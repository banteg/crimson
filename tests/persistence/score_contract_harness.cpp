// Runs the production JSON parser and score decoder, without a window or a game build.
#include <cmath>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include "crimsonland_highscore.h"
#include "../../crimson-core/host/json.inc"
#include "../../crimson-core/host/scores_format.inc"

static void hex(const char *bytes, size_t size) {
  for (size_t i = 0; i < size; ++i)
    printf("%02x", (unsigned char)bytes[i]);
}
int main() {
  std::string line;
  while (std::getline(std::cin, line)) {
    Json parsed;
    ScoresStored stored;
    if (!json_parse(line.data(), line.size(), parsed, true) || !scores_read(parsed, stored)) {
      puts("invalid");
      continue;
    }
    hex((const char *)&stored.record, sizeof stored.record);
    printf(" %d %u ", stored.table.players, stored.table.cl_build);
    hex(stored.table.list.data(), stored.table.list.size());
    printf(" %s %s\n", stored.run.c_str(), stored.import_id.c_str());
  }
}
