// Original 56-byte .top entries and the mode/player dependent codec (0x406e10..0x406f89).
#include "game.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>

namespace freeware {
static const char *files[] = {"career.top", "career2.top", "rush.top", "rush2.top"};
static uint32_t score_key(size_t i, int board) {
  uint32_t n = uint32_t(i % 243);
  return (((n + 1) * n + uint32_t(1 + board % 2) + 6) * n + uint32_t(1 + board / 2) * 124) & 255;
}
static uint32_t weight(size_t i) {
  // The game runs the x87 unit at single precision. Round the product before truncating.
  return static_cast<uint32_t>(float(i) * .7f);
}
template <typename T> static T load(const uint8_t *p) {
  T value;
  std::memcpy(&value, p, 4);
  return value;
}
template <typename T> static void put(uint8_t *p, T value) { std::memcpy(p, &value, 4); }
static void sort_scores(std::vector<Score> &table, bool survival) {
  std::stable_sort(table.begin(), table.end(), [=](const Score &a, const Score &b) {
    return survival ? a.seconds > b.seconds : a.experience > b.experience;
  });
}
bool decode_scores(std::vector<uint8_t> bytes, int board, std::vector<Score> &out) {
  if (bytes.size() < 4 || (bytes.size() - 4) % 56)
    return false;
  size_t size = bytes.size() - 4;
  uint32_t sum = 0;
  for (size_t i = 0; i < size; ++i) {
    bytes[i] = uint8_t(bytes[i] - score_key(i, board));
    sum += weight(i) * int8_t(bytes[i]);
  }
  if (sum != load<uint32_t>(&bytes[size]))
    return false;
  std::vector<Score> decoded;
  for (size_t i = 0; i < size; i += 56) {
    auto *p = &bytes[i];
    auto len = std::find(p, p + 32, 0) - p;
    if (len == 32)
      return false;
    Score s{};
    s.name.assign(reinterpret_cast<const char *>(p), len);
    s.seconds = float(load<int32_t>(p + 32));
    s.experience = load<int32_t>(p + 36);
    s.min_fps = load<float>(p + 40);
    s.average_fps = load<float>(p + 44);
    s.max_fps = load<float>(p + 48);
    s.version = load<float>(p + 52);
    decoded.push_back(s);
  }
  sort_scores(decoded, board >= 2);
  out.swap(decoded);
  return true;
}
std::vector<uint8_t> encode_scores(const std::vector<Score> &table, int board) {
  std::vector<uint8_t> bytes(table.size() * 56 + 4);
  for (size_t i = 0; i < table.size(); ++i) {
    auto *p = &bytes[i * 56];
    const auto &s = table[i];
    std::memcpy(p, s.name.data(), std::min<size_t>(31, s.name.size()));
    put(p + 32, int32_t(s.seconds));
    put(p + 36, int32_t(s.experience));
    put(p + 40, s.min_fps);
    put(p + 44, s.average_fps);
    put(p + 48, s.max_fps);
    put(p + 52, s.version);
  }
  uint32_t sum = 0;
  size_t size = bytes.size() - 4;
  for (size_t i = 0; i < size; ++i) {
    sum += weight(i) * int8_t(bytes[i]);
    bytes[i] = uint8_t(bytes[i] + score_key(i, board));
  }
  put(bytes.data() + size, sum);
  return bytes;
}
void Game::load_scores() {
  if (save_dir.empty())
    return;
  for (int i = 0; i < 4; i++) {
    std::ifstream f(save_dir + files[i], std::ios::binary);
    if (!f)
      continue;
    invalid_scores[i] = !decode_scores({std::istreambuf_iterator<char>(f), {}}, i, rankings[i]);
    if (invalid_scores[i])
      std::fprintf(stderr, "Invalid 1.4.0 score file %s\n", files[i]);
  }
}
void Game::record_score() {
  Score score{};
  score.name = name;
  score.seconds = int(run.seconds);
  score.kills = run.kills;
  score.experience = run.experience;
  score.min_fps = run.min_fps;
  score.average_fps = run.seconds > 0 ? run.frames / run.seconds : 0;
  score.max_fps = run.max_fps;
  auto &table = scores();
  table.push_back(score);
  sort_scores(table, survival);
  if (save_dir.empty())
    return;
  const int board = (survival ? 2 : 0) + int(two_players);
  std::string path = save_dir + files[board], tmp = path + ".tmp";
  // A damaged original score file remains available for inspection and repair.
  if (invalid_scores[board])
    return;
  auto bytes = encode_scores(table, board);
  std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
  f.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  f.close();
  if (!f || std::rename(tmp.c_str(), path.c_str()) != 0)
    std::fprintf(stderr, "Could not save %s\n", path.c_str());
}
} // namespace freeware
