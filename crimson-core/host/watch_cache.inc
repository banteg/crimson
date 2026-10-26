// A prepared replay kept on disk, for the next time it plays (host/watch.inc's
// preparing pass, CRIMSON_WATCH_CACHE in client/main.cpp): the pass's keyframes,
// marks and tunes, the terrain's bake logs, and its copies as the host reads
// them back. The host's build names them: another build may play or draw a
// replay differently, and the terrain differs by render mode.
extern "C" int rtx_render_mode; // game/rtx.cpp
static char watch_cache_build[65]; // the host's build, or "" for none
static constexpr int WATCH_CACHE_KEPT = 16;
static constexpr uint32_t WATCH_CACHE_MAGIC = 0x31435743; // "CWC1"

__attribute__((export_name("game_watch_cache"))) char *game_watch_cache() { return watch_cache_build; }

static std::string watch_cache_path() {
  const LoadedReplay &replay = watch.replay;
  std::vector<uint8_t> named(replay.recording);
  named.insert(named.end(), replay.result.begin(), replay.result.end());
  const uint8_t *pickers = (const uint8_t *)replay.pickers.data();
  named.insert(named.end(), pickers, pickers + replay.pickers.size() * sizeof(int));
  uint8_t digest[32];
  sha256(named.data(), named.size(), digest);
  return "cache/prepared/" + std::string(watch_cache_build, 16) + "-" + hex(digest, 16) +
         (rtx_render_mode ? "-rtx" : "") + ".bin";
}

struct WatchCacheOut {
  std::vector<uint8_t> bytes;
  template <class T> void put(const T &value) {
    const uint8_t *at = (const uint8_t *)&value;
    bytes.insert(bytes.end(), at, at + sizeof value);
  }
  template <class T> void put(const std::vector<T> &values) {
    put(values.size());
    const uint8_t *at = (const uint8_t *)values.data();
    bytes.insert(bytes.end(), at, at + values.size() * sizeof(T));
  }
  template <class T> void put(const PackedLog<T> &log) {
    put(log.blocks.size());
    for (const std::vector<uint8_t> &block : log.blocks)
      put(block);
    put(log.open);
  }
};

// A file read as it was written, short or not.
struct WatchCacheIn {
  const uint8_t *at, *end;
  bool ok = true;
  bool take(void *out, size_t size) {
    ok = ok && (size_t)(end - at) >= size;
    if (ok)
      memcpy(out, at, size), at += size;
    return ok;
  }
  template <class T> void get(T &value) { take(&value, sizeof value); }
  template <class T> void get(std::vector<T> &values) {
    size_t count = 0;
    get(count);
    ok = ok && count <= (size_t)(end - at) / sizeof(T);
    values.resize(ok ? count : 0);
    take(values.data(), values.size() * sizeof(T));
  }
  template <class T> void get(PackedLog<T> &log) {
    size_t blocks = 0;
    get(blocks);
    ok = ok && blocks <= (size_t)(end - at);
    log.clear();
    log.blocks.resize(ok ? blocks : 0);
    for (std::vector<uint8_t> &block : log.blocks)
      get(block);
    get(log.open);
  }
};

// The pass just prepared, onto disk: not where the host cannot read the
// terrain's copies back.
static void watch_cache_save() {
  if (!*watch_cache_build || !host_texture_read(terrain.shots.front().id, nullptr, 0))
    return;
  WatchCacheOut out;
  out.put(WATCH_CACHE_MAGIC);
  out.put(watch.ticks);
  out.put(watch.played);
  out.put(std::vector<char>(watch.stopped.begin(), watch.stopped.end()));
  out.put(watch.key_ticks);
  out.put(watch.keys.size());
  for (const Keyframe &key : watch.keys) {
    out.put(key.tick);
    out.put(key.at);
    out.put(key.batches);
    out.put(key.packed);
  }
  out.put(watch.picks);
  out.put(watch.marks);
  out.put(watch.tunes);
  out.put(terrain.batches);
  out.put(terrain.queue);
  out.put(terrain.rotated);
  out.put(terrain.shots.size());
  for (const TerrainShot &shot : terrain.shots) {
    std::vector<uint8_t> pixels(host_texture_read(shot.id, nullptr, 0));
    host_texture_read(shot.id, pixels.data(), (int)pixels.size());
    out.put(shot.batches);
    out.put(shot.tick);
    out.put(zstd_pack(pixels, 1));
  }
  mkdir("cache", 0755);
  mkdir("cache/prepared", 0755);
  prune_oldest("cache/prepared", ".bin", WATCH_CACHE_KEPT);
  std::string path = watch_cache_path(), writing = path + ".writing";
  FILE *fp = platform_fopen(writing.c_str(), "wb");
  if (!fp)
    return;
  bool written = fwrite(out.bytes.data(), 1, out.bytes.size(), fp) == out.bytes.size();
  if (fclose(fp) == 0 && written)
    rename(writing.c_str(), path.c_str());
  else
    unlink(writing.c_str());
}

// The pass kept for this replay, in place of preparing it: false, with nothing
// changed, for none.
static bool watch_cache_load() {
  if (!*watch_cache_build)
    return false;
  FILE *fp = platform_fopen(watch_cache_path().c_str(), "rb");
  if (!fp)
    return false;
  std::vector<uint8_t> file;
  uint8_t chunk[1 << 16];
  for (size_t n; (n = fread(chunk, 1, sizeof chunk, fp));)
    file.insert(file.end(), chunk, chunk + n);
  fclose(fp);
  WatchCacheIn in{file.data(), file.data() + file.size()};
  uint32_t magic = 0;
  int ticks = 0, key_ticks = 0;
  bool played = false;
  std::vector<char> stopped;
  std::vector<Keyframe> keys;
  std::vector<WatchPick> picks;
  std::vector<WatchMark> marks;
  std::vector<WatchTune> tunes;
  std::vector<DecalBatch> batches;
  PackedLog<fx_queue_entry_t> queue;
  PackedLog<RotatedDecal> rotated;
  in.get(magic);
  in.ok = in.ok && magic == WATCH_CACHE_MAGIC;
  in.get(ticks);
  in.get(played);
  in.get(stopped);
  in.get(key_ticks);
  size_t count = 0;
  in.get(count);
  for (size_t i = 0; in.ok && i < count; ++i) {
    Keyframe key;
    in.get(key.tick);
    in.get(key.at);
    in.get(key.batches);
    in.get(key.packed);
    keys.push_back(std::move(key));
  }
  in.get(picks);
  in.get(marks);
  in.get(tunes);
  in.get(batches);
  in.get(queue);
  in.get(rotated);
  in.get(count);
  // The copies go to the host as they come; a copy it refuses (a terrain of
  // another size) drops them all.
  std::vector<TerrainShot> shots;
  for (size_t i = 0; in.ok && i < count; ++i) {
    TerrainShot shot = {0, 0, TERRAIN_SHOT_IDS + terrain.next_shot_id++};
    std::vector<uint8_t> packed;
    in.get(shot.batches);
    in.get(shot.tick);
    in.get(packed);
    std::vector<uint8_t> pixels = in.ok ? zstd_unpack(packed.data(), packed.size(), 256u << 20) : packed;
    in.ok = in.ok && host_texture_write(shot.id, terrain_host_id(), pixels.data(), (int)pixels.size());
    shots.push_back(shot);
  }
  in.ok = in.ok && in.at == in.end && !keys.empty() && !shots.empty();
  if (!in.ok) {
    for (const TerrainShot &shot : shots)
      host_texture_release(shot.id);
    return false;
  }
  for (const TerrainShot &shot : terrain.shots)
    host_texture_release(shot.id);
  terrain.shots = std::move(shots);
  terrain.batches = std::move(batches);
  terrain.queue = std::move(queue);
  terrain.rotated = std::move(rotated);
  watch.ticks = ticks;
  watch.played = played;
  watch.stopped.assign(stopped.begin(), stopped.end());
  watch.key_ticks = key_ticks;
  watch.keys = std::move(keys);
  watch.picks = std::move(picks);
  watch.marks = std::move(marks);
  watch.tunes = std::move(tunes);
  // Where the pass leaves playback: at the end, which a seek restores a keyframe from.
  watch.tick = ticks;
  return true;
}
