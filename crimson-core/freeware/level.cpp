// The released modes have empty object layers. The original frame also contains a
// level test and an editor, both using these 0x30-byte objects and 0x28-byte triggers.
#include "freeware_level.h"
#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

extern freeware::Game *freeware_frame_game;
extern "C" void creature_reset_all();
extern "C" float freeware_elapsed_seconds, freeware_pickup_time, freeware_berserk_timer;
extern "C" int freeware_pickup_id, freeware_no_pickup;
static_assert(sizeof(freeware_level_object) == 0x30 && sizeof(freeware_level_trigger) == 0x28);

namespace {
template <class T> void add(freeware_level_list<T> &list, T *entry) {
  std::unique_ptr<T> item(entry);
  int n = list.size();
  if (list.end == list.capacity) {
    int size = n ? n * 2 : 4;
    auto pointers = std::make_unique<T *[]>(size);
    if (n)
      std::copy_n(list.begin, n, pointers.get());
    delete[] list.begin;
    list.begin = pointers.release();
    list.end = list.begin + n;
    list.capacity = list.begin + size;
  }
  *list.end++ = item.release();
}
template <class T> void clear_list(freeware_level_list<T> &list) {
  for (auto it = list.begin; it != list.end; ++it)
    delete *it;
  delete[] list.begin;
  list = {};
}
std::string level_path(const char *file) {
  std::string name = file;
  std::replace(name.begin(), name.end(), '\\', '/');
  return freeware_frame_game->save_dir + name;
}
constexpr char signature[] = "Crimsonland level v.0.0.2b";
template <class T> bool write_list(std::FILE *f, const freeware_level_list<T> &list) {
  for (auto it = list.begin; it != list.end; ++it)
    if (std::fwrite(*it, sizeof(T), 1, f) != 1)
      return false;
  return true;
}
template <class T> bool read_list(std::FILE *f, freeware_level_list<T> &list, int count) {
  if (count < 0)
    return false;
  for (int i = 0; i < count; ++i) {
    auto item = std::make_unique<T>();
    if (std::fread(item.get(), sizeof(T), 1, f) != 1)
      return false;
    add(list, item.release());
  }
  return true;
}
} // namespace
void freeware_level_map::clear() {
  flag = 0;
  for (auto &layer : layers)
    clear_list(layer);
  clear_list(triggers);
}
void freeware_level_map::add_object(int layer, freeware_level_object *object) { add(layers[layer], object); }
void freeware_level_map::add_trigger(freeware_level_trigger *trigger) { add(triggers, trigger); }
bool freeware_level_map::save(const char *path) {
  auto target = level_path(path);
  auto tmp = target + ".tmp";
  auto *f = std::fopen(tmp.c_str(), "wb");
  if (!f)
    return false;
  char header[28]{};
  std::memcpy(header, signature, sizeof(signature));
  int counts[] = {triggers.size(), layers[0].size(), layers[1].size(), layers[2].size()};
  bool ok = std::fwrite(header, 28, 1, f) == 1 && std::fwrite(&start, 8, 1, f) == 1 &&
            std::fwrite(&start_heading, 4, 1, f) == 1 && std::fwrite(&flag, 1, 1, f) == 1 &&
            std::fwrite(counts, sizeof(counts), 1, f) == 1 && write_list(f, triggers);
  for (auto &layer : layers)
    ok = ok && write_list(f, layer);
  ok = std::fclose(f) == 0 && ok && std::rename(tmp.c_str(), target.c_str()) == 0;
  if (!ok)
    std::remove(tmp.c_str());
  return ok;
}
bool freeware_level_map::load(const char *path) {
  auto *f = std::fopen(level_path(path).c_str(), "rb");
  if (!f)
    return false;
  freeware_level_map next{};
  char header[28];
  int counts[4];
  bool ok = std::fread(header, 28, 1, f) == 1 && !std::memcmp(header, signature, sizeof(signature)) &&
            std::fread(&next.start, 8, 1, f) == 1 && std::fread(&next.start_heading, 4, 1, f) == 1 &&
            std::fread(&next.flag, 1, 1, f) == 1 && std::fread(counts, sizeof(counts), 1, f) == 1 &&
            read_list(f, next.triggers, counts[0]);
  for (int i = 0; i < 3 && ok; ++i)
    ok = read_list(f, next.layers[i], counts[i + 1]);
  std::fclose(f);
  if (ok)
    std::swap(*this, next);
  next.clear();
  return ok;
}
void freeware_level_map::arm_triggers() {
  for (auto it = triggers.begin; it != triggers.end; ++it)
    (*it)->enabled = 1;
}
void freeware_level_map::update_triggers() {
  auto &g = *freeware_frame_game;
  for (auto it = triggers.begin; it != triggers.end; ++it) {
    auto &t = **it;
    if (!t.enabled)
      continue;
    if (t.type == 0) {
      effect_color_t color = {.8f, .8f, .8f, 1};
      auto &c = creature_pool[creature_spawn(&t.position, &color, 1)];
      c.ai_mode = 0;
      c.activation_radius = t.radius;
      t.enabled = 0;
    } else if (t.type == 2 &&
               std::hypot(t.position.x - g.run.player.x, t.position.y - g.run.player.y) < t.radius) {
      weapon_assign_player(0, t.weapon);
      t.enabled = 0;
    }
  }
}

void freeware_level_map::render_layer(int layer, int) {
  auto &g = *freeware_frame_game;
  for (auto it = layers[layer].begin; it != layers[layer].end; ++it) {
    auto &o = **it;
    auto brush = std::find_if(g.brushes.begin(), g.brushes.end(),
                              [&o](const auto &b) { return b.object.texture == o.texture; });
    if (brush != g.brushes.end())
      g.frame_sprites.push_back({brush->name.c_str(), g.camera.x + o.position.x, g.camera.y + o.position.y,
                                 o.width, o.height, o.rotation, o.color});
  }
}
void freeware_level_map::render_triggers(unsigned char playing) {
  if (playing)
    return;
  auto &g = *freeware_frame_game;
  for (auto it = triggers.begin; it != triggers.end; ++it) {
    auto &t = **it;
    g.frame_sprites.push_back({"radius",
                               g.camera.x + t.position.x - t.radius,
                               g.camera.y + t.position.y - t.radius,
                               t.radius * 2,
                               t.radius * 2,
                               0,
                               {1, 1, 1, .6f}});
  }
}
void freeware::Game::load_next_level() {
  creature_reset_all();
  ++level_number;
  char path[48];
  std::snprintf(path, sizeof(path), "levels/level_%d.lvl", level_number);
  if (!freeware_current_map->load(path)) {
    level_number = 1;
    freeware_current_map->load("levels/level_1.lvl");
  }
  generate_terrain();
  for (auto &shot : projectile_pool)
    shot.active = 0;
  for (auto &sprite : sprite_effect_pool)
    sprite.active = 0;
  for (auto &rocket : secondary_projectile_pool)
    rocket.active = 0;
  freeware_pickup_id = freeware_no_pickup;
  run.seconds = freeware_elapsed_seconds = run.pickup.time = freeware_pickup_time = run.berserk =
      freeware_berserk_timer = 0;
  for (int i = 0; i < 2; ++i) {
    auto &p = player_state_table[i].freeware;
    p.position = freeware_current_map->start;
    if (i == 1)
      p.position.x += 80;
    p.shield = p.control_reserved = 0;
    p.plaguebearer = 0;
    p.size = 48;
    p.speed_multiplier = 2;
    p.heading = freeware_current_map->start_heading;
    p.spread = 1;
    p.move_speed = 0;
    p.ammo = p.clip_size = 10;
    p.reload_duration = 1;
    p.reload = 0;
    p.cooldown = .8f;
    p.weapon = 1;
    actor(i).player = p.position;
    actor(i).body_angle = p.heading;
    actor(i).spread = 1;
    actor(i).shield = 0;
    actor(i).cooldown = .8f;
  }
  cursor_x = 320;
  cursor_y = 140;
  current_player_index = 0;
  for (auto &c : creature_pool)
    c.plague_infected = 0;
  freeware_current_map->arm_triggers();
}
