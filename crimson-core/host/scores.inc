// Local high scores as the Python port keeps them (src/crimson/persistence/highscores.py,
// docs/formats/highscores.md): one record per line of scores.jsonl in the game
// folder, which both games share. The original's loader reads its table from
// there, encoded as the original's files held it (highscore_table_open), and
// highscore_save_record appends there (highscore_store). The original's
// scores5/*.hi tables import at startup (scores5.py) and move aside.
#include <algorithm>
#include <set>
#include <errno.h>

static const char SCORES_FILE[] = "scores.jsonl";

#include "scores_format.inc"
// The table the menus' settings name: on the high score screen the Play Game
// menu's build, and on a run's screens (its end, Typ-o's names, which a Typ-o
// run on another build than the last loads again: host/session.inc
// typo_names_start) the run's, which takes the menus' place for them
// (menu_cl_build).
static ScoresTable scores_table() {
  bool quest = config_blob.game_mode == GAME_MODE_QUEST;
  int slot = config_blob.selected_saved_name_slot;
  const char *list = config_blob.saved_names[slot];
  return {config_blob.game_mode, quest ? quest_stage_major : 0, quest ? quest_stage_minor : 0,
          quest && config_blob.hardcore, config_blob.player_count,
          slot ? std::string(list, strnlen(list, sizeof config_blob.saved_names[slot])) : "", menu_cl_build};
}

// A saved record: the original's, its table, and its run on the leaderboard ("" for none).
// ScoreTable.holds: only quests keep hardcore runs apart; each build keeps its own.
static bool scores_holds(const ScoresTable &table, const ScoresStored &stored) {
  const ScoresTable &own = stored.table;
  bool quest = table.mode == GAME_MODE_QUEST;
  return own.mode == table.mode && own.players == table.players && own.list == table.list &&
         own.cl_build == table.cl_build &&
         (!quest || (own.major == table.major && own.minor == table.minor && own.hardcore == table.hardcore));
}
// The high score screen's title and a score card name 1.9.8's tables and runs
// (screens/high_scores_view/main_panel.py, ui/highscore_card.py): the menus'
// build, which a run's screens and a replay's viewer take the place of. A 1.9.8
// card's origin line names the rules, and for a score from the Internet takes
// the original's shorter "Internet score" (its "Internet score of local
// origin"), within the card's widest native line. checks/game_rules.mjs reads
// both as the screens would draw them now, and finds them on the screens.
extern "C" __attribute__((export_name("game_scores_title_build"))) const char *scores_title_build() {
  return menu_cl_build == PORTABLE_CL_BUILD_1_9_8 ? " (1.9.8)" : "";
}
extern "C" __attribute__((export_name("game_scores_card_origin"))) const char *scores_card_origin(int received) {
  if (menu_cl_build != PORTABLE_CL_BUILD_1_9_8)
    return received ? "Score from the Internet" : "Local score";
  return received ? "Internet score, 1.9.8 rules" : "Local score, 1.9.8 rules";
}

// The replay the run that just ended saved, which its score names by number.
static struct {
  int number;
  std::string run;
  int rules;
} scores_linked;
static void scores_unlink() {
  memset(highscore_active_record.reserved0, 0, sizeof highscore_active_record.reserved0);
  scores_linked = {};
}
// The run's replay is `number` (0: none saved): the score record names it, and
// a score saved with that number links the run's leaderboard id and rules.
static void scores_link(int number, const std::vector<uint8_t> &payload) {
  memcpy(highscore_active_record.reserved0, &number, sizeof highscore_active_record.reserved0);
  uint8_t digest[32];
  sha256(payload.data(), payload.size(), digest);
  scores_linked = {number, hex(digest, 32), cfg.rules};
}

// A Latin-1 string as a JSON string in UTF-8, as msgspec writes it.
static void scores_json_text(std::string &out, const char *text, size_t size) {
  out += '"';
  for (size_t i = 0; i < size && text[i]; ++i) {
    unsigned char c = (unsigned char)text[i];
    char escape[8];
    if (c == '"' || c == '\\')
      out += '\\', out += (char)c;
    else if (c < 0x20)
      snprintf(escape, sizeof escape, "\\u%04x", c), out += escape;
    else if (c < 0x80)
      out += (char)c;
    else
      out += (char)(0xc0 | c >> 6), out += (char)(0x80 | (c & 0x3f));
  }
  out += '"';
}

// A record's line on `table`, its fields in HighScoreRecord's order and those
// at their defaults left out, as the Python port writes it; `linked` adds the
// run's.
static std::string scores_line(const highscore_record_t &record, bool hardcore, const ScoresTable &table, bool linked,
                               const std::string &import_id = "") {
  std::string out = "{\"v\":1";
  auto number = [&](const char *key, long long value) {
    if (value)
      out += std::string(",\"") + key + "\":" + std::to_string(value);
  };
  if (record.player_name[0])
    out += ",\"name\":", scores_json_text(out, record.player_name, sizeof record.player_name);
  number("game_mode_id", record.game_mode_id);
  if (record.game_mode_id == GAME_MODE_QUEST && record.quest_stage_major && record.quest_stage_minor)
    out += ",\"quest_level\":{\"major\":" + std::to_string(record.quest_stage_major) +
           ",\"minor\":" + std::to_string(record.quest_stage_minor) + "}";
  if (hardcore)
    out += ",\"hardcore\":true";
  if (table.players != 1)
    number("player_count", table.players);
  if (!table.list.empty())
    out += ",\"score_list\":", scores_json_text(out, table.list.data(), table.list.size());
  if (table.cl_build != PORTABLE_CL_BUILD_1_9_93)
    number("cl_build", table.cl_build);
  number("run_elapsed_ms", (int32_t)record.run_elapsed_ms);
  number("score_xp", record.score_xp);
  number("most_used_weapon_id", record.most_used_weapon_id);
  number("shots_fired", record.shots_fired);
  number("shots_hit", record.shots_hit);
  number("creature_kill_count", record.creature_kill_count);
  number("uni_num", record.random_tag);
  if (record.day) {
    char date[32];
    snprintf(date, sizeof date, ",\"date\":\"%04d-%02d-%02d\"", 2000 + record.year_offset, record.month, record.day);
    out += date;
  }
  uint32_t replay;
  memcpy(&replay, record.reserved0, sizeof replay);
  number("replay_number", replay);
  if (linked) {
    out += ",\"run\":\"" + scores_linked.run + "\"";
    out += ",\"rules\":" + std::to_string(scores_linked.rules);
    out += ",\"game_version\":", scores_json_text(out, CRIMSON_GAME_VERSION, sizeof CRIMSON_GAME_VERSION);
  }
  if (!import_id.empty())
    out += ",\"import_id\":\"" + import_id + "\"";
  return out + "}\n";
}

// Every saved record; a line that does not read (a torn write) is skipped.
static std::vector<ScoresStored> scores_load() {
  std::vector<ScoresStored> stored;
  std::set<std::string> imported;
  FILE *fp = platform_fopen(SCORES_FILE, "rb");
  if (!fp)
    return stored;
  std::string text;
  char chunk[4096];
  for (size_t n; (n = fread(chunk, 1, sizeof chunk, fp));)
    text.append(chunk, n);
  fclose(fp);
  for (size_t start = 0; start < text.size();) {
    size_t end = std::min(text.find('\n', start), text.size());
    Json line;
    ScoresStored each;
    if (json_parse(text.data() + start, end - start, line, true) && scores_read(line, each) &&
        (each.import_id.empty() || imported.insert(each.import_id).second))
      stored.push_back(each);
    start = end + 1;
  }
  return stored;
}

// The desktop host locks this a+b descriptor until close; the web host owns its
// directory. Finish partial writes under that lock, and flush before acknowledging.
static bool scores_append(std::string lines) {
  if (lines.empty())
    return true;
  FILE *fp = platform_fopen(SCORES_FILE, "a+b");
  if (!fp)
    return false;
  int fd = fileno(fp);
  off_t size = lseek(fd, 0, SEEK_END);
  char tail;
  bool written = size >= 0;
  if (size > 0) {
    written = lseek(fd, -1, SEEK_END) >= 0 && read(fd, &tail, 1) == 1;
    if (written && tail != '\n')
      lines.insert(0, "\n");
  }
  for (size_t at = 0; written && at < lines.size();) {
    ssize_t count = write(fd, lines.data() + at, lines.size() - at);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      written = false;
    else
      at += (size_t)count;
  }
  if (written)
    written = fsync(fd) == 0;
  if (!written && size >= 0)
    ftruncate(fd, size);
  return fclose(fp) == 0 && written;
}

// A local record the board holds: by run id, or for one imported from the
// original without one, by name, time and experience (records.py _same_run).
static bool scores_same_run(const ScoresStored &local, const ScoresRun &board) {
  if (!local.run.empty())
    return local.run == board.run;
  return !strcmp(board.record.player_name, local.record.player_name) &&
         board.record.run_elapsed_ms == local.record.run_elapsed_ms && board.record.score_xp == local.record.score_xp;
}

// scores5's table names: the original's, and Typ-o's under the name an earlier
// port gave it.
static bool scores5_table_name(const std::string &base) {
  if (base == "survival" || base == "rush" || base == "unknown" || base == "typo")
    return true;
  if (base.compare(0, 5, "quest"))
    return false;
  size_t at = base.compare(5, 2, "hc") ? 5 : 7;
  auto digits = [&] {
    size_t start = at;
    while (at < base.size() && isdigit((unsigned char)base[at]))
      ++at;
    return at > start;
  };
  return digits() && at < base.size() && base[at++] == '_' && digits() && at == base.size();
}
// A scores5 file's player count (the `_<players>` suffix) and named list (after
// `.hi`), or false when the file is not a table.
static bool scores5_file(const std::string &name, int &players, std::string &list) {
  size_t hi = name.find(".hi");
  if (hi == std::string::npos)
    return false;
  std::string base = name.substr(0, hi);
  list = name.substr(hi + 3);
  players = 1;
  if (scores5_table_name(base))
    return true;
  size_t n = base.size();
  if (n > 2 && base[n - 2] == '_' && base[n - 1] >= '2' && base[n - 1] <= '4' && scores5_table_name(base.substr(0, n - 2))) {
    players = base[n - 1] - '0';
    return true;
  }
  return false;
}

extern "C" {
// The table highscore_load_table reads: the shown table's saved records, with
// the shown board's kept runs after them while Show internet scores is ticked,
// so the original's filters and order take them in. A record the board holds
// turns green and takes the board's run instead of showing twice. Asks for a
// board it has not fetched yet.
FILE *highscore_table_open() {
  static char *table;
  scores_shown.clear();
  ScoresBoard board;
  std::vector<ScoresRun> runs;
  if (ranked_enabled && config_blob.show_online_scores && scores_board(board)) {
    auto kept = scores_kept.find(board);
    if (kept != scores_kept.end())
      runs = kept->second;
    else if (!scores_out && !scores_asked.count(board))
      scores_send(board, true);
  }
  size_t size = 0;
  free(table);
  table = nullptr;
  FILE *out = open_memstream(&table, &size);
  ScoresTable shown = scores_table();
  for (ScoresStored &stored : scores_load()) {
    if (!scores_holds(shown, stored))
      continue;
    highscore_record_t &record = stored.record;
    auto same = std::find_if(runs.begin(), runs.end(), [&](const ScoresRun &run) { return scores_same_run(stored, run); });
    if (same != runs.end())
      record.flags |= 1;
    highscore_write_record(&record, out);
    if (same != runs.end()) {
      scores_shown.push_back({record, same->run});
      runs.erase(same);
    }
  }
  for (ScoresRun &run : runs) {
    highscore_write_record(&run.record, out);
    scores_shown.push_back(run);
  }
  fclose(out);
  return fmemopen(table, size, "rb");
}

// highscore_save_record's write: the record goes to the shown table, dated as
// highscore_write_record dates it, with its replay's run when it names the one
// just saved. A record received from the internet stays out: the leaderboard
// serves those now. False when it could not be written.
bool highscore_store(highscore_record_t *record) {
  if ((record->flags & 1) && !(record->flags & 2))
    return true;
  if (!record->day) {
    time_t now = time(nullptr);
    if (struct tm *day = localtime(&now)) {
      record->day = (unsigned char)day->tm_mday;
      record->month = (unsigned char)(day->tm_mon + 1);
      record->year_offset = (unsigned char)(day->tm_year + 1900 - 2000);
      record->date_week = (unsigned char)highscore_iso_week(day->tm_year + 1900, day->tm_mon + 1, day->tm_mday);
    }
  }
  ScoresTable table = scores_table();
  bool quest = table.mode == GAME_MODE_QUEST;
  highscore_record_t saved = *record;
  saved.game_mode_id = (unsigned char)table.mode;
  saved.quest_stage_major = (unsigned char)table.major;
  saved.quest_stage_minor = (unsigned char)table.minor;
  int replay;
  memcpy(&replay, saved.reserved0, sizeof replay);
  bool hardcore = quest ? table.hardcore : saved.hardcore_marker == 0x75;
  return scores_append(scores_line(saved, hardcore, table, replay && replay == scores_linked.number));
}

// The original's tables, appended to scores.jsonl in name order, each then
// moved to scores5/imported/ (with .1, .2... when that name is taken), 1.9.93's
// runs. Records the original received from the internet stay out.
void scores_import() {
  DIR *dir = opendir("scores5");
  if (!dir)
    return;
  std::vector<std::string> names;
  while (dirent *entry = readdir(dir))
    names.push_back(entry->d_name);
  closedir(dir);
  std::sort(names.begin(), names.end());
  for (const std::string &name : names) {
    int players;
    std::string list;
    if (!scores5_file(name, players, list))
      continue;
    std::string path = "scores5/" + name;
    FILE *fp = platform_fopen(path.c_str(), "rb");
    if (!fp)
      continue;
    std::string data;
    char chunk[4096];
    for (size_t count; (count = fread(chunk, 1, sizeof chunk, fp));)
      data.append(chunk, count);
    bool read_ok = !ferror(fp);
    fclose(fp);
    if (!read_ok)
      continue;
    std::string source = name + '\0' + data;
    uint8_t digest[32];
    sha256((const uint8_t *)source.data(), source.size(), digest);
    std::string id = hex(digest, 32);
    fp = fmemopen(data.data(), data.size(), "rb");
    if (!fp)
      continue;
    std::string lines;
    highscore_record_t record;
    while (!feof(fp)) {
      long offset = ftell(fp);
      if (!highscore_read_record((char *)&record, fp) || ((record.flags & 1) && !(record.flags & 2)))
        continue;
      ScoresTable table = {record.game_mode_id, record.quest_stage_major, record.quest_stage_minor, false, players, list,
                           PORTABLE_CL_BUILD_1_9_93};
      std::string line = scores_line(record, record.hardcore_marker == 0x75, table, false, id + ":" + std::to_string(offset));
      Json parsed;
      ScoresStored checked;
      if (json_parse(line.data(), line.size(), parsed, true) && scores_read(parsed, checked))
        lines += line;
    }
    fclose(fp);
    if (!scores_append(lines))
      continue;
    mkdir("scores5/imported", 0755);
    std::string target = "scores5/imported/" + name;
    struct stat taken;
    for (int copy = 1; !stat(target.c_str(), &taken); ++copy)
      target = "scores5/imported/" + name + "." + std::to_string(copy);
    rename(path.c_str(), target.c_str());
  }
}
}
