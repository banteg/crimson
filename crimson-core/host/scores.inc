// Local high scores as the Python port keeps them (src/crimson/persistence/highscores.py,
// docs/formats/highscores.md): one record per line of scores.jsonl in the game
// folder, which both games share. The original's loader reads its table from
// there, encoded as the original's files held it (highscore_table_open), and
// highscore_save_record appends there (highscore_store). The original's
// scores5/*.hi tables import at startup (scores5.py) and move aside.
#include <algorithm>

static const char SCORES_FILE[] = "scores.jsonl";

// A table: the mode, a quest's level and difficulty, the players and the named
// list, as highscore_build_path names the original's file.
struct ScoresTable {
  int mode, major, minor;
  bool hardcore;
  int players;
  std::string list;
};
// The table the menus' settings name.
static ScoresTable scores_table() {
  bool quest = config_blob.game_mode == GAME_MODE_QUEST;
  int slot = config_blob.selected_saved_name_slot;
  const char *list = config_blob.saved_names[slot];
  return {config_blob.game_mode, quest ? quest_stage_major : 0, quest ? quest_stage_minor : 0,
          quest && config_blob.hardcore, config_blob.player_count,
          slot ? std::string(list, strnlen(list, sizeof config_blob.saved_names[slot])) : ""};
}

// A saved record: the original's, its table, and its run on the leaderboard ("" for none).
struct ScoresStored {
  highscore_record_t record;
  ScoresTable table;
  std::string run;
};
// ScoreTable.holds: only quests keep hardcore runs apart.
static bool scores_holds(const ScoresTable &table, const ScoresStored &stored) {
  const ScoresTable &own = stored.table;
  bool quest = table.mode == GAME_MODE_QUEST;
  return own.mode == table.mode && own.players == table.players && own.list == table.list &&
         (!quest || (own.major == table.major && own.minor == table.minor && own.hardcore == table.hardcore));
}

// The replay the run that just ended saved, which its score names by number.
static struct {
  int number;
  std::string run;
  int rules;
} scores_linked;
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

// A record's line, its fields in HighScoreRecord's order and those at their
// defaults left out, as the Python port writes it; `linked` adds the run's.
static std::string scores_line(const highscore_record_t &record, bool hardcore, int players, const std::string &list,
                               bool linked) {
  std::string out = "{\"v\":1";
  auto number = [&](const char *key, long long value) {
    if (value)
      out += std::string(",\"") + key + "\":" + std::to_string(value);
  };
  if (record.player_name[0])
    out += ",\"name\":", scores_json_text(out, record.player_name, sizeof record.player_name);
  number("game_mode_id", record.game_mode_id);
  if (record.quest_stage_major && record.quest_stage_minor)
    out += ",\"quest_level\":{\"major\":" + std::to_string(record.quest_stage_major) +
           ",\"minor\":" + std::to_string(record.quest_stage_minor) + "}";
  if (hardcore)
    out += ",\"hardcore\":true";
  if (players != 1)
    number("player_count", players);
  if (!list.empty())
    out += ",\"score_list\":", scores_json_text(out, list.data(), list.size());
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
    number("rules", scores_linked.rules);
    out += ",\"game_version\":", scores_json_text(out, CRIMSON_GAME_VERSION, sizeof CRIMSON_GAME_VERSION);
  }
  return out + "}\n";
}

// A line as the record the original keeps, or false when it is not one.
static bool scores_read(const Json &line, ScoresStored &out) {
  const Json *version = line.field("v", Json::NUMBER);
  if (line.kind != Json::OBJECT || !version || version->number != 1)
    return false;
  auto number = [&](const char *key, double fallback = 0) {
    const Json *value = line.field(key, Json::NUMBER);
    return value ? value->number : fallback;
  };
  auto text = [&](const char *key) {
    const Json *value = line.field(key, Json::STRING);
    return value ? value->text : std::string();
  };
  highscore_record_t &record = out.record;
  record = {};
  snprintf(record.player_name, sizeof record.player_name, "%s", text("name").c_str());
  record.game_mode_id = (unsigned char)number("game_mode_id");
  if (const Json *quest = line.field("quest_level", Json::OBJECT)) {
    const Json *major = quest->field("major", Json::NUMBER), *minor = quest->field("minor", Json::NUMBER);
    record.quest_stage_major = major ? (unsigned char)major->number : 0;
    record.quest_stage_minor = minor ? (unsigned char)minor->number : 0;
  }
  const Json *hardcore = line.field("hardcore", Json::BOOLEAN);
  out.table = {record.game_mode_id, record.quest_stage_major, record.quest_stage_minor, hardcore && hardcore->number,
               (int)number("player_count", 1), text("score_list")};
  record.run_elapsed_ms = (uint32_t)(int32_t)number("run_elapsed_ms");
  record.score_xp = (uint32_t)number("score_xp");
  record.most_used_weapon_id = (unsigned char)number("most_used_weapon_id");
  record.shots_fired = (uint32_t)number("shots_fired");
  record.shots_hit = (uint32_t)number("shots_hit");
  record.creature_kill_count = (uint32_t)number("creature_kill_count");
  record.random_tag = (uint32_t)number("uni_num");
  uint32_t replay = (uint32_t)number("replay_number");
  memcpy(record.reserved0, &replay, sizeof replay);
  int year, month, day;
  if (sscanf(text("date").c_str(), "%d-%d-%d", &year, &month, &day) == 3) {
    record.day = (unsigned char)day;
    record.month = (unsigned char)month;
    record.year_offset = (unsigned char)(year - 2000);
    record.date_week = (unsigned char)highscore_iso_week(year, month, day);
  }
  record.hardcore_marker = out.table.hardcore ? 0x75 : 0;
  record.sentinel_pipe = 0x7c;
  record.sentinel_ff = 0xff;
  out.run = text("run");
  return true;
}

// Every saved record; a line that does not read (a torn write) is skipped.
static std::vector<ScoresStored> scores_load() {
  std::vector<ScoresStored> stored;
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
    if (json_parse(text.data() + start, end - start, line) && scores_read(line, each))
      stored.push_back(each);
    start = end + 1;
  }
  return stored;
}

// Appends lines in one write, after a newline when a torn last line lacks one.
static bool scores_append(std::string lines) {
  if (lines.empty())
    return true;
  if (FILE *fp = platform_fopen(SCORES_FILE, "rb")) {
    if (!fseek(fp, -1, SEEK_END) && fgetc(fp) != '\n')
      lines.insert(0, "\n");
    fclose(fp);
  }
  FILE *fp = platform_fopen(SCORES_FILE, "ab");
  if (!fp)
    return false;
  bool written = fwrite(lines.data(), 1, lines.size(), fp) == lines.size();
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
  return scores_append(scores_line(saved, hardcore, table.players, table.list, replay && replay == scores_linked.number));
}

// The original's tables, appended to scores.jsonl in name order, each then
// moved to scores5/imported/ (with .1, .2... when that name is taken). Records
// the original received from the internet stay out.
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
    std::string lines;
    highscore_record_t record;
    while (!feof(fp)) {
      if (!highscore_read_record((char *)&record, fp) || ((record.flags & 1) && !(record.flags & 2)))
        continue;
      lines += scores_line(record, record.hardcore_marker == 0x75, players, list, false);
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
