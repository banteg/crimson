// The scores.jsonl v1 decoder, shared by the game and the contract harness.
struct ScoresTable {
  int mode, major, minor;
  bool hardcore;
  int players;
  std::string list;
};
struct ScoresStored {
  highscore_record_t record;
  ScoresTable table;
  std::string run, import_id;
};

static bool score_integer(const Json &value, double low, double high) {
  return value.kind == Json::NUMBER && value.integer && value.number >= low && value.number <= high;
}
static bool score_hex(const std::string &value) {
  return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
}
static bool score_date(const std::string &text, int &year, int &month, int &day) {
  if (text.size() != 10 || text[4] != '-' || text[7] != '-')
    return false;
  for (size_t i = 0; i < text.size(); ++i)
    if (i != 4 && i != 7 && (text[i] < '0' || text[i] > '9'))
      return false;
  if (sscanf(text.c_str(), "%d-%d-%d", &year, &month, &day) != 3 || year < 2000 || year > 2255 || month < 1 || month > 12)
    return false;
  static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  return day >= 1 && day <= days[month - 1] + (month == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
}

static bool scores_read(const Json &line, ScoresStored &out) {
  if (line.kind != Json::OBJECT)
    return false;
  const Json *version = line.field("v", Json::NUMBER);
  if (!version || !score_integer(*version, 1, 1))
    return false;
  for (const auto &[key, value] : line.fields) {
    bool valid = false;
    if (key == "v")
      valid = score_integer(value, 1, 1);
    else if (key == "game_mode_id")
      valid = score_integer(value, 0, 4) || score_integer(value, 8, 8);
    else if (key == "most_used_weapon_id")
      valid = score_integer(value, 0, 53);
    else if (key == "player_count")
      valid = score_integer(value, 1, 4);
    else if (key == "run_elapsed_ms")
      valid = score_integer(value, -2147483648.0, 2147483647.0);
    else if (key == "score_xp" || key == "shots_fired" || key == "shots_hit" || key == "creature_kill_count" ||
             key == "uni_num" || key == "replay_number" || key == "rules")
      valid = (key == "rules" && value.kind == Json::NUL) || score_integer(value, 0, 4294967295.0);
    else if (key == "hardcore" || key == "received")
      valid = value.kind == Json::BOOLEAN && (key != "received" || !value.number);
    else if (key == "name" || key == "score_list" || key == "game_version")
      valid = value.kind == Json::STRING && (key == "game_version" || value.text.size() <= 31);
    else if (key == "run")
      valid = value.kind == Json::STRING && (value.text.empty() || score_hex(value.text));
    else if (key == "import_id") {
      const std::string &id = value.text;
      valid = value.kind == Json::STRING && (id.empty() ||
          (id.size() > 65 && id[64] == ':' && score_hex(id.substr(0, 64)) &&
           id.find_first_not_of("0123456789", 65) == std::string::npos));
    } else if (key == "date") {
      int year, month, day;
      valid = value.kind == Json::NUL || (value.kind == Json::STRING && score_date(value.text, year, month, day));
    } else if (key == "quest_level") {
      const Json *major = value.field("major", Json::NUMBER), *minor = value.field("minor", Json::NUMBER);
      valid = value.kind == Json::NUL || (value.kind == Json::OBJECT && value.fields.size() == 2 &&
          major && minor && score_integer(*major, 1, 5) && score_integer(*minor, 1, 10));
    }
    if (!valid)
      return false;
  }
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
    if (record.game_mode_id != GAME_MODE_QUEST)
      return false;
    record.quest_stage_major = (unsigned char)quest->field("major", Json::NUMBER)->number;
    record.quest_stage_minor = (unsigned char)quest->field("minor", Json::NUMBER)->number;
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
  if (score_date(text("date"), year, month, day)) {
    record.day = (unsigned char)day;
    record.month = (unsigned char)month;
    record.year_offset = (unsigned char)(year - 2000);
    record.date_week = (unsigned char)highscore_iso_week(year, month, day);
  }
  record.hardcore_marker = out.table.hardcore ? 0x75 : 0;
  record.sentinel_pipe = 0x7c;
  record.sentinel_ff = 0xff;
  out.run = text("run");
  out.import_id = text("import_id");
  return true;
}
