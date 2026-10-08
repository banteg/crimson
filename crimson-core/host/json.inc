// JSON (RFC 8259) as the leaderboard answers it, read into values whose
// strings are Latin-1, the game's encoding: a code point past it reads as '?'.
struct Json {
  enum Kind { NUL, BOOLEAN, NUMBER, STRING, ARRAY, OBJECT } kind = NUL;
  double number = 0;
  std::string text;
  std::vector<Json> items;
  std::vector<std::pair<std::string, Json>> fields;

  const Json *field(const char *key, Kind kind) const {
    for (const auto &[name, value] : fields)
      if (name == key && value.kind == kind)
        return &value;
    return nullptr;
  }
};

struct JsonReader {
  // Deeper than any answer nests, shallow enough for the stack.
  static constexpr int max_depth = 16;
  const char *at, *end;

  void space() {
    while (at < end && (*at == ' ' || *at == '\t' || *at == '\n' || *at == '\r'))
      ++at;
  }
  bool word(const char *text) {
    size_t n = strlen(text);
    if ((size_t)(end - at) < n || memcmp(at, text, n))
      return false;
    at += n;
    return true;
  }
  bool digits() {
    const char *start = at;
    while (at < end && *at >= '0' && *at <= '9')
      ++at;
    return at > start;
  }
  bool number(double &out) {
    const char *start = at;
    if (at < end && *at == '-')
      ++at;
    if (at < end && *at == '0')
      ++at;
    else if (!digits())
      return false;
    if (at < end && *at == '.' && (++at, !digits()))
      return false;
    if (at < end && (*at == 'e' || *at == 'E')) {
      if (++at < end && (*at == '+' || *at == '-'))
        ++at;
      if (!digits())
        return false;
    }
    out = strtod(std::string(start, at).c_str(), nullptr);
    return std::isfinite(out);
  }
  bool string(std::string &out) {
    if (at == end || *at != '"')
      return false;
    for (++at; at < end;) {
      unsigned char c = (unsigned char)*at++;
      unsigned code = c;
      if (c == '"')
        return true;
      if (c < 0x20)
        return false;
      if (c == '\\') {
        static const char escapes[] = "\"\\/bfnrt", values[] = "\"\\/\b\f\n\r\t";
        const char *escape = at < end && *at ? strchr(escapes, *at) : nullptr;
        if (escape) {
          code = (unsigned char)values[escape - escapes];
          ++at;
        } else if (at < end && *at == 'u' && end - at > 4) {
          code = 0;
          for (int i = 1; i <= 4; ++i) {
            if (!isxdigit((unsigned char)at[i]))
              return false;
            code = code << 4 | (unsigned)(isdigit((unsigned char)at[i]) ? at[i] - '0' : (at[i] | 0x20) - 'a' + 10);
          }
          at += 5;
        } else {
          return false;
        }
      } else if (c >= 0x80) {
        // UTF-8: the lead byte says how many continuation bytes follow.
        int more = c >= 0xf8 ? -1 : c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc0 ? 1 : -1;
        if (more < 0 || end - at < more)
          return false;
        code = c & (0x3f >> more);
        for (int i = 0; i < more; ++i) {
          if ((at[i] & 0xc0) != 0x80)
            return false;
          code = code << 6 | (at[i] & 0x3f);
        }
        at += more;
      }
      out += code < 0x100 ? (char)code : '?';
    }
    return false;
  }
  bool value(Json &out, int depth) {
    space();
    if (at == end || depth > max_depth)
      return false;
    char open = *at;
    if (open == '{' || open == '[') {
      ++at;
      out.kind = open == '{' ? Json::OBJECT : Json::ARRAY;
      char close = open == '{' ? '}' : ']';
      space();
      if (at < end && *at == close)
        return ++at, true;
      for (;;) {
        Json item;
        if (open == '{') {
          std::string key;
          space();
          if (!string(key))
            return false;
          space();
          if (at == end || *at++ != ':' || !value(item, depth + 1))
            return false;
          out.fields.emplace_back(std::move(key), std::move(item));
        } else {
          if (!value(item, depth + 1))
            return false;
          out.items.push_back(std::move(item));
        }
        space();
        if (at == end)
          return false;
        char next = *at++;
        if (next == close)
          return true;
        if (next != ',')
          return false;
      }
    }
    if (open == '"')
      return out.kind = Json::STRING, string(out.text);
    if (word("true"))
      return out.kind = Json::BOOLEAN, out.number = 1, true;
    if (word("false"))
      return out.kind = Json::BOOLEAN, true;
    if (word("null"))
      return out.kind = Json::NUL, true;
    return out.kind = Json::NUMBER, number(out.number);
  }
};

// The whole of `size` bytes as one JSON value, or false when it is not.
static bool json_parse(const char *text, size_t size, Json &out) {
  JsonReader reader{text, text + size};
  if (!reader.value(out, 0))
    return false;
  reader.space();
  return reader.at == reader.end;
}
