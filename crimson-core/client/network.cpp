// Desktop leaderboard HTTP and file work. The web host uses shell.html instead.
#ifndef __EMSCRIPTEN__
#include "network.h"
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <unistd.h>
#include <utility>
#include <vector>

// clang-format off
// The shared parser relies on the standard declarations above.
#include "../host/json.inc"
// clang-format on

namespace {
namespace fs = std::filesystem;
constexpr size_t JSON_LIMIT = 4 << 20, REPLAY_LIMIT = 16 << 20,
                 ENVELOPE_LIMIT = 24 << 20;
// A custom quest's table (PortableQuest, crimson-core/host/api.h).
constexpr size_t QUEST_BYTES = 6184;
struct Url {
  CURLU *handle = curl_url();
  explicit Url(const std::string &text) {
    if (!handle || text.find('\0') != std::string::npos ||
        curl_url_set(handle, CURLUPART_URL, text.c_str(), 0)) {
      if (handle)
        curl_url_cleanup(handle);
      handle = nullptr;
    }
  }
  ~Url() {
    if (handle)
      curl_url_cleanup(handle);
  }
  std::string part(CURLUPart part, unsigned flags = 0) const {
    char *text = nullptr;
    if (!handle || curl_url_get(handle, part, &text, flags))
      return {};
    std::string out = text;
    curl_free(text);
    return out;
  }
  std::string origin() const {
    std::string scheme = part(CURLUPART_SCHEME), host = part(CURLUPART_HOST);
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if ((scheme != "https" && scheme != "http") || host.empty() ||
        !part(CURLUPART_USER).empty() || !part(CURLUPART_PASSWORD).empty())
      return {};
    return scheme + "://" + host + ":" +
           part(CURLUPART_PORT, CURLU_DEFAULT_PORT);
  }
};
bool object(const std::string &text, Json &value) {
  return text.find('\0') == std::string::npos &&
         json_parse(text.data(), text.size(), value) &&
         value.kind == Json::OBJECT;
}
bool read_file(const std::string &path, std::string &bytes) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return false;
  bytes.assign(std::istreambuf_iterator<char>(in), {});
  return !in.bad();
}
// A failed write leaves the old file intact; no partial replay becomes
// watchable.
bool atomic_write(const std::string &path, const std::string &bytes) {
  std::string temp = (fs::path(path).parent_path() /
                      ("." + fs::path(path).stem().string() + ".part.XXXXXX"))
                         .string();
  int fd = mkstemp(temp.data());
  if (fd < 0)
    return false;
  size_t at = 0;
  while (at < bytes.size()) {
    ssize_t n = write(fd, bytes.data() + at, bytes.size() - at);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      break;
    at += (size_t)n;
  }
  bool ok = at == bytes.size() && fsync(fd) == 0;
  if (close(fd))
    ok = false;
  if (ok)
    ok = rename(temp.c_str(), path.c_str()) == 0;
  unlink(temp.c_str());
  return ok;
}
struct ResponseBuffer {
  std::string *bytes;
  size_t limit;
};
size_t receive(char *data, size_t size, size_t count, void *opaque) {
  auto &buffer = *(ResponseBuffer *)opaque;
  if (size && count > SIZE_MAX / size)
    return 0;
  size_t n = size * count;
  if (n > buffer.limit - buffer.bytes->size())
    return 0;
  buffer.bytes->append(data, n);
  return n;
}
int progress(void *opaque, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
  return ((std::atomic<bool> *)opaque)->load() ? 1 : 0;
}
} // namespace

bool LeaderboardNetwork::run_id(const std::string &id) {
  return id.size() == 64 && std::all_of(id.begin(), id.end(), [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}
// A custom quest's id: its digest's first 12 hex digits.
bool LeaderboardNetwork::quest_id(const std::string &id) {
  return id.size() == 12 && std::all_of(id.begin(), id.end(), [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}
// The site the API is under, which serves replays and quest tables.
std::string LeaderboardNetwork::site() const {
  std::string site = api_;
  if (site.size() >= 4 && site.compare(site.size() - 4, 4, "/api") == 0)
    site.resize(site.size() - 4);
  return site;
}
std::string LeaderboardNetwork::replay_link(const std::string &text,
                                            const std::string &api) {
  if (run_id(text))
    return text;
  Url link(text), service(api);
  if (link.origin().empty() || link.origin() != service.origin() ||
      !link.part(CURLUPART_FRAGMENT).empty())
    return {};
  std::string route = link.part(CURLUPART_PATH),
              query = link.part(CURLUPART_QUERY);
  if (route == "/play/" || route == "/play") {
    std::string run;
    for (size_t at = 0; at < query.size();) {
      size_t end = query.find('&', at);
      if (end == std::string::npos)
        end = query.size();
      std::string part = query.substr(at, end - at);
      if (part.compare(0, 6, "watch=") == 0) {
        if (!run.empty() || !run_id(part.substr(6)))
          return {};
        run = part.substr(6);
      }
      at = end + 1;
    }
    return run;
  }
  if (!query.empty() || route.compare(0, 6, "/runs/"))
    return {};
  std::string run = route.substr(6);
  if (run.size() > 4 && run.substr(run.size() - 4) == ".crd")
    run.resize(run.size() - 4);
  return run_id(run) ? run : std::string{};
}

std::string LeaderboardNetwork::quote(const std::string &text) {
  std::string out = "\"";
  for (unsigned char c : text) {
    if (c == '"' || c == '\\')
      out += '\\', out += (char)c;
    else if (c < 0x20 || c >= 0x80) {
      char escaped[7];
      snprintf(escaped, sizeof escaped, "\\u%04x", c);
      out += escaped;
    } else
      out += (char)c;
  }
  return out + "\"";
}

LeaderboardNetwork::LeaderboardNetwork(std::string api, std::string directory,
                                       std::string version)
    : api_(std::move(api)), directory_(std::move(directory)),
      agent_("crimsonland/" + version) {
  // Initialize curl before starting our worker, even with older libcurl builds.
  static const CURLcode initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
  while (!api_.empty() && api_.back() == '/')
    api_.pop_back();
  if (initialized != CURLE_OK)
    throw std::runtime_error("Could not initialize leaderboard networking");
  if (api_.empty())
    return;
  Url url(api_);
  origin_ = url.origin();
  if (origin_.empty() || !url.part(CURLUPART_QUERY).empty() ||
      !url.part(CURLUPART_FRAGMENT).empty())
    throw std::runtime_error("CRIMSON_LEADERBOARD_URL must be an HTTP(S) API "
                             "URL without credentials, query or fragment");
  signal(SIGPIPE, SIG_IGN);
  try {
    for (int lane = 0; lane < 3; ++lane)
      workers_[lane] = std::thread(&LeaderboardNetwork::work, this, lane);
  } catch (...) {
    {
      std::lock_guard lock(mutex_);
      stop_ = true;
    }
    ready_.notify_all();
    for (auto &worker : workers_)
      if (worker.joinable())
        worker.join();
    throw;
  }
}
LeaderboardNetwork::~LeaderboardNetwork() {
  {
    std::lock_guard lock(mutex_);
    stop_ = true;
  }
  ready_.notify_all();
  for (auto &worker : workers_)
    if (worker.joinable())
      worker.join();
}
bool LeaderboardNetwork::request(Kind kind, std::string body) {
  std::lock_guard lock(mutex_);
  if (!enabled() || stop_ || kind < 0 || kind >= COUNT || pending_[kind])
    return false;
  pending_[kind] = true;
  requests_.push_back({kind, std::move(body)});
  ready_.notify_all();
  return true;
}
bool LeaderboardNetwork::poll(Event &event) {
  std::lock_guard lock(mutex_);
  if (events_.empty())
    return false;
  event = std::move(events_.front());
  events_.pop_front();
  pending_[event.kind] = false;
  return true;
}
void LeaderboardNetwork::work(int lane) {
  // Scores follow the upload pass, as Update scores does in the web host.
  // Login, custom quest pages and downloads never wait behind that pass.
  auto belongs = [lane](const Request &r) {
    return lane == ((r.kind == REPLAY || r.kind == LINK || r.kind == QUEST) ? 2
                    : r.kind == CHALLENGE || r.kind == LOGIN || r.kind == CUSTOM
                        ? 1
                        : 0);
  };
  for (;;) {
    Request request;
    {
      std::unique_lock lock(mutex_);
      ready_.wait(lock, [&] {
        return stop_ ||
               std::any_of(requests_.begin(), requests_.end(), belongs);
      });
      if (stop_)
        return;
      auto found = std::find_if(requests_.begin(), requests_.end(), belongs);
      request = std::move(*found);
      requests_.erase(found);
    }
    Event event{request.kind};
    try {
      event = perform(request);
    } catch (const std::exception &error) {
      event.error = error.what();
    }
    std::lock_guard lock(mutex_);
    events_.push_back(std::move(event));
  }
}
LeaderboardNetwork::Event LeaderboardNetwork::http(Kind kind,
                                                   const std::string &url,
                                                   const std::string *body,
                                                   size_t limit) {
  Event event{kind};
  CURL *curl = curl_easy_init();
  if (!curl) {
    event.error = "Could not create HTTP request";
    return event;
  }
  ResponseBuffer buffer{&event.body, limit};
  curl_slist *headers = nullptr;
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_USERAGENT, agent_.c_str());
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
  if (kind == UPLOAD || kind == REPLAY) {
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 45L);
  } else
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
#if LIBCURL_VERSION_NUM >= 0x075500
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#else
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
                   (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
  curl_easy_setopt(curl, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  // Never redirect signed uploads or login requests to another origin.
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress);
  curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &stop_);
  if (body) {
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body->data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                     (curl_off_t)body->size());
  }
  CURLcode result = curl_easy_perform(curl);
  long status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  event.status = (int)status;
  event.ok = result == CURLE_OK;
  if (!event.ok)
    event.error = curl_easy_strerror(result);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  return event;
}
std::string LeaderboardNetwork::path(const std::string &relative,
                                     bool create_parent) {
  fs::path out(directory_);
  auto parts = fs::path(relative);
  for (auto it = parts.begin(); it != parts.end(); ++it) {
    if (*it == ".." || it->is_absolute())
      throw std::runtime_error("Invalid leaderboard file path");
    // Match the WASI host's case-insensitive Windows file names.
    fs::path component = *it;
    std::error_code scan_error;
    if (fs::is_directory(out, scan_error)) {
      for (const auto &entry : fs::directory_iterator(out)) {
        std::string name = entry.path().filename().string(),
                    wanted = component.string();
        auto lower = [](unsigned char c) { return std::tolower(c); };
        std::transform(name.begin(), name.end(), name.begin(), lower);
        std::transform(wanted.begin(), wanted.end(), wanted.begin(), lower);
        if (name == wanted) {
          component = entry.path().filename();
          break;
        }
      }
    }
    out /= component;
    std::error_code error;
    auto status = fs::symlink_status(out, error);
    if (fs::is_symlink(status))
      throw std::runtime_error("Leaderboard files cannot be symlinks");
    if (create_parent && std::next(it) != parts.end() && !fs::exists(status))
      fs::create_directory(out);
  }
  return out.string();
}
// Each queued run's outcome goes to event.lines in the Python port's words
// (src/crimson/leaderboard/client.py); a run this pass cannot read, to
// event.error.
bool LeaderboardNetwork::upload(Event &event) {
  std::string &error = event.error;
  std::string outbox = path("leaderboard/outbox");
  if (!fs::exists(outbox))
    return true;
  std::vector<fs::path> files;
  for (const auto &entry : fs::directory_iterator(outbox))
    if (entry.path().extension() == ".json" &&
        run_id(entry.path().stem().string()))
      files.push_back(entry.path());
  std::sort(files.begin(), files.end());
  for (const auto &file : files) {
    if (stop_)
      return false;
    try {
      std::string source =
                      path("leaderboard/outbox/" + file.filename().string()),
                  entry;
      if (fs::file_size(source) > ENVELOPE_LIMIT || !read_file(source, entry)) {
        error = "Could not read queued run; skipping it";
        continue;
      }
      Json envelope;
      if (!object(entry, envelope)) {
        error = "Invalid queued run JSON; skipping it";
        continue;
      }
      std::string run = file.stem().string().substr(0, 12);
      Event answer = http(UPLOAD, api_ + "/runs", &entry, JSON_LIMIT);
      if (!answer.ok) {
        event.lines.push_back("leaderboard: can't reach " + api_ + " (" + answer.error + "); runs wait in " + outbox);
        return false;
      }
      // A service error, or the service asking to slow down (429): the runs wait.
      if (answer.status >= 500 || answer.status == 429 || answer.status < 200 ||
          (answer.status >= 300 && answer.status < 400)) {
        event.lines.push_back("leaderboard: service error (HTTP " + std::to_string(answer.status) +
                              "); runs wait in " + outbox);
        return false;
      }
      if (answer.status >= 400 && answer.status != 409) {
        Json response;
        const Json *reason = object(answer.body, response)
                                 ? response.field("reason", Json::STRING)
                                 : nullptr;
        std::string rejected =
            path("leaderboard/rejected/" + file.filename().string(), true);
        size_t end = entry.find_last_not_of(" \r\n\t");
        std::string bytes =
            entry.substr(0, end) + (envelope.fields.empty() ? "" : ",") +
            "\"reason\":" +
            quote(reason ? reason->text
                         : "HTTP " + std::to_string(answer.status)) +
            "}";
        if (!atomic_write(rejected, bytes)) {
          error = "Could not save rejected run; keeping it queued";
          return false;
        }
        event.lines.push_back("leaderboard: run " + run + " rejected (" +
                              (reason ? reason->text : "HTTP " + std::to_string(answer.status)) + ")");
      } else
        event.lines.push_back(answer.status == 409 ? "leaderboard: run " + run + " was already uploaded"
                                                   : "leaderboard: uploaded run " + run);
      fs::remove(source);
    } catch (const std::exception &) {
      error = "Could not process queued run; skipping it";
    }
  }
  return error.empty();
}
LeaderboardNetwork::Event LeaderboardNetwork::perform(const Request &request) {
  if (request.kind == UPLOAD) {
    Event event{UPLOAD};
    event.ok = upload(event);
    return event;
  }
  if (request.kind == SCORES) {
    Event sent{UPLOAD};
    // Outbox failures do not make a read-only board request fail.
    try {
      upload(sent);
    } catch (const std::exception &) {
    }
    Event event = http(SCORES, api_ + "/scores", &request.body, JSON_LIMIT);
    event.ok = event.ok && event.status == 200 &&
               event.body.find('\0') == std::string::npos;
    event.lines = std::move(sent.lines);
    return event;
  }
  if (request.kind == CUSTOM) {
    Event event =
        http(CUSTOM, api_ + "/custom/browse", &request.body, JSON_LIMIT);
    event.ok = event.ok && event.status == 200 &&
               event.body.find('\0') == std::string::npos;
    return event;
  }
  if (request.kind == QUEST) {
    if (!quest_id(request.body))
      return {QUEST, false, 0, {}, "Invalid quest id"};
    Event event = http(QUEST, site() + "/custom/" + request.body + ".bin",
                       nullptr, QUEST_BYTES);
    event.ok =
        event.ok && event.status == 200 && event.body.size() == QUEST_BYTES;
    if (event.ok) {
      std::string file = path("quests/online/" + request.body + ".bin", true);
      event.ok = atomic_write(file, event.body);
      if (!event.ok)
        event.error = "Could not save downloaded quest";
    }
    event.body.clear();
    return event;
  }
  if (request.kind == CHALLENGE || request.kind == LOGIN) {
    Event event = http(
        request.kind,
        api_ + (request.kind == CHALLENGE ? "/auth/challenge" : "/auth/login"),
        &request.body, JSON_LIMIT);
    Json answer;
    const char *key = request.kind == CHALLENGE ? "challenge" : "url";
    const Json *value =
        event.ok && event.status == 200 && object(event.body, answer)
            ? answer.field(key, Json::STRING)
            : nullptr;
    event.ok = value != nullptr;
    if (value)
      event.body = value->text;
    if (event.ok && request.kind == CHALLENGE)
      event.ok = run_id(event.body);
    if (event.ok && request.kind == LOGIN) {
      Url link(event.body);
      std::string route = link.part(CURLUPART_PATH);
      event.ok = link.origin() == origin_ && route.size() == 71 &&
                 route.substr(0, 7) == "/login/" && run_id(route.substr(7)) &&
                 link.part(CURLUPART_QUERY).empty() &&
                 link.part(CURLUPART_FRAGMENT).empty();
    }
    if (!event.ok)
      event.error = "Can't sign in to the leaderboard";
    return event;
  }
  if (request.kind == LINK) {
    Event event = perform({REPLAY, request.body});
    event.kind = LINK;
    if (event.ok) {
      event.body = "replays/online/" + request.body + ".crd";
      Event card =
          http(LINK, api_ + "/runs/" + request.body, nullptr, JSON_LIMIT);
      Json details;
      if (card.ok && card.status == 200 && object(card.body, details)) {
        if (const Json *name = details.field("name", Json::STRING))
          event.runner = name->text;
        // A co-op run's players, "A & B", as the game's boards name them.
        if (const Json *team = details.field("team", Json::ARRAY)) {
          event.runner.clear();
          for (size_t i = 0; i < team->items.size(); ++i) {
            const Json *seat = team->items[i].field("name", Json::STRING);
            event.runner += (i ? " & " : "") + (seat ? seat->text : "?");
          }
        }
        if (const Json *rank = details.field("rank", Json::NUMBER);
            rank && rank->number >= 0 && rank->number <= INT32_MAX &&
            rank->number == floor(rank->number))
          event.rank = (int)rank->number;
        if (const Json *date = details.field("accepted_at", Json::NUMBER);
            date && date->number >= 0 && date->number <= 0x1p53)
          event.accepted_at = date->number;
      }
    }
    return event;
  }
  if (!run_id(request.body))
    return {REPLAY, false, 0, {}, "Invalid replay id"};
  Event event = http(REPLAY, site() + "/runs/" + request.body + ".crd",
                     nullptr, REPLAY_LIMIT);
  event.ok = event.ok && event.status == 200;
  if (event.ok) {
    std::string file = path("replays/online/" + request.body + ".crd", true);
    event.ok = atomic_write(file, event.body);
    if (!event.ok)
      event.error = "Could not save downloaded replay";
  }
  event.body.clear();
  return event;
}
#endif
