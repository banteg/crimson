#pragma once
#ifndef __EMSCRIPTEN__
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// The desktop transport never touches module memory. Requests own their input;
// the main thread drains completions before running the next game frame.
class LeaderboardNetwork {
public:
  enum Kind { UPLOAD, SCORES, CHALLENGE, LOGIN, REPLAY, LINK, CUSTOM, QUEST, COUNT };
  struct Event {
    Kind kind;
    bool ok = false;
    int status = 0;
    std::string body, error;
    // What the uploader made of each queued run, for the console.
    std::vector<std::string> lines;
    std::string runner;
    int rank = 0;
    double accepted_at = 0;
  };
  LeaderboardNetwork(std::string api, std::string directory,
                     std::string version);
  ~LeaderboardNetwork();
  bool enabled() const { return !api_.empty(); }
  bool request(Kind kind, std::string body = {});
  bool poll(Event &event);
  static std::string replay_link(const std::string &text,
                                 const std::string &api);
  static bool run_id(const std::string &id);
  static bool quest_id(const std::string &id);
  static std::string quote(const std::string &latin1);

private:
  struct Request {
    Kind kind;
    std::string body;
  };
  std::string api_, origin_, directory_, agent_;
  std::atomic<bool> stop_{false};
  std::mutex mutex_;
  std::condition_variable ready_;
  std::deque<Request> requests_;
  std::deque<Event> events_;
  bool pending_[COUNT] = {};
  std::thread workers_[3];
  void work(int lane);
  Event perform(const Request &request);
  Event http(Kind kind, const std::string &url, const std::string *body,
             size_t limit);
  bool upload(Event &event);
  std::string path(const std::string &relative, bool create_parent = false);
  std::string site() const;
};
#endif
