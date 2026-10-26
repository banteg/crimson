#include "network.h"
#include <chrono>
#include <cstdio>
#include <thread>
int main(int argc, char **argv) {
  if (argc != 5)
    return 2;
  if (std::string(argv[3]) == "shutdown") {
    for (int i = 0; i < 300; ++i) {
      LeaderboardNetwork net(argv[1], argv[2], "test");
      net.request(LeaderboardNetwork::UPLOAD);
    }
    return 0;
  }
  if (std::string(argv[3]) == "link") {
    printf("%s", LeaderboardNetwork::replay_link(argv[4], argv[1]).c_str());
    return 0;
  }
  LeaderboardNetwork net(argv[1], argv[2], "test");
  if (std::string(argv[3]) == "cancel") {
    net.request(LeaderboardNetwork::REPLAY, argv[4]);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return 0;
  }
  if (std::string(argv[3]) == "parallel") {
    net.request(LeaderboardNetwork::UPLOAD);
    auto parallel_kind = std::string(argv[4]) == "link"
                             ? LeaderboardNetwork::LINK
                             : LeaderboardNetwork::CHALLENGE;
    net.request(parallel_kind, parallel_kind == LeaderboardNetwork::LINK
                                   ? std::string(64, 'a')
                                   : "{}");
    LeaderboardNetwork::Event event{LeaderboardNetwork::UPLOAD};
    for (int i = 0; i < 150; ++i) {
      if (net.poll(event) && event.kind == parallel_kind) {
        printf("%d %d\n%s", event.ok, event.status, event.body.c_str());
        return 0;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return 6;
  }
  auto kind = (LeaderboardNetwork::Kind)atoi(argv[3]);
  if (!net.request(kind, argv[4]))
    return 3;
  if (net.request(kind, argv[4]))
    return 4;
  LeaderboardNetwork::Event event{kind};
  for (int i = 0; i < 1500; ++i) {
    if (net.poll(event)) {
      printf("%d %d\n", event.ok, event.status);
      fwrite(event.body.data(), 1, event.body.size(), stdout);
      // A link's replay path, then the runner its card names.
      if (kind == LeaderboardNetwork::LINK)
        printf("\n%s", event.runner.c_str());
      fprintf(stderr, "%s\n", event.error.c_str());
      for (const std::string &line : event.lines)
        fprintf(stderr, "%s\n", line.c_str());
      return 0;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return 5;
}
