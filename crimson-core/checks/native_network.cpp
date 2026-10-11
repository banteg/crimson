#include "network.h"
#include <chrono>
#include <cstdio>
#include <thread>
int main(int argc, char **argv) {
  if (argc != 5)
    return 2;
  LeaderboardNetwork net(argv[1], argv[2], "test");
  if (std::string(argv[3]) == "cancel") {
    net.request(LeaderboardNetwork::REPLAY, argv[4]);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return 0;
  }
  if (std::string(argv[3]) == "parallel") {
    net.request(LeaderboardNetwork::UPLOAD);
    net.request(LeaderboardNetwork::CHALLENGE, "{}");
    LeaderboardNetwork::Event event{LeaderboardNetwork::UPLOAD};
    for (int i = 0; i < 150; ++i) {
      if (net.poll(event) && event.kind == LeaderboardNetwork::CHALLENGE) {
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
      fprintf(stderr, "%s\n", event.error.c_str());
      return 0;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return 5;
}
