// Included by the generated client host only. No verifier macro or ABI changes.
static bool client_in_tick;
extern "C" unsigned char game_paused_flag, console_open_flag;
static FILE *client_trace() {
  static FILE *file = []() {
    const char *path = getenv("CRIMSON_CLIENT_TRACE");
    if (!path) return stderr;
    FILE *f = fopen(path, "w");
    if (!f) { perror("client trace"); abort(); }
    setvbuf(f, nullptr, _IONBF, 0);
    return f;
  }();
  return file;
}
[[noreturn]] void client_unsupported(const char *reason) {
  fprintf(client_trace(), "{\"event\":\"unsupported\",\"tick\":%u,\"reason\":\"%s\"}\n", tick, reason);
  fprintf(stderr, "client unsupported: %s at tick %u\n", reason, tick);
  abort();
}
static void client_slot(int slot, const char *name, bool read) {
  fprintf(client_trace(), "{\"event\":\"grim\",\"tick\":%u,\"in_tick\":%s,\"slot\":%d,\"name\":\"%s\",\"return_read\":%s}\n",
          tick, client_in_tick ? "true" : "false", slot, name, read ? "true" : "false");
}
void client_sound_trigger(const char *name, int id) {
  fprintf(client_trace(), "{\"event\":\"sound_trigger\",\"tick\":%u,\"name\":\"%s\",\"id\":%d}\n", tick, name, id);
}
static void client_check_rand(const char *file, int line, const char *caller) {
  if (!client_in_tick) {
    fprintf(client_trace(), "{\"event\":\"rand_outside_tick\",\"tick\":%u,\"source\":\"%s\",\"line\":%d,\"caller\":\"%s\"}\n", tick, file, line, caller);
    fprintf(stderr, "client crt_rand outside simulation tick: %s (%s:%d), tick %u\n", caller, file, line, tick);
    abort();
  }
}
extern "C" int crt_rand();
extern "C" int client_rand(const char *file, int line, const char *caller) {
  client_check_rand(file, line, caller);
  fprintf(client_trace(), "{\"event\":\"rand\",\"tick\":%u,\"source\":\"%s\",\"line\":%d,\"caller\":\"%s\"}\n", tick, file, line, caller);
  return crt_rand();
}
struct ClientTickScope {
  ClientTickScope() { client_in_tick = true; }
  ~ClientTickScope() { client_in_tick = false; }
};
extern "C" void perk_selection_screen_update();
extern "C" void config_load_presets(int) { client_unsupported("configuration:load-presets"); }
extern "C" int GetKeyNameTextA(int32_t, char *, int) { client_unsupported("platform:key-name"); }
