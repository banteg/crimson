// The Win32 calls and static-CRT wrappers the recovered executable makes. Files
// live under the host's game directory, with Windows paths; the registry is a
// small key/value file there; threads, DLLs and WinInet are unavailable, which
// the recovered code already handles as failures.
#include <ctype.h>
#include <direct.h>
#include <dirent.h>
#include <io.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <windows.h>

// "load\\x.jaz" and "C:\\game\\x" become host-relative "load/x.jaz" and "game/x".
static const char *host_path(const char *path, char *buffer, size_t size) {
  if (isalpha((unsigned char)path[0]) && path[1] == ':')
    path += 2;
  while (*path == '\\' || *path == '/')
    ++path;
  size_t i = 0;
  for (; path[i] && i + 1 < size; ++i)
    buffer[i] = path[i] == '\\' ? '/' : path[i];
  buffer[i] = 0;
  return buffer;
}

extern "C" {
// Every file the recovered code opens takes a Windows path (game.py renames fopen).
FILE *platform_fopen(const char *path, const char *mode) {
  char buffer[512];
  return fopen(host_path(path, buffer, sizeof(buffer)), mode);
}
FILE *crt_fopen(char *path, char *mode) { return platform_fopen(path, mode); }
unsigned int crt_fread(void *ptr, unsigned int size, unsigned int count, FILE *fp) { return fread(ptr, size, count, fp); }
unsigned int crt_fwrite(void *ptr, unsigned int size, unsigned int count, FILE *fp) {
  return fwrite(ptr, size, count, fp);
}
int crt_fseek(FILE *fp, long offset, int origin) { return fseek(fp, offset, origin); }
long crt_ftell(FILE *fp) { return ftell(fp); }
int crt_fclose(FILE *fp) { return fclose(fp); }
int crt_fflush(FILE *fp) { return fflush(fp); }
char *crt_fgets(char *buffer, int size, FILE *fp) { return fgets(buffer, size, fp); }
int crt_vsprintf(char *buffer, const char *format, va_list args) { return vsprintf(buffer, format, args); }
int _stricmp(const char *a, const char *b) { return strcasecmp(a, b); }
int _strnicmp(const char *a, const char *b, size_t count) { return strncasecmp(a, b, count); }

// _findfirst over a directory, matching the pattern's '*' and '?'.
struct Search {
  DIR *dir;
  char pattern[260];
};
static bool glob_match(const char *pattern, const char *name) {
  if (!*pattern)
    return !*name;
  if (*pattern == '*')
    return glob_match(pattern + 1, name) || (*name && glob_match(pattern, name + 1));
  return *name && (*pattern == '?' || tolower((unsigned char)*pattern) == tolower((unsigned char)*name)) &&
         glob_match(pattern + 1, name + 1);
}
static int search_next(Search *search, _finddata_t *data) {
  while (dirent *entry = readdir(search->dir)) {
    if (!glob_match(search->pattern, entry->d_name))
      continue;
    memset(data, 0, sizeof(*data));
    strncpy(data->name, entry->d_name, sizeof(data->name) - 1);
    return 0;
  }
  return -1;
}
long crt_findfirst(char *pattern, _finddata_t *data) {
  char buffer[512];
  host_path(pattern, buffer, sizeof(buffer));
  char *slash = strrchr(buffer, '/');
  auto *search = new Search;
  strncpy(search->pattern, slash ? slash + 1 : buffer, sizeof(search->pattern) - 1);
  search->pattern[sizeof(search->pattern) - 1] = 0;
  if (slash)
    *slash = 0;
  search->dir = opendir(slash ? buffer : ".");
  if (!search->dir || search_next(search, data)) {
    if (search->dir)
      closedir(search->dir);
    delete search;
    return -1;
  }
  return (long)search;
}
// The MSVC CRT refuses a failed search's handle, which the game still closes.
int crt_findnext(long handle, _finddata_t *data) { return handle == -1 ? -1 : search_next((Search *)handle, data); }
int crt_findclose(long handle) {
  if (handle == -1)
    return -1;
  auto *search = (Search *)handle;
  closedir(search->dir);
  delete search;
  return 0;
}

int crt_atexit(void (*)(void)) { return 0; }
[[noreturn]] void crt_exit(int) { abort(); }
char *crt_getcwd(char *buffer, int size) { return _getcwd(buffer, size); }
int crt_isalpha(int c) { return isalpha(c); }
int crt_printf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  int n = vprintf(format, args);
  va_end(args);
  return n;
}
char *crt_strtok(char *text, char *delimiters) { return strtok(text, delimiters); }
unsigned int crt_time(void *timer) {
  time_t now = time(nullptr);
  if (timer)
    *(unsigned int *)timer = (unsigned int)now;
  return (unsigned int)now;
}

LPSTR WINAPI GetCommandLineA(void) {
  static char empty[] = "";
  return empty;
}
int WINAPI MultiByteToWideChar(UINT, DWORD, LPCSTR text, int length, LPWSTR wide, int capacity) {
  if (length < 0)
    length = (int)strlen(text) + 1;
  if (!capacity)
    return length;
  int n = length < capacity ? length : capacity;
  for (int i = 0; i < n; ++i)
    wide[i] = (unsigned char)text[i];
  return n;
}
// Links to the original's web pages stay closed.
HRESULT WINAPI HlinkNavigateString(IUnknown *, LPCWSTR) { return 0; }

// No threads: a started thread runs to completion before its starter continues.
// The startup audio load finishes at once; the score and update checks fail fast offline.
void crt_beginthread(void (*function)(void *), unsigned int, void *argument) { function(argument); }
void crt_endthread(void) {}

VOID WINAPI Sleep(DWORD) {}
DWORD WINAPI GetLastError(void) { return 0; }
VOID WINAPI OutputDebugStringA(LPCSTR) {}
VOID WINAPI GetLocalTime(LPSYSTEMTIME result) {
  time_t now = time(nullptr);
  struct tm *t = localtime(&now);
  result->wYear = t->tm_year + 1900;
  result->wMonth = t->tm_mon + 1;
  result->wDayOfWeek = t->tm_wday;
  result->wDay = t->tm_mday;
  result->wHour = t->tm_hour;
  result->wMinute = t->tm_min;
  result->wSecond = t->tm_sec;
  result->wMilliseconds = 0;
}
BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER *counter) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  unsigned long long ticks = (unsigned long long)now.tv_sec * 1000000 + now.tv_nsec / 1000;
  counter->LowPart = (LONG)ticks;
  counter->HighPart = (LONG)(ticks >> 32);
  return 1;
}
BOOL WINAPI CreateDirectoryA(LPCSTR path, void *) {
  char buffer[512];
  return mkdir(host_path(path, buffer, sizeof(buffer)), 0755) == 0;
}
int _mkdir(const char *path) { return CreateDirectoryA(path, nullptr) ? 0 : -1; }

// No DLLs: mods and the original Grim loader find nothing.
HMODULE WINAPI LoadLibraryA(LPCSTR) { return nullptr; }
BOOL WINAPI FreeLibrary(HMODULE) { return 1; }
FARPROC WINAPI GetProcAddress(HMODULE, LPCSTR) { return nullptr; }
HINSTANCE WINAPI ShellExecuteA(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT) { return (HINSTANCE)33; }

// WinInet: offline.
void *WINAPI InternetOpenA(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD) { return nullptr; }
void *WINAPI InternetConnectA(void *, LPCSTR, WORD, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR) { return nullptr; }
void *WINAPI HttpOpenRequestA(void *, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR *, DWORD, DWORD_PTR) { return nullptr; }
BOOL WINAPI HttpSendRequestA(void *, LPCSTR, DWORD, LPVOID, DWORD) { return 0; }
BOOL WINAPI InternetReadFile(void *, LPVOID, DWORD, LPDWORD read) {
  if (read)
    *read = 0;
  return 0;
}
BOOL WINAPI InternetCloseHandle(void *) { return 1; }
BOOL WINAPI InternetGetLastResponseInfoA(LPDWORD, LPSTR, LPDWORD length) {
  if (length)
    *length = 0;
  return 0;
}
}

// --- Registry ----------------------------------------------------------------------
// Values are DWORDs under a key path; registry.cfg keeps them as "path\name=value".

struct RegistryValue {
  char key[160];
  char name[64];
  DWORD value;
};
static RegistryValue registry[64];
static int registry_count = -1;
static char registry_keys[16][160];

static void registry_load() {
  if (registry_count >= 0)
    return;
  registry_count = 0;
  FILE *fp = fopen("registry.cfg", "r");
  if (!fp)
    return;
  char line[256];
  while (registry_count < 64 && fgets(line, sizeof(line), fp)) {
    char *equals = strrchr(line, '=');
    char *slash = equals ? (char *)memrchr(line, '\\', equals - line) : nullptr;
    if (!slash)
      continue;
    RegistryValue &entry = registry[registry_count++];
    snprintf(entry.key, sizeof(entry.key), "%.*s", (int)(slash - line), line);
    snprintf(entry.name, sizeof(entry.name), "%.*s", (int)(equals - slash - 1), slash + 1);
    entry.value = strtoul(equals + 1, nullptr, 10);
  }
  fclose(fp);
}
static void registry_save() {
  FILE *fp = fopen("registry.cfg", "w");
  if (!fp)
    return;
  for (int i = 0; i < registry_count; ++i)
    fprintf(fp, "%s\\%s=%u\n", registry[i].key, registry[i].name, (unsigned)registry[i].value);
  fclose(fp);
}

extern "C" {
LONG WINAPI RegCreateKeyExA(HKEY root, LPCSTR path, DWORD, LPSTR, DWORD, DWORD, LPVOID, HKEY *result, LPDWORD) {
  for (int i = 0; i < 16; ++i)
    if (!registry_keys[i][0] || i == 15) {
      snprintf(registry_keys[i], sizeof(registry_keys[i]), "%s\\%s",
               root == HKEY_LOCAL_MACHINE ? "HKLM" : "HKCU", path);
      *result = (HKEY)(uintptr_t)(i + 1);
      return ERROR_SUCCESS;
    }
  return 1;
}
LONG WINAPI RegCloseKey(HKEY key) {
  registry_keys[(uintptr_t)key - 1][0] = 0;
  return ERROR_SUCCESS;
}
LONG WINAPI RegQueryValueExA(HKEY key, LPCSTR name, LPDWORD, LPDWORD type, BYTE *data, LPDWORD size) {
  registry_load();
  const char *path = registry_keys[(uintptr_t)key - 1];
  for (int i = 0; i < registry_count; ++i)
    if (!strcmp(registry[i].key, path) && !strcmp(registry[i].name, name)) {
      if (type)
        *type = REG_DWORD;
      if (data && size && *size >= sizeof(DWORD))
        memcpy(data, &registry[i].value, sizeof(DWORD));
      if (size)
        *size = sizeof(DWORD);
      return ERROR_SUCCESS;
    }
  return 2; // ERROR_FILE_NOT_FOUND
}
LONG WINAPI RegSetValueExA(HKEY key, LPCSTR name, DWORD, DWORD type, const BYTE *data, DWORD size) {
  if (type != REG_DWORD || size != sizeof(DWORD))
    return 1;
  registry_load();
  const char *path = registry_keys[(uintptr_t)key - 1];
  int i = 0;
  while (i < registry_count && (strcmp(registry[i].key, path) || strcmp(registry[i].name, name)))
    ++i;
  if (i == registry_count) {
    if (registry_count == 64)
      return 1;
    ++registry_count;
    snprintf(registry[i].key, sizeof(registry[i].key), "%s", path);
    snprintf(registry[i].name, sizeof(registry[i].name), "%s", name);
  }
  memcpy(&registry[i].value, data, sizeof(DWORD));
  registry_save();
  return ERROR_SUCCESS;
}
}

// The DirectX version gate (dxversion/): the platform layer is Direct3D 8.1.
extern "C" HRESULT dx_get_version(int *version, char *text, int size) {
  *version = 0x80100;
  if (size > 0)
    snprintf(text, size, "8.1");
  return 0;
}
