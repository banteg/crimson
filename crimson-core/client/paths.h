#pragma once
#include <dirent.h>
#include <string>
#include <strings.h>

// Match the game's Windows filenames. Consumes and closes the directory stream.
inline std::string client_path_name(DIR *dir, const std::string &name) {
  std::string match = name;
  if (dir) {
    while (dirent *entry = readdir(dir))
      if (!strcasecmp(entry->d_name, name.c_str())) {
        match = entry->d_name;
        break;
      }
    closedir(dir);
  }
  return match;
}
