#include "jinclude.h"
#include "jpeglib.h"

__declspec(dllimport) void * __stdcall GetActiveWindow(void);
__declspec(dllimport) int __stdcall MessageBoxA(
  void *window, const char *text, const char *caption, unsigned int type);

void output_message(j_common_ptr cinfo)
{
  char buffer[JMSG_LENGTH_MAX];

  (*cinfo->err->format_message) (cinfo, buffer);
  MessageBoxA(GetActiveWindow(), buffer, "JPEG Error", 0);
}
