#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

#include "freeware_http.h"

extern "C" char s_empty_string[];

extern "C" freeware_http_response *freeware_http_get(const char *server, const char *path, const char *filename)
{
    HINTERNET session = InternetOpenA("MSDN ", INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
    if (!session)
        return 0;
    HINTERNET connection = InternetConnectA(session, server, 0, s_empty_string, s_empty_string, INTERNET_SERVICE_HTTP, 0, 0);
    char resource[512];
    sprintf(resource, "%s/%s", path, filename);
    HINTERNET request = HttpOpenRequestA(connection, "GET", resource, "HTTP/1.0", 0, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    HttpSendRequestA(request, 0, 0, 0, 0);

    char content_length[32];
    DWORD length = sizeof(content_length);
    HttpQueryInfoA(request, HTTP_QUERY_CONTENT_LENGTH, content_length, &length, 0);
    long size = atol(content_length);
    char *data = new char[size + 1];
    DWORD received;
    InternetReadFile(request, data, size + 1, &received);
    data[size] = 0;
    freeware_http_response *response = new freeware_http_response;
    response->data = data;
    response->size = received;
    return response;
}
