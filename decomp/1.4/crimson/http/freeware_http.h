#ifndef FREEWARE_HTTP_H
#define FREEWARE_HTTP_H

struct freeware_http_response {
    char *data;
    unsigned long size;
};

extern "C" freeware_http_response *freeware_http_get(const char *server, const char *path, const char *filename);

#endif
