#include <windows.h>

class MyApp {
public:
    unsigned char reserved_00[0x1c];
    HGDIOBJ bitmap;

    void cleanup(void);
};

void MyApp::cleanup(void)
{
    if (bitmap != 0) {
        DeleteObject(bitmap);
        bitmap = 0;
    }
}
