#include "cl_build.h"

#if CL_BUILD == 10908
#include "reflexive_arcade.h"
#endif

class MyApp {
public:
    void cleanup(void);
    void shutdown(void);
};

void MyApp::shutdown(void)
{
    cleanup();
#if CL_BUILD == 10908
    // The 1.9.8 Reflexive Arcade build releases the arcade client last.
    RA_ShutDown();
#endif
}
