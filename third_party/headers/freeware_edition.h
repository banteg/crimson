#ifndef FREEWARE_EDITION_H
#define FREEWARE_EDITION_H
#include "cl_build.h"
// Native matching uses the PE's ABI. The portable client can run earlier rules with its shared record layout.
#ifndef FREEWARE_EDITION
#define FREEWARE_EDITION CL_BUILD
#endif
namespace freeware_rules {
enum { plasma_round = FREEWARE_EDITION == 10002 ? 6 : 7, plasma_minigun_round = FREEWARE_EDITION == 10002 ? 8 : 9 };
}
#endif
