#ifndef FREEWARE_EDITION_H
#define FREEWARE_EDITION_H
#include "cl_build.h"
// Native matching uses the PE's ABI. The portable client can run earlier rules with its shared record layout.
#ifndef FREEWARE_EDITION
#define FREEWARE_EDITION CL_BUILD
#endif
namespace freeware_rules {
enum { plasma_round = FREEWARE_EDITION == 10002 ? 6 : 7, plasma_minigun_round = FREEWARE_EDITION == 10002 ? 8 : 9 };
// The two early registration tables start at Bloody Mess. The portable backing array has
// a spare zero slot for effects absent from an edition; it is never offered by the picker.
enum {
    absent = 47,
    bloody_mess = FREEWARE_EDITION < 10400 ? 0 : 1,
    almost_invisible = bloody_mess + 1, sharpshooter = bloody_mess + 2,
    long_distance_runner = bloody_mess + 3, fastloader = bloody_mess + 4,
    lean_mean_exp = FREEWARE_EDITION == 10002 ? absent : bloody_mess + 5,
    combustion = FREEWARE_EDITION == 10002 ? 5 : bloody_mess + 6,
    instant_winner = combustion + 1, grim_deal = combustion + 2, plaguebearer = combustion + 3,
    ammo_maniac = FREEWARE_EDITION == 10002 ? absent : bloody_mess + 10,
    radioactive = FREEWARE_EDITION == 10002 ? 9 : bloody_mess + 11,
    berserk = radioactive + 1, timebender = FREEWARE_EDITION == 10002 ? 11 : absent,
    fastshot = FREEWARE_EDITION == 10002 ? 12 : bloody_mess + 13,
    reflex_boosted = fastshot + 1, doctor = fastshot + 2, jinxed = fastshot + 3,
    evil_eyes = FREEWARE_EDITION == 10002 ? absent : bloody_mess + 17,
    anxious_loader = FREEWARE_EDITION == 10002 ? absent : FREEWARE_EDITION == 10300 ? 18 : 22,
    final_revenge = FREEWARE_EDITION == 10002 ? absent : anxious_loader + 1,
    infernal_contract = FREEWARE_EDITION == 10002 ? absent : anxious_loader + 2,
    perk_expert = FREEWARE_EDITION == 10002 ? absent : anxious_loader + 3
};

}
#endif
