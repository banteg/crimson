#include "cl_build.h"
#include <stdio.h>

extern "C" char freeware_text_buffer[];

extern "C" char *weapon_name_get(int weapon_id)
{
    if (weapon_id == 1)
        sprintf(freeware_text_buffer, "Pistol");
    else if (weapon_id == 2)
        sprintf(freeware_text_buffer, "AutoRifle");
    else if (weapon_id == 3)
        sprintf(freeware_text_buffer, "Shotgun");
    else if (weapon_id == 4)
#if CL_BUILD == 10300
        sprintf(freeware_text_buffer, "Sewed-off Shotgun");
#else
        sprintf(freeware_text_buffer, "Sawed-off Shotgun");
#endif
    else if (weapon_id == 5)
        sprintf(freeware_text_buffer, "Flamethrower");
    else if (weapon_id == 15)
        sprintf(freeware_text_buffer, "Blowtorch");
    else if (weapon_id == 6)
        sprintf(freeware_text_buffer, "High RPM Rifle");
    else if (weapon_id == 7)
        sprintf(freeware_text_buffer, "Plasma Rifle");
    else if (weapon_id == 8)
        sprintf(freeware_text_buffer, "TriPlasma Rifle");
    else if (weapon_id == 9)
        sprintf(freeware_text_buffer, "Plasma Minigun");
    else if (weapon_id == 10)
        sprintf(freeware_text_buffer, "Gauss Gun");
    else if (weapon_id == 11)
        sprintf(freeware_text_buffer, "Rockets");
    else if (weapon_id == 12)
        sprintf(freeware_text_buffer, "Seeker Rockets");
    else if (weapon_id == 13)
        sprintf(freeware_text_buffer, "Mean Minigun");
    else if (weapon_id == 14)
        sprintf(freeware_text_buffer, "Plasma Shotgun");
#if CL_BUILD == 10300
    else if (weapon_id == 17)
        sprintf(freeware_text_buffer, "Plague Gun");
#endif
    else if (weapon_id == 16)
#if CL_BUILD == 10300
        sprintf(freeware_text_buffer, "The Secret Weapon");
#else
        sprintf(freeware_text_buffer, "Rocket Blast");
#endif
#if CL_BUILD == 10400
    else if (weapon_id == 20)
        sprintf(freeware_text_buffer, "The Grim Weapon");
    else if (weapon_id == 18)
        sprintf(freeware_text_buffer, "Rainbow Gun");
    else if (weapon_id == 19)
        sprintf(freeware_text_buffer, "Bubble Gun");
    else if (weapon_id == 17)
        sprintf(freeware_text_buffer, "Plague Gun");
#endif
    else
        sprintf(freeware_text_buffer, "Unknown");
    return freeware_text_buffer;
}
