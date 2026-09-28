#include "grim_joystick_input.h"

int __stdcall grim_joystick_configure_axis(
    const GrimDeviceObjectInstance *object, void *)
{
    if ((object->type & 3) != 0) {
        GrimPropertyRange range;
        range.header.size = sizeof(range);
        range.header.header_size = sizeof(range.header);
        range.header.object = object->type;
        range.header.how = 2;
        range.minimum = -1000;
        range.maximum = 1000;
        if (grim_joystick_device->vtable->SetProperty(
                grim_joystick_device,
                (const GrimGuid *)4,
                &range.header) < 0) {
            return 0;
        }
    }
    return 1;
}
