#ifndef GRIM_JOYSTICK_INPUT_H
#define GRIM_JOYSTICK_INPUT_H

#include "grim_joystick_state.h"

typedef unsigned long GrimDword;

struct GrimGuid {
    unsigned long data1;
    unsigned short data2;
    unsigned short data3;
    unsigned char data4[8];
};

struct GrimDataFormat;
struct GrimDirectInput;
struct GrimJoystickDevice;
struct GrimDeviceInstance;
struct GrimDeviceObjectInstance;

typedef int (__stdcall *GrimEnumDevicesCallback)(
    const GrimDeviceInstance *instance, void *context);
typedef int (__stdcall *GrimEnumObjectsCallback)(
    const GrimDeviceObjectInstance *object, void *context);

struct GrimDirectInputVtable {
    void *QueryInterface;
    void *AddRef;
    unsigned long (__stdcall *Release)(GrimDirectInput *self);
    long (__stdcall *CreateDevice)(
        GrimDirectInput *self,
        const GrimGuid *guid,
        GrimJoystickDevice **device,
        void *outer);
    long (__stdcall *EnumDevices)(
        GrimDirectInput *self,
        GrimDword type,
        GrimEnumDevicesCallback callback,
        void *context,
        GrimDword flags);
};

struct GrimJoystickDeviceVtable {
    void *QueryInterface;
    void *AddRef;
    unsigned long (__stdcall *Release)(GrimJoystickDevice *self);
    void *GetCapabilities;
    long (__stdcall *EnumObjects)(
        GrimJoystickDevice *self,
        GrimEnumObjectsCallback callback,
        void *context,
        GrimDword flags);
    void *GetProperty;
    long (__stdcall *SetProperty)(
        GrimJoystickDevice *self,
        const GrimGuid *property,
        const void *header);
    long (__stdcall *Acquire)(GrimJoystickDevice *self);
    long (__stdcall *Unacquire)(GrimJoystickDevice *self);
    long (__stdcall *GetDeviceState)(
        GrimJoystickDevice *self, GrimDword size, void *state);
    void *GetDeviceData;
    long (__stdcall *SetDataFormat)(
        GrimJoystickDevice *self, const GrimDataFormat *format);
    void *SetEventNotification;
    long (__stdcall *SetCooperativeLevel)(
        GrimJoystickDevice *self, void *hwnd, GrimDword flags);
    void *slots[11];
    long (__stdcall *Poll)(GrimJoystickDevice *self);
};

struct GrimDirectInput {
    GrimDirectInputVtable *vtable;
};

struct GrimJoystickDevice {
    GrimJoystickDeviceVtable *vtable;
};

struct GrimDeviceInstance {
    GrimDword size;
    GrimGuid guid_instance;
};

struct GrimDeviceObjectInstance {
    unsigned char prefix[0x18];
    GrimDword type;
};

struct GrimPropertyHeader {
    GrimDword size;
    GrimDword header_size;
    GrimDword object;
    GrimDword how;
};

struct GrimPropertyRange {
    GrimPropertyHeader header;
    long minimum;
    long maximum;
};

extern GrimDirectInput *grim_dinput_joystick;
extern GrimJoystickDevice *grim_joystick_device;
extern bool grim_joystick_found;

extern int __stdcall grim_joystick_enum_device(
    const GrimDeviceInstance *instance, void *context);
extern int __stdcall grim_joystick_configure_axis(
    const GrimDeviceObjectInstance *object, void *context);
extern bool grim_joystick_poll(void);

#endif
