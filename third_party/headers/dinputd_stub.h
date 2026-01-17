#ifndef DINPUTD_STUB_H
#define DINPUTD_STUB_H

#include "dinput.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IDirectInputEffectDriver IDirectInputEffectDriver;
typedef struct IDirectInputJoyConfig IDirectInputJoyConfig;
typedef struct IDirectInputJoyConfig8 IDirectInputJoyConfig8;

struct IDirectInputEffectDriver {
    void *lpVtbl;
};

struct IDirectInputJoyConfig {
    void *lpVtbl;
};

struct IDirectInputJoyConfig8 {
    void *lpVtbl;
};

#ifdef __cplusplus
}
#endif

#endif
