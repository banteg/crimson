// The compiler's byte order, under the names musl's libm.h reads.
#pragma once
#ifndef __BYTE_ORDER
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#define __BYTE_ORDER __BYTE_ORDER__
#endif
