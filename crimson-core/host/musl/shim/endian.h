// The compiler's byte order, under the names musl's libm.h reads. Where the libc has its own <endian.h> (glibc,
// wasi-libc), that one defines them.
#pragma once
#if __has_include_next(<endian.h>)
#include_next <endian.h>
#endif
#ifndef __BYTE_ORDER
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#define __BYTE_ORDER __BYTE_ORDER__
#endif
