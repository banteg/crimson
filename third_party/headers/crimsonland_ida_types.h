/* Shared typedefs for IDA/Ghidra parsing (minimal stubs). */
#ifndef CRIMSONLAND_IDA_TYPES_H
#define CRIMSONLAND_IDA_TYPES_H

typedef unsigned char byte;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;

typedef unsigned int uint;

typedef unsigned char Byte;
typedef Byte *Bytef;
typedef unsigned int uInt;
typedef unsigned long uLong;
typedef uLong uLongf;
typedef void *voidp;
typedef void *voidpf;

struct z_stream_s;
typedef struct z_stream_s z_stream;
typedef z_stream *z_streamp;

typedef unsigned char png_byte;
typedef unsigned short png_uint_16;
typedef unsigned int png_uint_32;
typedef int png_int_32;
typedef void *png_voidp;
typedef png_byte *png_bytep;

struct png_struct_def;
typedef struct png_struct_def png_struct;
typedef png_struct *png_structp;

struct IGrim2D;
typedef struct IGrim2D IGrim2D;

#endif
