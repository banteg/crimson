/*
 * Matcher-only adaptation of zlib 1.1.3 inflate.c.
 * Copyright (C) 1995-1998 Mark Adler.
 *
 * The stream state and control flow follow the pinned upstream release. Names
 * are isolated so the scratch object can coexist with the reconstructed port.
 */

typedef struct grim_zlib_inflate_state_source_s grim_zlib_inflate_state_source_t;
typedef struct grim_zlib_inflate_stream_source_s grim_zlib_inflate_stream_source_t;
typedef struct grim_inflate_blocks_opaque_source_s grim_inflate_blocks_opaque_source_t;

typedef void *(__cdecl *grim_zlib_inflate_alloc_source_fn_t)(
    void *, unsigned int, unsigned int);
typedef void (__cdecl *grim_zlib_inflate_free_source_fn_t)(void *, void *);
typedef unsigned long (__cdecl *grim_zlib_inflate_check_source_fn_t)(
    unsigned long, const unsigned char *, unsigned int);

struct grim_zlib_inflate_stream_source_s {
    unsigned char *next_input;
    unsigned int available_input;
    unsigned long total_input;
    unsigned char *next_output;
    unsigned int available_output;
    unsigned long total_output;
    char *message;
    grim_zlib_inflate_state_source_t *state;
    grim_zlib_inflate_alloc_source_fn_t allocate;
    grim_zlib_inflate_free_source_fn_t release;
    void *opaque;
    int data_type;
    unsigned long adler;
    unsigned long reserved;
};

typedef enum grim_zlib_inflate_mode_source_e {
    GRIM_STREAM_METHOD,
    GRIM_STREAM_FLAG,
    GRIM_STREAM_DICT4,
    GRIM_STREAM_DICT3,
    GRIM_STREAM_DICT2,
    GRIM_STREAM_DICT1,
    GRIM_STREAM_DICT0,
    GRIM_STREAM_BLOCKS,
    GRIM_STREAM_CHECK4,
    GRIM_STREAM_CHECK3,
    GRIM_STREAM_CHECK2,
    GRIM_STREAM_CHECK1,
    GRIM_STREAM_DONE,
    GRIM_STREAM_BAD
} grim_zlib_inflate_mode_source_t;

struct grim_zlib_inflate_state_source_s {
    grim_zlib_inflate_mode_source_t mode;
    union {
        unsigned int method;
        struct {
            unsigned long actual;
            unsigned long expected;
        } check;
        unsigned int marker;
    } sub;
    int nowrap;
    unsigned int window_bits;
    grim_inflate_blocks_opaque_source_t *blocks;
};

void __cdecl grim_inflate_blocks_reset(
    grim_inflate_blocks_opaque_source_t *,
    grim_zlib_inflate_stream_source_t *,
    unsigned long *);
int __cdecl grim_inflate_blocks_free(
    grim_inflate_blocks_opaque_source_t *,
    grim_zlib_inflate_stream_source_t *);
grim_inflate_blocks_opaque_source_t *__cdecl grim_inflate_blocks_new(
    grim_zlib_inflate_stream_source_t *,
    grim_zlib_inflate_check_source_fn_t,
    unsigned int);
int __cdecl grim_inflate_blocks(
    grim_inflate_blocks_opaque_source_t *,
    grim_zlib_inflate_stream_source_t *,
    int);
void *__cdecl grim_zcalloc(void *, unsigned int, unsigned int);
void __cdecl grim_zcfree(void *, void *);
unsigned long __cdecl grim_adler32(
    unsigned long, const unsigned char *, unsigned int);

int grim_inflate_reset(grim_zlib_inflate_stream_source_t *stream)
{
    if (stream == 0 || stream->state == 0)
        return -2;
    stream->total_input = stream->total_output = 0;
    stream->message = 0;
    stream->state->mode = stream->state->nowrap
        ? GRIM_STREAM_BLOCKS
        : GRIM_STREAM_METHOD;
    grim_inflate_blocks_reset(stream->state->blocks, stream, 0);
    return 0;
}

int grim_inflate_end(grim_zlib_inflate_stream_source_t *stream)
{
    if (stream == 0 || stream->state == 0 || stream->release == 0)
        return -2;
    if (stream->state->blocks != 0)
        grim_inflate_blocks_free(stream->state->blocks, stream);
    stream->release(stream->opaque, stream->state);
    stream->state = 0;
    return 0;
}

int grim_inflate_init2(
    grim_zlib_inflate_stream_source_t *stream,
    int window_bits,
    const char *version,
    int stream_size)
{
    if (version == 0 || version[0] != '1' ||
        stream_size != sizeof(grim_zlib_inflate_stream_source_t))
        return -6;

    if (stream == 0)
        return -2;
    stream->message = 0;
    if (stream->allocate == 0) {
        stream->allocate = grim_zcalloc;
        stream->opaque = 0;
    }
    if (stream->release == 0)
        stream->release = grim_zcfree;
    stream->state = (grim_zlib_inflate_state_source_t *)stream->allocate(
        stream->opaque, 1, sizeof(grim_zlib_inflate_state_source_t));
    if (stream->state == 0)
        return -4;
    stream->state->blocks = 0;

    stream->state->nowrap = 0;
    if (window_bits < 0) {
        window_bits = -window_bits;
        stream->state->nowrap = 1;
    }

    if (window_bits < 8 || window_bits > 15) {
        grim_inflate_end(stream);
        return -2;
    }
    stream->state->window_bits = (unsigned int)window_bits;

    stream->state->blocks = grim_inflate_blocks_new(
        stream,
        stream->state->nowrap ? 0 : grim_adler32,
        (unsigned int)1 << window_bits);
    if (stream->state->blocks == 0) {
        grim_inflate_end(stream);
        return -4;
    }

    grim_inflate_reset(stream);
    return 0;
}

int grim_inflate_init(
    grim_zlib_inflate_stream_source_t *stream,
    const char *version,
    int stream_size)
{
    return grim_inflate_init2(stream, 15, version, stream_size);
}

#define GRIM_STREAM_NEED_BYTE \
    { \
        if (stream->available_input == 0) \
            return result; \
        result = flush_result; \
    }
#define GRIM_STREAM_NEXT_BYTE \
    (stream->available_input--, stream->total_input++, *stream->next_input++)

int grim_inflate(
    grim_zlib_inflate_stream_source_t *stream,
    int flush_result)
{
    int result;
    unsigned int byte;

    if (stream == 0 || stream->state == 0 || stream->next_input == 0)
        return -2;
    flush_result = flush_result == 4 ? -5 : 0;
    result = -5;
    while (1)
        switch (stream->state->mode) {
        case GRIM_STREAM_METHOD:
            GRIM_STREAM_NEED_BYTE
            if (((stream->state->sub.method = GRIM_STREAM_NEXT_BYTE) & 0xf) !=
                8) {
                stream->state->mode = GRIM_STREAM_BAD;
                stream->message = "unknown compression method";
                stream->state->sub.marker = 5;
                break;
            }
            if ((stream->state->sub.method >> 4) + 8 >
                stream->state->window_bits) {
                stream->state->mode = GRIM_STREAM_BAD;
                stream->message = "invalid window size";
                stream->state->sub.marker = 5;
                break;
            }
            stream->state->mode = GRIM_STREAM_FLAG;
        case GRIM_STREAM_FLAG:
            GRIM_STREAM_NEED_BYTE
            byte = GRIM_STREAM_NEXT_BYTE;
            if (((stream->state->sub.method << 8) + byte) % 31) {
                stream->state->mode = GRIM_STREAM_BAD;
                stream->message = "incorrect header check";
                stream->state->sub.marker = 5;
                break;
            }
            if (!(byte & 0x20)) {
                stream->state->mode = GRIM_STREAM_BLOCKS;
                break;
            }
            stream->state->mode = GRIM_STREAM_DICT4;
        case GRIM_STREAM_DICT4:
            GRIM_STREAM_NEED_BYTE
            stream->state->sub.check.expected =
                (unsigned long)GRIM_STREAM_NEXT_BYTE << 24;
            stream->state->mode = GRIM_STREAM_DICT3;
        case GRIM_STREAM_DICT3:
            GRIM_STREAM_NEED_BYTE
            stream->state->sub.check.expected +=
                (unsigned long)GRIM_STREAM_NEXT_BYTE << 16;
            stream->state->mode = GRIM_STREAM_DICT2;
        case GRIM_STREAM_DICT2:
            GRIM_STREAM_NEED_BYTE
            stream->state->sub.check.expected +=
                (unsigned long)GRIM_STREAM_NEXT_BYTE << 8;
            stream->state->mode = GRIM_STREAM_DICT1;
        case GRIM_STREAM_DICT1:
            GRIM_STREAM_NEED_BYTE
            stream->state->sub.check.expected +=
                (unsigned long)GRIM_STREAM_NEXT_BYTE;
            stream->adler = stream->state->sub.check.expected;
            stream->state->mode = GRIM_STREAM_DICT0;
            return 2;
        case GRIM_STREAM_DICT0:
            stream->state->mode = GRIM_STREAM_BAD;
            stream->message = "need dictionary";
            stream->state->sub.marker = 0;
            return -2;
        case GRIM_STREAM_BLOCKS:
            if ((result = grim_inflate_blocks(
                     stream->state->blocks, stream, result)) == -3) {
                stream->state->mode = GRIM_STREAM_BAD;
                stream->state->sub.marker = 0;
                break;
            }
            if (result == 0)
                result = flush_result;
            if (result != 1)
                return result;
            result = flush_result;
            grim_inflate_blocks_reset(
                stream->state->blocks,
                stream,
                &stream->state->sub.check.actual);
            if (stream->state->nowrap) {
                stream->state->mode = GRIM_STREAM_DONE;
                break;
            }
            stream->state->mode = GRIM_STREAM_CHECK4;
        case GRIM_STREAM_CHECK4:
            GRIM_STREAM_NEED_BYTE
            stream->state->sub.check.expected =
                (unsigned long)GRIM_STREAM_NEXT_BYTE << 24;
            stream->state->mode = GRIM_STREAM_CHECK3;
        case GRIM_STREAM_CHECK3:
            GRIM_STREAM_NEED_BYTE
            stream->state->sub.check.expected +=
                (unsigned long)GRIM_STREAM_NEXT_BYTE << 16;
            stream->state->mode = GRIM_STREAM_CHECK2;
        case GRIM_STREAM_CHECK2:
            GRIM_STREAM_NEED_BYTE
            stream->state->sub.check.expected +=
                (unsigned long)GRIM_STREAM_NEXT_BYTE << 8;
            stream->state->mode = GRIM_STREAM_CHECK1;
        case GRIM_STREAM_CHECK1:
            GRIM_STREAM_NEED_BYTE
            stream->state->sub.check.expected +=
                (unsigned long)GRIM_STREAM_NEXT_BYTE;

            if (stream->state->sub.check.actual !=
                stream->state->sub.check.expected) {
                stream->state->mode = GRIM_STREAM_BAD;
                stream->message = "incorrect data check";
                stream->state->sub.marker = 5;
                break;
            }
            stream->state->mode = GRIM_STREAM_DONE;
        case GRIM_STREAM_DONE:
            return 1;
        case GRIM_STREAM_BAD:
            return -3;
        default:
            return -2;
        }
}
