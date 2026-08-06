/*
 * Matcher-only adaptation of zlib 1.1.3 infblock.c and adler32.c.
 * Copyright (C) 1995-1998 Mark Adler.
 *
 * The state layouts and algorithms follow the pinned upstream release. Names
 * are isolated so the scratch object can coexist with the reconstructed port.
 */

#include <string.h>

typedef struct grim_zlib_stream_source_s grim_zlib_stream_source_t;
typedef struct grim_inflate_blocks_state_source_s
    grim_inflate_blocks_state_source_t;

typedef void *(__cdecl *grim_zlib_alloc_source_fn_t)(
    void *, unsigned int, unsigned int);
typedef void (__cdecl *grim_zlib_free_source_fn_t)(void *, void *);
typedef unsigned long (__cdecl *grim_zlib_check_source_fn_t)(
    unsigned long, const unsigned char *, unsigned int);

struct grim_zlib_stream_source_s {
    unsigned char *next_input;
    unsigned int available_input;
    unsigned long total_input;
    unsigned char *next_output;
    unsigned int available_output;
    unsigned long total_output;
    char *message;
    void *state;
    grim_zlib_alloc_source_fn_t allocate;
    grim_zlib_free_source_fn_t release;
    void *opaque;
    int data_type;
    unsigned long adler;
    unsigned long reserved;
};

typedef struct grim_inflate_huft_source_s {
    union {
        struct {
            unsigned char operation;
            unsigned char bits;
        } what;
        unsigned int padding;
    } word;
    unsigned int base;
} grim_inflate_huft_source_t;

typedef enum grim_inflate_codes_mode_source_e {
    GRIM_INFLATE_CODE_START,
    GRIM_INFLATE_CODE_LEN,
    GRIM_INFLATE_CODE_LENEXT,
    GRIM_INFLATE_CODE_DIST,
    GRIM_INFLATE_CODE_DISTEXT,
    GRIM_INFLATE_CODE_COPY,
    GRIM_INFLATE_CODE_LIT,
    GRIM_INFLATE_CODE_WASH,
    GRIM_INFLATE_CODE_END,
    GRIM_INFLATE_CODE_BAD
} grim_inflate_codes_mode_source_t;

typedef struct grim_inflate_codes_state_source_s {
    grim_inflate_codes_mode_source_t mode;
    unsigned int length;
    union {
        struct {
            grim_inflate_huft_source_t *tree;
            unsigned int need;
        } code;
        unsigned int literal;
        struct {
            unsigned int extra;
            unsigned int distance;
        } copy;
    } sub;
    unsigned char literal_bits;
    unsigned char distance_bits;
    grim_inflate_huft_source_t *literal_tree;
    grim_inflate_huft_source_t *distance_tree;
} grim_inflate_codes_state_source_t;

typedef enum grim_inflate_block_mode_source_e {
    GRIM_INFLATE_TYPE,
    GRIM_INFLATE_LENS,
    GRIM_INFLATE_STORED,
    GRIM_INFLATE_TABLE,
    GRIM_INFLATE_BTREE,
    GRIM_INFLATE_DTREE,
    GRIM_INFLATE_CODES,
    GRIM_INFLATE_DRY,
    GRIM_INFLATE_DONE,
    GRIM_INFLATE_BAD
} grim_inflate_block_mode_source_t;

struct grim_inflate_blocks_state_source_s {
    grim_inflate_block_mode_source_t mode;
    union {
        unsigned int bytes_left;
        struct {
            unsigned int table;
            unsigned int index;
            unsigned int *bit_lengths;
            unsigned int bit_depth;
            grim_inflate_huft_source_t *bit_tree;
        } trees;
        struct {
            void *codes;
        } decode;
    } sub;
    unsigned int is_last;
    unsigned int bit_count;
    unsigned long bit_buffer;
    grim_inflate_huft_source_t *hufts;
    unsigned char *window;
    unsigned char *window_end;
    unsigned char *read;
    unsigned char *write;
    grim_zlib_check_source_fn_t check;
    unsigned long check_value;
};

void __cdecl grim_inflate_codes_free(
    void *, grim_zlib_stream_source_t *);

void grim_inflate_blocks_reset(
    grim_inflate_blocks_state_source_t *state,
    grim_zlib_stream_source_t *stream,
    unsigned long *check_value)
{
    if (check_value != 0)
        *check_value = state->check_value;
    if (state->mode == GRIM_INFLATE_BTREE ||
        state->mode == GRIM_INFLATE_DTREE)
        stream->release(stream->opaque, state->sub.trees.bit_lengths);
    if (state->mode == GRIM_INFLATE_CODES)
        grim_inflate_codes_free(state->sub.decode.codes, stream);
    state->mode = GRIM_INFLATE_TYPE;
    state->bit_count = 0;
    state->bit_buffer = 0;
    state->read = state->write = state->window;
    if (state->check != 0)
        stream->adler = state->check_value = state->check(0, 0, 0);
}

grim_inflate_blocks_state_source_t *grim_inflate_blocks_new(
    grim_zlib_stream_source_t *stream,
    grim_zlib_check_source_fn_t check,
    unsigned int window_size)
{
    grim_inflate_blocks_state_source_t *state;

    if ((state = (grim_inflate_blocks_state_source_t *)
             stream->allocate(
                 stream->opaque,
                 1,
                 sizeof(grim_inflate_blocks_state_source_t))) == 0)
        return state;
    if ((state->hufts = (grim_inflate_huft_source_t *)
             stream->allocate(
                 stream->opaque,
                 sizeof(grim_inflate_huft_source_t),
                 1440)) == 0) {
        stream->release(stream->opaque, state);
        return 0;
    }
    if ((state->window = (unsigned char *)stream->allocate(
             stream->opaque, 1, window_size)) == 0) {
        stream->release(stream->opaque, state->hufts);
        stream->release(stream->opaque, state);
        return 0;
    }
    state->window_end = state->window + window_size;
    state->check = check;
    state->mode = GRIM_INFLATE_TYPE;
    grim_inflate_blocks_reset(state, stream, 0);
    return state;
}

int grim_inflate_blocks_free(
    grim_inflate_blocks_state_source_t *state,
    grim_zlib_stream_source_t *stream)
{
    grim_inflate_blocks_reset(state, stream, 0);
    stream->release(stream->opaque, state->window);
    stream->release(stream->opaque, state->hufts);
    stream->release(stream->opaque, state);
    return 0;
}

#define GRIM_ADLER_BASE 65521L
#define GRIM_ADLER_NMAX 5552
#define GRIM_ADLER_DO1(buffer, index) \
    { sum1 += buffer[index]; sum2 += sum1; }
#define GRIM_ADLER_DO2(buffer, index) \
    GRIM_ADLER_DO1(buffer, index); GRIM_ADLER_DO1(buffer, index + 1);
#define GRIM_ADLER_DO4(buffer, index) \
    GRIM_ADLER_DO2(buffer, index); GRIM_ADLER_DO2(buffer, index + 2);
#define GRIM_ADLER_DO8(buffer, index) \
    GRIM_ADLER_DO4(buffer, index); GRIM_ADLER_DO4(buffer, index + 4);
#define GRIM_ADLER_DO16(buffer) \
    GRIM_ADLER_DO8(buffer, 0); GRIM_ADLER_DO8(buffer, 8);

unsigned long grim_adler32(
    unsigned long adler,
    const unsigned char *buffer,
    unsigned int length)
{
    unsigned long sum1 = adler & 0xffff;
    unsigned long sum2 = (adler >> 16) & 0xffff;
    int count;

    if (buffer == 0)
        return 1L;

    while (length > 0) {
        count = length < GRIM_ADLER_NMAX ? length : GRIM_ADLER_NMAX;
        length -= count;
        while (count >= 16) {
            GRIM_ADLER_DO16(buffer);
            buffer += 16;
            count -= 16;
        }
        if (count != 0)
            do {
                sum1 += *buffer++;
                sum2 += sum1;
            } while (--count);
        sum1 %= GRIM_ADLER_BASE;
        sum2 %= GRIM_ADLER_BASE;
    }
    return (sum2 << 16) | sum1;
}

grim_inflate_codes_state_source_t *grim_inflate_codes_new(
    unsigned int literal_bits,
    unsigned int distance_bits,
    grim_inflate_huft_source_t *literal_tree,
    grim_inflate_huft_source_t *distance_tree,
    grim_zlib_stream_source_t *stream)
{
    grim_inflate_codes_state_source_t *codes;

    if ((codes = (grim_inflate_codes_state_source_t *)stream->allocate(
             stream->opaque,
             1,
             sizeof(grim_inflate_codes_state_source_t))) != 0) {
        codes->mode = GRIM_INFLATE_CODE_START;
        codes->literal_bits = (unsigned char)literal_bits;
        codes->distance_bits = (unsigned char)distance_bits;
        codes->literal_tree = literal_tree;
        codes->distance_tree = distance_tree;
    }
    return codes;
}

int grim_inflate_flush(
    grim_inflate_blocks_state_source_t *state,
    grim_zlib_stream_source_t *stream,
    int result)
{
    unsigned int count;
    unsigned char *output;
    unsigned char *read;

    output = stream->next_output;
    read = state->read;

    count = (unsigned int)(
        (read <= state->write ? state->write : state->window_end) - read);
    if (count > stream->available_output)
        count = stream->available_output;
    if (count != 0 && result == -5)
        result = 0;

    stream->available_output -= count;
    stream->total_output += count;

    if (state->check != 0)
        stream->adler = state->check_value =
            state->check(state->check_value, read, count);

    memcpy(output, read, count);
    output += count;
    read += count;

    if (read == state->window_end) {
        read = state->window;
        if (state->write == state->window_end)
            state->write = state->window;

        count = (unsigned int)(state->write - read);
        if (count > stream->available_output)
            count = stream->available_output;
        if (count != 0 && result == -5)
            result = 0;

        stream->available_output -= count;
        stream->total_output += count;

        if (state->check != 0)
            stream->adler = state->check_value =
                state->check(state->check_value, read, count);

        memcpy(output, read, count);
        output += count;
        read += count;
    }

    stream->next_output = output;
    state->read = read;
    return result;
}
