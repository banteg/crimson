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

extern unsigned int grim_inflate_mask[17];

int __cdecl grim_inflate_fast(
    unsigned int,
    unsigned int,
    grim_inflate_huft_source_t *,
    grim_inflate_huft_source_t *,
    grim_inflate_blocks_state_source_t *,
    grim_zlib_stream_source_t *);

#define GRIM_INFLATE_UPDATE_BITS \
    { state->bit_buffer = bit_buffer; state->bit_count = bit_count; }
#define GRIM_INFLATE_UPDATE_INPUT \
    { \
        stream->available_input = available_input; \
        stream->total_input += input - stream->next_input; \
        stream->next_input = input; \
    }
#define GRIM_INFLATE_UPDATE_OUTPUT \
    { state->write = output; }
#define GRIM_INFLATE_UPDATE \
    { \
        GRIM_INFLATE_UPDATE_BITS \
        GRIM_INFLATE_UPDATE_INPUT \
        GRIM_INFLATE_UPDATE_OUTPUT \
    }
#define GRIM_INFLATE_LEAVE \
    { \
        GRIM_INFLATE_UPDATE \
        return grim_inflate_flush(state, stream, result); \
    }
#define GRIM_INFLATE_LOAD_INPUT \
    { \
        input = stream->next_input; \
        available_input = stream->available_input; \
        bit_buffer = state->bit_buffer; \
        bit_count = state->bit_count; \
    }
#define GRIM_INFLATE_NEED_BYTE \
    { \
        if (available_input) \
            result = 0; \
        else \
            GRIM_INFLATE_LEAVE \
    }
#define GRIM_INFLATE_NEXT_BYTE (available_input--, *input++)
#define GRIM_INFLATE_NEED_BITS(count) \
    { \
        while (bit_count < (count)) { \
            GRIM_INFLATE_NEED_BYTE \
            bit_buffer |= ((unsigned long)GRIM_INFLATE_NEXT_BYTE) << bit_count; \
            bit_count += 8; \
        } \
    }
#define GRIM_INFLATE_DUMP_BITS(count) \
    { bit_buffer >>= (count); bit_count -= (count); }
#define GRIM_INFLATE_WINDOW_AVAILABLE \
    (unsigned int)(output < state->read \
        ? state->read - output - 1 \
        : state->window_end - output)
#define GRIM_INFLATE_LOAD_OUTPUT \
    { output = state->write; available_output = GRIM_INFLATE_WINDOW_AVAILABLE; }
#define GRIM_INFLATE_WRAP_OUTPUT \
    { \
        if (output == state->window_end && state->read != state->window) { \
            output = state->window; \
            available_output = GRIM_INFLATE_WINDOW_AVAILABLE; \
        } \
    }
#define GRIM_INFLATE_FLUSH_OUTPUT \
    { \
        GRIM_INFLATE_UPDATE_OUTPUT \
        result = grim_inflate_flush(state, stream, result); \
        GRIM_INFLATE_LOAD_OUTPUT \
    }
#define GRIM_INFLATE_NEED_OUTPUT \
    { \
        if (available_output == 0) { \
            GRIM_INFLATE_WRAP_OUTPUT \
            if (available_output == 0) { \
                GRIM_INFLATE_FLUSH_OUTPUT \
                GRIM_INFLATE_WRAP_OUTPUT \
                if (available_output == 0) \
                    GRIM_INFLATE_LEAVE \
            } \
        } \
        result = 0; \
    }
#define GRIM_INFLATE_OUTPUT_BYTE(value) \
    { *output++ = (unsigned char)(value); available_output--; }
#define GRIM_INFLATE_LOAD \
    { GRIM_INFLATE_LOAD_INPUT GRIM_INFLATE_LOAD_OUTPUT }

int grim_inflate_codes(
    grim_inflate_blocks_state_source_t *state,
    grim_zlib_stream_source_t *stream,
    int result)
{
    unsigned int temporary;
    grim_inflate_huft_source_t *tree_entry;
    unsigned int operation;
    unsigned long bit_buffer;
    unsigned int bit_count;
    unsigned char *input;
    unsigned int available_input;
    unsigned char *output;
    unsigned int available_output;
    unsigned char *copy;
    grim_inflate_codes_state_source_t *codes =
        (grim_inflate_codes_state_source_t *)state->sub.decode.codes;

    GRIM_INFLATE_LOAD

    while (1)
        switch (codes->mode) {
        case GRIM_INFLATE_CODE_START:
            if (available_output >= 258 && available_input >= 10) {
                GRIM_INFLATE_UPDATE
                result = grim_inflate_fast(
                    codes->literal_bits,
                    codes->distance_bits,
                    codes->literal_tree,
                    codes->distance_tree,
                    state,
                    stream);
                GRIM_INFLATE_LOAD
                if (result != 0) {
                    codes->mode = result == 1
                        ? GRIM_INFLATE_CODE_WASH
                        : GRIM_INFLATE_CODE_BAD;
                    break;
                }
            }
            codes->sub.code.need = codes->literal_bits;
            codes->sub.code.tree = codes->literal_tree;
            codes->mode = GRIM_INFLATE_CODE_LEN;
        case GRIM_INFLATE_CODE_LEN:
            temporary = codes->sub.code.need;
            GRIM_INFLATE_NEED_BITS(temporary)
            tree_entry = codes->sub.code.tree +
                ((unsigned int)bit_buffer & grim_inflate_mask[temporary]);
            GRIM_INFLATE_DUMP_BITS(tree_entry->word.what.bits)
            operation = (unsigned int)tree_entry->word.what.operation;
            if (operation == 0) {
                codes->sub.literal = tree_entry->base;
                codes->mode = GRIM_INFLATE_CODE_LIT;
                break;
            }
            if (operation & 16) {
                codes->sub.copy.extra = operation & 15;
                codes->length = tree_entry->base;
                codes->mode = GRIM_INFLATE_CODE_LENEXT;
                break;
            }
            if ((operation & 64) == 0) {
                codes->sub.code.need = operation;
                codes->sub.code.tree = tree_entry + tree_entry->base;
                break;
            }
            if (operation & 32) {
                codes->mode = GRIM_INFLATE_CODE_WASH;
                break;
            }
            codes->mode = GRIM_INFLATE_CODE_BAD;
            stream->message = "invalid literal/length code";
            result = -3;
            GRIM_INFLATE_LEAVE
        case GRIM_INFLATE_CODE_LENEXT:
            temporary = codes->sub.copy.extra;
            GRIM_INFLATE_NEED_BITS(temporary)
            codes->length +=
                (unsigned int)bit_buffer & grim_inflate_mask[temporary];
            GRIM_INFLATE_DUMP_BITS(temporary)
            codes->sub.code.need = codes->distance_bits;
            codes->sub.code.tree = codes->distance_tree;
            codes->mode = GRIM_INFLATE_CODE_DIST;
        case GRIM_INFLATE_CODE_DIST:
            temporary = codes->sub.code.need;
            GRIM_INFLATE_NEED_BITS(temporary)
            tree_entry = codes->sub.code.tree +
                ((unsigned int)bit_buffer & grim_inflate_mask[temporary]);
            GRIM_INFLATE_DUMP_BITS(tree_entry->word.what.bits)
            operation = (unsigned int)tree_entry->word.what.operation;
            if (operation & 16) {
                codes->sub.copy.extra = operation & 15;
                codes->sub.copy.distance = tree_entry->base;
                codes->mode = GRIM_INFLATE_CODE_DISTEXT;
                break;
            }
            if ((operation & 64) == 0) {
                codes->sub.code.need = operation;
                codes->sub.code.tree = tree_entry + tree_entry->base;
                break;
            }
            codes->mode = GRIM_INFLATE_CODE_BAD;
            stream->message = "invalid distance code";
            result = -3;
            GRIM_INFLATE_LEAVE
        case GRIM_INFLATE_CODE_DISTEXT:
            temporary = codes->sub.copy.extra;
            GRIM_INFLATE_NEED_BITS(temporary)
            codes->sub.copy.distance +=
                (unsigned int)bit_buffer & grim_inflate_mask[temporary];
            GRIM_INFLATE_DUMP_BITS(temporary)
            codes->mode = GRIM_INFLATE_CODE_COPY;
        case GRIM_INFLATE_CODE_COPY:
            copy = (unsigned int)(output - state->window) <
                    codes->sub.copy.distance
                ? state->window_end -
                    (codes->sub.copy.distance - (output - state->window))
                : output - codes->sub.copy.distance;
            while (codes->length) {
                GRIM_INFLATE_NEED_OUTPUT
                GRIM_INFLATE_OUTPUT_BYTE(*copy++)
                if (copy == state->window_end)
                    copy = state->window;
                codes->length--;
            }
            codes->mode = GRIM_INFLATE_CODE_START;
            break;
        case GRIM_INFLATE_CODE_LIT:
            GRIM_INFLATE_NEED_OUTPUT
            GRIM_INFLATE_OUTPUT_BYTE(codes->sub.literal)
            codes->mode = GRIM_INFLATE_CODE_START;
            break;
        case GRIM_INFLATE_CODE_WASH:
            if (bit_count > 7) {
                bit_count -= 8;
                available_input++;
                input--;
            }
            GRIM_INFLATE_FLUSH_OUTPUT
            if (state->read != state->write)
                GRIM_INFLATE_LEAVE
            codes->mode = GRIM_INFLATE_CODE_END;
        case GRIM_INFLATE_CODE_END:
            result = 1;
            GRIM_INFLATE_LEAVE
        case GRIM_INFLATE_CODE_BAD:
            result = -3;
            GRIM_INFLATE_LEAVE
        default:
            result = -2;
            GRIM_INFLATE_LEAVE
        }
}

static const unsigned int grim_inflate_border[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

int __cdecl grim_inflate_trees_fixed(
    unsigned int *,
    unsigned int *,
    grim_inflate_huft_source_t **,
    grim_inflate_huft_source_t **,
    grim_zlib_stream_source_t *);
int __cdecl grim_inflate_trees_bits(
    unsigned int *,
    unsigned int *,
    grim_inflate_huft_source_t **,
    grim_inflate_huft_source_t *,
    grim_zlib_stream_source_t *);
int __cdecl grim_inflate_trees_dynamic(
    unsigned int,
    unsigned int,
    unsigned int *,
    unsigned int *,
    unsigned int *,
    grim_inflate_huft_source_t **,
    grim_inflate_huft_source_t **,
    grim_inflate_huft_source_t *,
    grim_zlib_stream_source_t *);

int grim_inflate_blocks(
    grim_inflate_blocks_state_source_t *state,
    grim_zlib_stream_source_t *stream,
    int result)
{
    unsigned int temporary;
    unsigned long bit_buffer;
    unsigned int bit_count;
    unsigned char *input;
    unsigned int available_input;
    unsigned char *output;
    unsigned int available_output;

    GRIM_INFLATE_LOAD

    while (1)
        switch (state->mode) {
        case GRIM_INFLATE_TYPE:
            GRIM_INFLATE_NEED_BITS(3)
            temporary = (unsigned int)bit_buffer & 7;
            state->is_last = temporary & 1;
            switch (temporary >> 1) {
            case 0:
                GRIM_INFLATE_DUMP_BITS(3)
                temporary = bit_count & 7;
                GRIM_INFLATE_DUMP_BITS(temporary)
                state->mode = GRIM_INFLATE_LENS;
                break;
            case 1:
                {
                    unsigned int literal_bits;
                    unsigned int distance_bits;
                    grim_inflate_huft_source_t *literal_tree;
                    grim_inflate_huft_source_t *distance_tree;

                    grim_inflate_trees_fixed(
                        &literal_bits,
                        &distance_bits,
                        &literal_tree,
                        &distance_tree,
                        stream);
                    state->sub.decode.codes = grim_inflate_codes_new(
                        literal_bits,
                        distance_bits,
                        literal_tree,
                        distance_tree,
                        stream);
                    if (state->sub.decode.codes == 0) {
                        result = -4;
                        GRIM_INFLATE_LEAVE
                    }
                }
                GRIM_INFLATE_DUMP_BITS(3)
                state->mode = GRIM_INFLATE_CODES;
                break;
            case 2:
                GRIM_INFLATE_DUMP_BITS(3)
                state->mode = GRIM_INFLATE_TABLE;
                break;
            case 3:
                GRIM_INFLATE_DUMP_BITS(3)
                state->mode = GRIM_INFLATE_BAD;
                stream->message = "invalid block type";
                result = -3;
                GRIM_INFLATE_LEAVE
            }
            break;
        case GRIM_INFLATE_LENS:
            GRIM_INFLATE_NEED_BITS(32)
            if ((((~bit_buffer) >> 16) & 0xffff) !=
                (bit_buffer & 0xffff)) {
                state->mode = GRIM_INFLATE_BAD;
                stream->message = "invalid stored block lengths";
                result = -3;
                GRIM_INFLATE_LEAVE
            }
            state->sub.bytes_left = (unsigned int)bit_buffer & 0xffff;
            bit_buffer = bit_count = 0;
            state->mode = state->sub.bytes_left
                ? GRIM_INFLATE_STORED
                : (state->is_last ? GRIM_INFLATE_DRY : GRIM_INFLATE_TYPE);
            break;
        case GRIM_INFLATE_STORED:
            if (available_input == 0)
                GRIM_INFLATE_LEAVE
            GRIM_INFLATE_NEED_OUTPUT
            temporary = state->sub.bytes_left;
            if (temporary > available_input)
                temporary = available_input;
            if (temporary > available_output)
                temporary = available_output;
            memcpy(output, input, temporary);
            input += temporary;
            available_input -= temporary;
            output += temporary;
            available_output -= temporary;
            if ((state->sub.bytes_left -= temporary) != 0)
                break;
            state->mode = state->is_last
                ? GRIM_INFLATE_DRY
                : GRIM_INFLATE_TYPE;
            break;
        case GRIM_INFLATE_TABLE:
            GRIM_INFLATE_NEED_BITS(14)
            state->sub.trees.table = temporary =
                (unsigned int)bit_buffer & 0x3fff;
            if ((temporary & 0x1f) > 29 ||
                ((temporary >> 5) & 0x1f) > 29) {
                state->mode = GRIM_INFLATE_BAD;
                stream->message = "too many length or distance symbols";
                result = -3;
                GRIM_INFLATE_LEAVE
            }
            temporary = 258 + (temporary & 0x1f) +
                ((temporary >> 5) & 0x1f);
            state->sub.trees.bit_lengths =
                (unsigned int *)stream->allocate(
                    stream->opaque,
                    temporary,
                    sizeof(unsigned int));
            if (state->sub.trees.bit_lengths == 0) {
                result = -4;
                GRIM_INFLATE_LEAVE
            }
            GRIM_INFLATE_DUMP_BITS(14)
            state->sub.trees.index = 0;
            state->mode = GRIM_INFLATE_BTREE;
        case GRIM_INFLATE_BTREE:
            while (state->sub.trees.index <
                   4 + (state->sub.trees.table >> 10)) {
                GRIM_INFLATE_NEED_BITS(3)
                state->sub.trees.bit_lengths[
                    grim_inflate_border[state->sub.trees.index++]] =
                    (unsigned int)bit_buffer & 7;
                GRIM_INFLATE_DUMP_BITS(3)
            }
            while (state->sub.trees.index < 19)
                state->sub.trees.bit_lengths[
                    grim_inflate_border[state->sub.trees.index++]] = 0;
            state->sub.trees.bit_depth = 7;
            temporary = grim_inflate_trees_bits(
                state->sub.trees.bit_lengths,
                &state->sub.trees.bit_depth,
                &state->sub.trees.bit_tree,
                state->hufts,
                stream);
            if (temporary != 0) {
                stream->release(stream->opaque, state->sub.trees.bit_lengths);
                result = temporary;
                if (result == -3)
                    state->mode = GRIM_INFLATE_BAD;
                GRIM_INFLATE_LEAVE
            }
            state->sub.trees.index = 0;
            state->mode = GRIM_INFLATE_DTREE;
        case GRIM_INFLATE_DTREE:
            while (temporary = state->sub.trees.table,
                   state->sub.trees.index <
                       258 + (temporary & 0x1f) +
                           ((temporary >> 5) & 0x1f)) {
                grim_inflate_huft_source_t *entry;
                unsigned int extra_bits;
                unsigned int repeat_count;
                unsigned int code;

                temporary = state->sub.trees.bit_depth;
                GRIM_INFLATE_NEED_BITS(temporary)
                entry = state->sub.trees.bit_tree +
                    ((unsigned int)bit_buffer &
                     grim_inflate_mask[temporary]);
                temporary = entry->word.what.bits;
                code = entry->base;
                if (code < 16) {
                    GRIM_INFLATE_DUMP_BITS(temporary)
                    state->sub.trees.bit_lengths[
                        state->sub.trees.index++] = code;
                } else {
                    extra_bits = code == 18 ? 7 : code - 14;
                    repeat_count = code == 18 ? 11 : 3;
                    GRIM_INFLATE_NEED_BITS(temporary + extra_bits)
                    GRIM_INFLATE_DUMP_BITS(temporary)
                    repeat_count += (unsigned int)bit_buffer &
                        grim_inflate_mask[extra_bits];
                    GRIM_INFLATE_DUMP_BITS(extra_bits)
                    extra_bits = state->sub.trees.index;
                    temporary = state->sub.trees.table;
                    if (extra_bits + repeat_count >
                            258 + (temporary & 0x1f) +
                                ((temporary >> 5) & 0x1f) ||
                        (code == 16 && extra_bits < 1)) {
                        stream->release(
                            stream->opaque,
                            state->sub.trees.bit_lengths);
                        state->mode = GRIM_INFLATE_BAD;
                        stream->message = "invalid bit length repeat";
                        result = -3;
                        GRIM_INFLATE_LEAVE
                    }
                    code = code == 16
                        ? state->sub.trees.bit_lengths[extra_bits - 1]
                        : 0;
                    do {
                        state->sub.trees.bit_lengths[extra_bits++] = code;
                    } while (--repeat_count);
                    state->sub.trees.index = extra_bits;
                }
            }
            state->sub.trees.bit_tree = 0;
            {
                unsigned int literal_bits;
                unsigned int distance_bits;
                grim_inflate_huft_source_t *literal_tree;
                grim_inflate_huft_source_t *distance_tree;
                grim_inflate_codes_state_source_t *codes;

                literal_bits = 9;
                distance_bits = 6;
                temporary = state->sub.trees.table;
                temporary = grim_inflate_trees_dynamic(
                    257 + (temporary & 0x1f),
                    1 + ((temporary >> 5) & 0x1f),
                    state->sub.trees.bit_lengths,
                    &literal_bits,
                    &distance_bits,
                    &literal_tree,
                    &distance_tree,
                    state->hufts,
                    stream);
                stream->release(
                    stream->opaque,
                    state->sub.trees.bit_lengths);
                if (temporary != 0) {
                    if (temporary == (unsigned int)-3)
                        state->mode = GRIM_INFLATE_BAD;
                    result = temporary;
                    GRIM_INFLATE_LEAVE
                }
                codes = grim_inflate_codes_new(
                    literal_bits,
                    distance_bits,
                    literal_tree,
                    distance_tree,
                    stream);
                if (codes == 0) {
                    result = -4;
                    GRIM_INFLATE_LEAVE
                }
                state->sub.decode.codes = codes;
            }
            state->mode = GRIM_INFLATE_CODES;
        case GRIM_INFLATE_CODES:
            GRIM_INFLATE_UPDATE
            result = grim_inflate_codes(state, stream, result);
            if (result != 1)
                return grim_inflate_flush(state, stream, result);
            result = 0;
            grim_inflate_codes_free(state->sub.decode.codes, stream);
            GRIM_INFLATE_LOAD
            if (!state->is_last) {
                state->mode = GRIM_INFLATE_TYPE;
                break;
            }
            state->mode = GRIM_INFLATE_DRY;
        case GRIM_INFLATE_DRY:
            GRIM_INFLATE_FLUSH_OUTPUT
            if (state->read != state->write)
                GRIM_INFLATE_LEAVE
            state->mode = GRIM_INFLATE_DONE;
        case GRIM_INFLATE_DONE:
            result = 1;
            GRIM_INFLATE_LEAVE
        case GRIM_INFLATE_BAD:
            result = -3;
            GRIM_INFLATE_LEAVE
        default:
            result = -2;
            GRIM_INFLATE_LEAVE
        }
}
