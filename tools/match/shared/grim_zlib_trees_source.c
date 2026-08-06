/*
 * Matcher-only adaptation of zlib 1.1.3 inftrees.c.
 * Copyright (C) 1995-1998 Mark Adler.
 *
 * The table builder and wrappers follow the pinned upstream release. Names
 * are isolated so the scratch object can coexist with the reconstructed port.
 */

typedef struct grim_zlib_tree_stream_source_s grim_zlib_tree_stream_source_t;

typedef void *(__cdecl *grim_zlib_tree_alloc_source_fn_t)(
    void *, unsigned int, unsigned int);
typedef void (__cdecl *grim_zlib_tree_free_source_fn_t)(void *, void *);

struct grim_zlib_tree_stream_source_s {
    unsigned char *next_input;
    unsigned int available_input;
    unsigned long total_input;
    unsigned char *next_output;
    unsigned int available_output;
    unsigned long total_output;
    char *message;
    void *state;
    grim_zlib_tree_alloc_source_fn_t allocate;
    grim_zlib_tree_free_source_fn_t release;
    void *opaque;
    int data_type;
    unsigned long adler;
    unsigned long reserved;
};

typedef struct grim_inflate_tree_huft_source_s {
    union {
        struct {
            unsigned char operation;
            unsigned char bits;
        } what;
        unsigned int padding;
    } word;
    unsigned int base;
} grim_inflate_tree_huft_source_t;

#define GRIM_TREE_OPERATION word.what.operation
#define GRIM_TREE_BITS word.what.bits
#define GRIM_TREE_BMAX 15
#define GRIM_TREE_MANY 1440

static const unsigned int grim_zlib_cplens[31] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0
};

static const unsigned int grim_zlib_cplext[31] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 112, 112
};

static const unsigned int grim_zlib_cpdist[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577
};

static const unsigned int grim_zlib_cpdext[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

static int grim_huft_build(
    unsigned int *lengths,
    unsigned int code_count,
    unsigned int simple_count,
    const unsigned int *base_values,
    const unsigned int *extra_bits,
    grim_inflate_tree_huft_source_t **tree,
    unsigned int *maximum_bits,
    grim_inflate_tree_huft_source_t *table_space,
    unsigned int *tables_used,
    unsigned int *values)
{
    unsigned int codes_at_length;
    unsigned int length_counts[GRIM_TREE_BMAX + 1];
    unsigned int table_stride;
    int maximum_length;
    int table_level;
    register unsigned int code;
    register unsigned int table_index;
    register int code_length;
    int table_bits;
    unsigned int mask;
    register unsigned int *cursor;
    grim_inflate_tree_huft_source_t *table;
    grim_inflate_tree_huft_source_t entry;
    grim_inflate_tree_huft_source_t *table_stack[GRIM_TREE_BMAX];
    register int consumed_bits;
    unsigned int offsets[GRIM_TREE_BMAX + 1];
    unsigned int *offset_cursor;
    int dummy_codes;
    unsigned int table_entries;

    cursor = length_counts;
#define GRIM_TREE_CLEAR_ONE *cursor++ = 0;
#define GRIM_TREE_CLEAR_TWO \
    GRIM_TREE_CLEAR_ONE GRIM_TREE_CLEAR_ONE GRIM_TREE_CLEAR_ONE GRIM_TREE_CLEAR_ONE
#define GRIM_TREE_CLEAR_FOUR \
    GRIM_TREE_CLEAR_TWO GRIM_TREE_CLEAR_TWO GRIM_TREE_CLEAR_TWO GRIM_TREE_CLEAR_TWO
    GRIM_TREE_CLEAR_FOUR
    cursor = lengths;
    code = code_count;
    do {
        length_counts[*cursor++]++;
    } while (--code);
    if (length_counts[0] == code_count) {
        *tree = (grim_inflate_tree_huft_source_t *)0;
        *maximum_bits = 0;
        return 0;
    }

    table_bits = *maximum_bits;
    for (table_index = 1; table_index <= GRIM_TREE_BMAX; table_index++)
        if (length_counts[table_index])
            break;
    code_length = table_index;
    if ((unsigned int)table_bits < table_index)
        table_bits = table_index;
    for (code = GRIM_TREE_BMAX; code; code--)
        if (length_counts[code])
            break;
    maximum_length = code;
    if ((unsigned int)table_bits > code)
        table_bits = code;
    *maximum_bits = table_bits;

    for (dummy_codes = 1 << table_index;
         table_index < code;
         table_index++, dummy_codes <<= 1)
        if ((dummy_codes -= length_counts[table_index]) < 0)
            return -3;
    if ((dummy_codes -= length_counts[code]) < 0)
        return -3;
    length_counts[code] += dummy_codes;

    offsets[1] = table_index = 0;
    cursor = length_counts + 1;
    offset_cursor = offsets + 2;
    while (--code)
        *offset_cursor++ = (table_index += *cursor++);

    cursor = lengths;
    code = 0;
    do {
        if ((table_index = *cursor++) != 0)
            values[offsets[table_index]++] = code;
    } while (++code < code_count);
    code_count = offsets[maximum_length];

    offsets[0] = code = 0;
    cursor = values;
    table_level = -1;
    consumed_bits = -table_bits;
    table_stack[0] = (grim_inflate_tree_huft_source_t *)0;
    table = (grim_inflate_tree_huft_source_t *)0;
    table_entries = 0;

    for (; code_length <= maximum_length; code_length++) {
        codes_at_length = length_counts[code_length];
        while (codes_at_length--) {
            while (code_length > consumed_bits + table_bits) {
                table_level++;
                consumed_bits += table_bits;

                table_entries = maximum_length - consumed_bits;
                table_entries = table_entries > (unsigned int)table_bits
                    ? table_bits
                    : table_entries;
                if ((table_stride = 1 << (table_index =
                         code_length - consumed_bits)) >
                    codes_at_length + 1) {
                    table_stride -= codes_at_length + 1;
                    offset_cursor = length_counts + code_length;
                    if (table_index < table_entries)
                        while (++table_index < table_entries) {
                            if ((table_stride <<= 1) <= *++offset_cursor)
                                break;
                            table_stride -= *offset_cursor;
                        }
                }
                table_entries = 1 << table_index;

                if (*tables_used + table_entries > GRIM_TREE_MANY)
                    return -4;
                table_stack[table_level] = table = table_space + *tables_used;
                *tables_used += table_entries;

                if (table_level) {
                    offsets[table_level] = code;
                    entry.GRIM_TREE_BITS = (unsigned char)table_bits;
                    entry.GRIM_TREE_OPERATION = (unsigned char)table_index;
                    table_index = code >> (consumed_bits - table_bits);
                    entry.base = (unsigned int)(
                        table - table_stack[table_level - 1] - table_index);
                    table_stack[table_level - 1][table_index] = entry;
                } else {
                    *tree = table;
                }
            }

            entry.GRIM_TREE_BITS = (unsigned char)(code_length - consumed_bits);
            if (cursor >= values + code_count) {
                entry.GRIM_TREE_OPERATION = 128 + 64;
            } else if (*cursor < simple_count) {
                entry.GRIM_TREE_OPERATION =
                    (unsigned char)(*cursor < 256 ? 0 : 32 + 64);
                entry.base = *cursor++;
            } else {
                entry.GRIM_TREE_OPERATION =
                    (unsigned char)(extra_bits[*cursor - simple_count] + 16 + 64);
                entry.base = base_values[*cursor++ - simple_count];
            }

            table_stride = 1 << (code_length - consumed_bits);
            for (table_index = code >> consumed_bits;
                 table_index < table_entries;
                 table_index += table_stride)
                table[table_index] = entry;

            for (table_index = 1 << (code_length - 1);
                 code & table_index;
                 table_index >>= 1)
                code ^= table_index;
            code ^= table_index;

            mask = (1 << consumed_bits) - 1;
            while ((code & mask) != offsets[table_level]) {
                table_level--;
                consumed_bits -= table_bits;
                mask = (1 << consumed_bits) - 1;
            }
        }
    }

    return dummy_codes != 0 && maximum_length != 1 ? -5 : 0;
}

int grim_inflate_trees_bits(
    unsigned int *lengths,
    unsigned int *bit_depth,
    grim_inflate_tree_huft_source_t **tree,
    grim_inflate_tree_huft_source_t *table_space,
    grim_zlib_tree_stream_source_t *stream)
{
    int result;
    unsigned int tables_used = 0;
    unsigned int *values;

    if ((values = (unsigned int *)stream->allocate(
             stream->opaque, 19, sizeof(unsigned int))) == 0)
        return -4;
    result = grim_huft_build(
        lengths, 19, 19, 0, 0, tree, bit_depth, table_space, &tables_used, values);
    if (result == -3)
        stream->message = "oversubscribed dynamic bit lengths tree";
    else if (result == -5 || *bit_depth == 0) {
        stream->message = "incomplete dynamic bit lengths tree";
        result = -3;
    }
    stream->release(stream->opaque, values);
    return result;
}

int grim_inflate_trees_dynamic(
    unsigned int literal_count,
    unsigned int distance_count,
    unsigned int *lengths,
    unsigned int *literal_depth,
    unsigned int *distance_depth,
    grim_inflate_tree_huft_source_t **literal_tree,
    grim_inflate_tree_huft_source_t **distance_tree,
    grim_inflate_tree_huft_source_t *table_space,
    grim_zlib_tree_stream_source_t *stream)
{
    int result;
    unsigned int tables_used = 0;
    unsigned int *values;

    if ((values = (unsigned int *)stream->allocate(
             stream->opaque, 288, sizeof(unsigned int))) == 0)
        return -4;

    result = grim_huft_build(
        lengths,
        literal_count,
        257,
        grim_zlib_cplens,
        grim_zlib_cplext,
        literal_tree,
        literal_depth,
        table_space,
        &tables_used,
        values);
    if (result != 0 || *literal_depth == 0) {
        if (result == -3)
            stream->message = "oversubscribed literal/length tree";
        else if (result != -4) {
            stream->message = "incomplete literal/length tree";
            result = -3;
        }
        stream->release(stream->opaque, values);
        return result;
    }

    result = grim_huft_build(
        lengths + literal_count,
        distance_count,
        0,
        grim_zlib_cpdist,
        grim_zlib_cpdext,
        distance_tree,
        distance_depth,
        table_space,
        &tables_used,
        values);
    if (result != 0 || (*distance_depth == 0 && literal_count > 257)) {
        if (result == -3)
            stream->message = "oversubscribed distance tree";
        else if (result == -5) {
            stream->message = "incomplete distance tree";
            result = -3;
        } else if (result != -4) {
            stream->message = "empty distance tree with lengths";
            result = -3;
        }
        stream->release(stream->opaque, values);
        return result;
    }

    stream->release(stream->opaque, values);
    return 0;
}

static unsigned int grim_zlib_fixed_literal_bits = 9;
static unsigned int grim_zlib_fixed_distance_bits = 5;
extern grim_inflate_tree_huft_source_t grim_zlib_fixed_literal_tree[];
extern grim_inflate_tree_huft_source_t grim_zlib_fixed_distance_tree[];

int grim_inflate_trees_fixed(
    unsigned int *literal_depth,
    unsigned int *distance_depth,
    grim_inflate_tree_huft_source_t **literal_tree,
    grim_inflate_tree_huft_source_t **distance_tree,
    grim_zlib_tree_stream_source_t *stream)
{
    *literal_depth = grim_zlib_fixed_literal_bits;
    *distance_depth = grim_zlib_fixed_distance_bits;
    *literal_tree = grim_zlib_fixed_literal_tree;
    *distance_tree = grim_zlib_fixed_distance_tree;
    return 0;
}
