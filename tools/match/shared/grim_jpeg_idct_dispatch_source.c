/*
 * Matcher-only reconstruction of the D3DX IJG inverse-DCT dispatchers.
 *
 * The pinned DirectX 8.1 archive identifies the two wrappers and their four
 * processor-specific callees.  D3DX keeps the IJG public entry points but
 * routes the integer transforms through an eight-byte-aligned workspace.
 */

typedef struct grim_jpeg_idct_decoder_source_s {
    unsigned char fields_000[0x11c];
    unsigned char *sample_range_limit;
} grim_jpeg_idct_decoder_source_t;

typedef struct grim_jpeg_idct_component_source_s {
    unsigned char fields_00[0x50];
    short *dct_table;
} grim_jpeg_idct_component_source_t;

extern unsigned char grim_jpeg_idct_processor_enabled;

void __cdecl grim_jpeg_idct_portable_islow(
    short *coefficients,
    short *multipliers,
    short *workspace,
    unsigned char **output,
    unsigned int output_column,
    unsigned char *range_limit);
void __cdecl grim_jpeg_idct_accelerated_islow(
    short *coefficients,
    short *multipliers,
    short *workspace,
    unsigned char **output,
    unsigned int output_column,
    unsigned char *range_limit);
void __cdecl grim_jpeg_idct_portable_ifast(
    short *coefficients,
    short *workspace,
    short *multipliers,
    unsigned char **output,
    unsigned int output_column,
    unsigned char *range_limit);
void __cdecl grim_jpeg_idct_accelerated_ifast(
    short *coefficients,
    short *workspace,
    short *multipliers,
    unsigned char **output,
    unsigned int output_column,
    unsigned char *range_limit);

void __cdecl grim_jpeg_idct_islow(
    grim_jpeg_idct_decoder_source_t *decoder,
    grim_jpeg_idct_component_source_t *component,
    short *coefficients,
    unsigned char **output,
    unsigned int output_column)
{
    unsigned char *range_limit;
    short workspace_storage[72];
    short *workspace;

    range_limit = decoder->sample_range_limit + 128;
    workspace = (short *) ((unsigned int)(workspace_storage + 4) & ~7u);
    component = (grim_jpeg_idct_component_source_t *) component->dct_table;

    if (grim_jpeg_idct_processor_enabled != 0) {
        grim_jpeg_idct_accelerated_islow(
            coefficients,
            (short *) component,
            workspace,
            output,
            output_column,
            range_limit);
    } else {
        grim_jpeg_idct_portable_islow(
            coefficients,
            (short *) component,
            workspace,
            output,
            output_column,
            range_limit);
    }
}

void __cdecl grim_jpeg_idct_ifast(
    grim_jpeg_idct_decoder_source_t *decoder,
    grim_jpeg_idct_component_source_t *component,
    short *coefficients,
    unsigned char **output,
    unsigned int output_column)
{
    unsigned char *range_limit;
    short workspace_storage[72];
    short *workspace;

    range_limit = decoder->sample_range_limit + 128;
    workspace = (short *) ((unsigned int)(workspace_storage + 4) & ~7u);
    component = (grim_jpeg_idct_component_source_t *) component->dct_table;

    if (grim_jpeg_idct_processor_enabled != 0) {
        grim_jpeg_idct_accelerated_ifast(
            coefficients,
            workspace,
            (short *) component,
            output,
            output_column,
            range_limit);
    } else {
        grim_jpeg_idct_portable_ifast(
            coefficients,
            workspace,
            (short *) component,
            output,
            output_column,
            range_limit);
    }
}
