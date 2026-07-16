extern "C" int grim_dxt5_decode_block(float *rgba, unsigned int *block);
extern "C" int __fastcall grim_dxt_unpremultiply_rgba_block(float *rgba);

extern "C" int grim_dxt4_decode_block(float *rgba, unsigned int *block)
{
    int result = grim_dxt5_decode_block(rgba, block);
    if (result >= 0) {
        result = grim_dxt_unpremultiply_rgba_block(rgba);
        if (result >= 0) {
            return 0;
        }
    }
    return result;
}
