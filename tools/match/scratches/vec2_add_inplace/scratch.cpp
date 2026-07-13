int vec2_add_inplace(int entity_index, float *pos, float *delta)
{
    pos[0] = pos[0] + delta[0];
    pos[1] = delta[1] + pos[1];
    return 0;
}
