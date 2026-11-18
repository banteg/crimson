extern "C" {
extern int config_game_mode, config_player_count;
extern char freeware_score_key[243];

void freeware_score_key_init()
{
    int seed = 0;
    for (int i = 0; i < 243; ++i) {
        seed = -2 * seed;
        freeware_score_key[i] = (((i % 21) * (seed % 5) * (seed + 3) * seed * 42
            + (i + 1) * i - config_player_count * seed * 44 + config_player_count + 6) * i
            + config_game_mode * 124);
    }
}

void freeware_score_encode(char *bytes, int size)
{
    int checksum = 0;
    for (int i = 0; i < size; ++i) {
        checksum += bytes[i] * (int)(i * .7f);
        bytes[i] += freeware_score_key[i % 243];
    }
    *(int *)(bytes + size) = checksum;
}

unsigned char freeware_score_decode(char *bytes, int size)
{
    int checksum = 0;
    for (int i = 0; i < size; ++i) {
        bytes[i] -= freeware_score_key[i % 243];
        checksum += bytes[i] * (int)(i * .7f);
    }
    return checksum == *(int *)(bytes + size);
}
}
