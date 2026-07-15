extern "C" int crt_rand(void);

extern "C" char *typo_word_pick_fragment(
    unsigned char include_extended_pool)
{
    int word_count = 52;
    if (!include_extended_pool) {
        word_count = 51;
    }

    switch (crt_rand() % word_count) {
    case 0: return "lamb";
    case 1: return "gun";
    case 2: return "head";
    case 3: return "tail";
    case 4: return "leg";
    case 5: return "nose";
    case 6: return "road";
    case 7: return "stab";
    case 8: return "high";
    case 9: return "low";
    case 10: return "hat";
    case 11: return "pie";
    case 12: return "hand";
    case 13: return "jack";
    case 14: return "cube";
    case 15: return "ice";
    case 16: return "cow";
    case 17: return "king";
    case 18: return "lord";
    case 19: return "mate";
    case 20: return "mary";
    case 21: return "dick";
    case 22: return "bill";
    case 23: return "cat";
    case 24: return "harry";
    case 25: return "tom";
    case 26: return "fly";
    case 27: return "call";
    case 28: return "shot";
    case 29: return "gate";
    case 30: return "quick";
    case 31: return "brown";
    case 32: return "fox";
    case 33: return "jumper";
    case 34: return "over";
    case 35: return "lazy";
    case 36: return "dog";
    case 37: return "zeta";
    case 38: return "unique";
    case 40: return "earl";
    case 41: return "sleep";
    case 42: return "onyx";
    case 43: return "mill";
    case 44: return "blue";
    case 45: return "below";
    case 46: return "scape";
    case 47: return "reap";
    case 48: return "damo";
    case 49: return "break";
    case 50: return "boom";
    case 51: return "the";
    default: return "nerd";
    }
}
