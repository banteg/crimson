extern "C" unsigned char credits_secret_match3_find(
    int board[][6], int *out_index, unsigned char *out_direction)
{
    for (int row = 0; row < 6; ++row) {
        for (int column = 0; column < 4; ++column) {
            int value = board[row][column];
            if (value >= 0) {
                int length = 1;
                if (board[row][column + 1] == value) {
                    length = 2;
                }
                if (board[row][column + 2] == value) {
                    ++length;
                }
                if (length == 3) {
                    *out_index = column + row * 6;
                    *out_direction = 1;
                    return 1;
                }
            }
        }
    }

    for (int column = 0; column < 6; ++column) {
        int row = 0;
        int *cell = &board[0][column];
        for (; row < 4; ++row, cell += 6) {
            int value = *cell;
            if (value >= 0) {
                int length = 1;
                if (cell[6] == value) {
                    length = 2;
                }
                if (cell[12] == value) {
                    ++length;
                }
                if (length == 3) {
                    *out_index = column + row * 6;
                    *out_direction = 0;
                    return 1;
                }
            }
        }
    }
    return 0;
}
