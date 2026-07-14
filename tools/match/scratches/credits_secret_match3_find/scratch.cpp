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
        for (int row = 0; row < 4; ++row) {
            int value = board[row][column];
            if (value >= 0) {
                int length = 1;
                if (board[row + 1][column] == value) {
                    length = 2;
                }
                if (board[row + 2][column] == value) {
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
