void quest_database_advance_slot(int *tier, int *index)
{
    *index += 1;
    if (*index >= 10) {
        *tier += 1;
        *index = 0;
    }
}
