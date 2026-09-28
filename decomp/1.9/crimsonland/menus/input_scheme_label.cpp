extern "C" char *input_scheme_label(int scheme)
{
    switch (scheme) {
    case 1:
        return "Relative";
    case 2:
        return "Static";
    case 3:
        return "Dual Action Pad";
    case 4:
        return "Mouse point&click";
    case 5:
        return "Computer";
    default:
        return "Unknown";
    }
}
