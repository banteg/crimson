extern "C" char *input_configure_for_label(int config_id)
{
    switch (config_id) {
    case 0:
        return "Mouse";
    case 3:
        return "Mouse relative";
    case 1:
        return "Keyboard";
    case 2:
        return "Joystick";
    case 4:
        return "Dual Action Pad";
    case 5:
        return "Computer";
    default:
        return "Unknown";
    }
}
