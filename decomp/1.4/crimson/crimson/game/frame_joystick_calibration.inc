// The two freeware menus poll one joystick when calibrating its center, threshold and hat.
grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
if (freeware_setup_step == 0) {
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    calibration_prompt("Center the " CALIBRATION_JOYSTICK " and press enter or a " CALIBRATION_JOYSTICK " button");
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    sprintf(freeware_ui_buffer, "X-Axis: %d\nY-Axis: %d", grim_interface_ptr->grim_get_joystick_x(),
            grim_interface_ptr->grim_get_joystick_y());
    grim_interface_ptr->grim_draw_text_mono(40, 250, freeware_ui_buffer);
    if ((FREEWARE_EDITION == 10300 || !console_open_flag) &&
        (menu_key(0x1c) || grim_interface_ptr->grim_is_joystick_button_down(0) ||
         grim_interface_ptr->grim_is_joystick_button_down(1) || grim_interface_ptr->grim_is_joystick_button_down(2) ||
         grim_interface_ptr->grim_is_joystick_button_down(3) || grim_interface_ptr->grim_is_joystick_button_down(4))) {
        freeware_pad_center_x = grim_interface_ptr->grim_get_joystick_x();
        freeware_pad_center_y = grim_interface_ptr->grim_get_joystick_y();
        ++freeware_setup_step;
    }
} else if (freeware_setup_step == 1) {
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    calibration_prompt("Set the " CALIBRATION_JOYSTICK
                       " X/Y-Axis threshold with arrow keys up/down, press enter when done.");
    if (FREEWARE_EDITION == 10300 || !console_open_flag) {
        if (menu_key(0xc8))
            freeware_pad_threshold += 10;
        if (menu_key(0xd0))
            freeware_pad_threshold -= 10;
        if (menu_key(0x1c))
            ++freeware_setup_step;
    }
    if (freeware_pad_threshold < 0)
        freeware_pad_threshold = 0;
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    sprintf(freeware_ui_buffer, "X/Y-Axis threshold: %d", freeware_pad_threshold);
    grim_interface_ptr->grim_draw_text_mono(40, 250, freeware_ui_buffer);
    sprintf(freeware_ui_buffer, "Status:\n\nUp: %d\nDown: %d\nLeft: %d\nRight: %d", input_move_up_active(),
            input_move_down_active(), input_move_left_active(), input_move_right_active());
    grim_interface_ptr->grim_draw_text_mono(40, 300, freeware_ui_buffer);
} else if (freeware_setup_step == 2) {
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    calibration_prompt("If your " CALIBRATION_JOYSTICK
                       " has 'hat' press it LEFT now and press enter. (press enter to skip this)");
    calibrate_pov(freeware_pov_left);
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    draw_pov_status();
} else if (freeware_setup_step == 3) {
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    calibration_prompt("If your " CALIBRATION_JOYSTICK
                       " has 'hat' press it RIGHT now and press enter. (press enter to skip this)");
    calibrate_pov(freeware_pov_right);
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    draw_pov_status();
} else if (freeware_setup_step >= 4) {
    freeware_setup_step = 0;
    freeware_calibrating = 0;
    freeware_save_config();
    config_load_presets();
}
