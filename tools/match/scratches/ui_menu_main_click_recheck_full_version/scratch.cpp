extern "C" unsigned char full_version_recheck_pending;

extern "C" void ui_menu_main_click_recheck_full_version(void)
{
    full_version_recheck_pending = 1;
}
