extern int config_detail_preset;
extern unsigned char config_fx_detail_flag0;
extern unsigned char config_fx_detail_flag1;
extern unsigned char config_fx_detail_flag2;

void config_apply_detail_preset(void)
{
    switch (config_detail_preset) {
    case 1:
        config_fx_detail_flag2 = 0;
    case 2:
        config_fx_detail_flag0 = 0;
        config_fx_detail_flag1 = 0;
        break;
    case 3:
    case 4:
    case 5:
        config_fx_detail_flag1 = 1;
        config_fx_detail_flag2 = 1;
        config_fx_detail_flag0 = 1;
        break;
    }
}
