extern int config_detail_preset;
extern unsigned char config_shadows_enabled;
extern unsigned char config_flame_glow_enabled;
extern unsigned char config_smoke_enabled;

void config_apply_detail_preset(void)
{
    switch (config_detail_preset) {
    case 1:
        config_smoke_enabled = 0;
    case 2:
        config_shadows_enabled = 0;
        config_flame_glow_enabled = 0;
        break;
    case 3:
    case 4:
    case 5:
        config_flame_glow_enabled = 1;
        config_smoke_enabled = 1;
        config_shadows_enabled = 1;
        break;
    }
}
