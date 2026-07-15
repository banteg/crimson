struct bonus_hud_slot_slide_cpp_t {
    float slide_x;
    float field_0x08;
    float *timer_ptr;
    float *alt_timer_ptr;
    char *label;
    int icon_id;
    float field_0x1c;
};

class bonus_hud_slot_cpp_t {
public:
    bonus_hud_slot_cpp_t(void)
    {
        slide.field_0x1c = 5.0f;
        active = 0;
        slide.slide_x = 0.0f;
        slide.icon_id = 1;
        slide.label = "Empty";
        slide.field_0x08 = 1.0f;
    }

    unsigned char active;
    unsigned char padding[3];
    bonus_hud_slot_slide_cpp_t slide;
};

bonus_hud_slot_cpp_t bonus_hud_slot_table[0x10];
