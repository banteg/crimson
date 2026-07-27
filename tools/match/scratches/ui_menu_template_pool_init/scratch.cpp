class ui_template_slot_cpp_t {
public:
    void construct(void);

    float x;
    float y;
    float z;
    float rhw;
    unsigned int color;
    float u;
    float v;
};

void ui_template_slot_cpp_t::construct(void)
{
}

class effect_vertex_cpp_t {
public:
    void construct(void);

    float x;
    float y;
    float z;
    float rhw;
    unsigned int color;
    float u;
    float v;
};

void effect_vertex_cpp_t::construct(void)
{
}

class ui_vec2_cpp_t {
public:
    void construct(void);

    float x;
    float y;
};

void ui_vec2_cpp_t::construct(void)
{
}

class ui_template_block_cpp_t {
public:
    ui_template_slot_cpp_t slots[8];
    int texture_handle;
    int mode;
};

typedef void (ui_template_slot_cpp_t::*slot_callback_t)(void);

extern "C" void __stdcall invoke_callback_n(
    ui_template_slot_cpp_t *cursor,
    int stride,
    int count,
    slot_callback_t callback);

extern "C" ui_template_block_cpp_t ui_template_pool_block_00;
extern "C" ui_template_block_cpp_t ui_template_pool_block_01;
extern "C" ui_template_block_cpp_t ui_template_pool_block_02;
extern "C" ui_template_block_cpp_t ui_sign_crimson_template;
extern "C" ui_template_block_cpp_t ui_menu_item_element;
extern "C" ui_template_block_cpp_t ui_menu_panel_template;
extern "C" ui_template_block_cpp_t ui_menu_item_subtemplate_block_01;
extern "C" ui_template_block_cpp_t ui_menu_item_subtemplate_block_02;
extern "C" ui_template_block_cpp_t ui_menu_item_subtemplate_block_03;
extern "C" ui_template_block_cpp_t ui_menu_item_subtemplate_block_04;
extern "C" ui_template_block_cpp_t ui_menu_item_subtemplate_block_05;
extern "C" ui_template_block_cpp_t ui_menu_item_subtemplate_block_06;

extern "C" void ui_menu_template_pool_init(void)
{
    ui_template_slot_cpp_t *cursor = ui_template_pool_block_00.slots;
    int remaining = 8;
    do {
        cursor->construct();
        ++cursor;
    } while (--remaining != 0);

    int mode = 4;
    cursor = ui_template_pool_block_01.slots;
    ui_template_pool_block_00.mode = mode;
    remaining = 8;
    do {
        cursor->construct();
        ++cursor;
    } while (--remaining != 0);

    ui_template_pool_block_01.mode = mode;
    cursor = ui_template_pool_block_02.slots;
    remaining = 8;
    do {
        cursor->construct();
        ++cursor;
    } while (--remaining != 0);

    ui_template_pool_block_02.mode = mode;
    cursor = ui_sign_crimson_template.slots;
    remaining = 8;
    do {
        cursor->construct();
        ++cursor;
    } while (--remaining != 0);

    ui_sign_crimson_template.mode = mode;
    cursor = ui_menu_item_element.slots;
    remaining = 8;
    do {
        cursor->construct();
        ++cursor;
    } while (--remaining != 0);

    ui_menu_item_element.mode = mode;
    cursor = ui_menu_panel_template.slots;
    remaining = 8;
    do {
        cursor->construct();
        ++cursor;
    } while (--remaining != 0);

    ui_menu_panel_template.mode = mode;
    invoke_callback_n(
        ui_menu_item_subtemplate_block_01.slots,
        sizeof(ui_template_slot_cpp_t),
        8,
        &ui_template_slot_cpp_t::construct);
    ui_menu_item_subtemplate_block_01.mode = mode;
    invoke_callback_n(
        ui_menu_item_subtemplate_block_02.slots,
        sizeof(ui_template_slot_cpp_t),
        8,
        &ui_template_slot_cpp_t::construct);
    ui_menu_item_subtemplate_block_02.mode = mode;
    invoke_callback_n(
        ui_menu_item_subtemplate_block_03.slots,
        sizeof(ui_template_slot_cpp_t),
        8,
        &ui_template_slot_cpp_t::construct);
    ui_menu_item_subtemplate_block_03.mode = mode;
    invoke_callback_n(
        ui_menu_item_subtemplate_block_04.slots,
        sizeof(ui_template_slot_cpp_t),
        8,
        &ui_template_slot_cpp_t::construct);
    ui_menu_item_subtemplate_block_04.mode = mode;
    invoke_callback_n(
        ui_menu_item_subtemplate_block_05.slots,
        sizeof(ui_template_slot_cpp_t),
        8,
        &ui_template_slot_cpp_t::construct);
    ui_menu_item_subtemplate_block_05.mode = mode;
    invoke_callback_n(
        ui_menu_item_subtemplate_block_06.slots,
        sizeof(ui_template_slot_cpp_t),
        8,
        &ui_template_slot_cpp_t::construct);
    ui_menu_item_subtemplate_block_06.mode = mode;
}
