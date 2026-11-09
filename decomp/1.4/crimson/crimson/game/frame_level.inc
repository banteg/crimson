// Level Test (mode 3) and editor (mode 4) helpers for the freeware frame callback.
#ifndef CRIMSON_FREEWARE_CLIENT
extern "C" {
extern int freeware_editor_brush, freeware_editor_layer;
extern float freeware_editor_rotation, freeware_editor_light, freeware_editor_alpha, freeware_editor_radius;
void terrain_generate(unsigned char), level_load_next();
unsigned char creatures_none_active();
}
#endif
__forceinline bool editor_key(int code, bool pressed) {
#ifdef CRIMSON_FREEWARE_CLIENT
    return pressed ? INPUT.level_pressed.test(code) : INPUT.level_down.test(code);
#else
    return pressed ? grim_interface_ptr->grim_was_key_pressed(code)
                   : grim_interface_ptr->grim_is_key_down((unsigned char)code);
#endif
}
__forceinline void rebuild_terrain() {
#ifdef CRIMSON_FREEWARE_CLIENT
    G.generate_terrain(!freeware_current_map->flag);
#else
    terrain_generate(!freeware_current_map->flag);
#endif
}
struct editor_tint : effect_color_t {
    editor_tint(float red, float green, float blue, float opacity) {
        r = red;
        g = green;
        b = blue;
        a = opacity;
    }
};
struct editor_point : vec2f_t {
    editor_point(float px, float py) {
        x = px;
        y = py;
    }
};
#ifndef CRIMSON_FREEWARE_CLIENT
struct editor_offset_t : vec2f_t {
    editor_offset_t() {
        x = 0;
        y = 0;
    }
    // VC6 registers the editor's static offset for destruction on its first use.
    ~editor_offset_t() {}
};
struct editor_trigger : freeware_level_trigger {
    __forceinline editor_trigger(int kind, const vec2f_t &at, float angle, float r) {
        enabled = 0;
        type = kind;
        position = at;
        heading = angle;
        velocity = editor_point(0, 0);
        radius = r;
    }
};
#endif

__forceinline unsigned editor_brush_count() {
#ifdef CRIMSON_FREEWARE_CLIENT
    return (unsigned)G.brushes.size();
#else
    return freeware_brushes.size();
#endif
}
__forceinline const freeware_level_object &editor_brush(int index) {
#ifdef CRIMSON_FREEWARE_CLIENT
    return G.brushes[index].object;
#else
    return *freeware_brushes[index];
#endif
}
__forceinline unsigned char editor_click(int button) {
#ifdef CRIMSON_FREEWARE_CLIENT
    return button == 0 ? INPUT.click : INPUT.perk_button;
#else
    return grim_interface_ptr->grim_was_mouse_button_pressed(button);
#endif
}
__forceinline freeware_level_trigger *editor_make_trigger(int kind, const float &angle, const float &radius) {
#ifdef CRIMSON_FREEWARE_CLIENT
    freeware_level_trigger *trigger = new freeware_level_trigger();
    trigger->type = kind;
    trigger->position = editor_point(MOUSE_X - CAM.x, MOUSE_Y - CAM.y);
    trigger->heading = angle;
    trigger->radius = radius;
    return trigger;
#else
    return new editor_trigger(kind, editor_point(MOUSE_X - CAM.x, MOUSE_Y - CAM.y), angle, radius);
#endif
}
__forceinline bool level_cleared() {
#ifdef CRIMSON_FREEWARE_CLIENT
    for (int i = 0; i < 512; ++i)
        if (creature_pool[i].active)
            return false;
    return true;
#else
    return creatures_none_active() != 0;
#endif
}
