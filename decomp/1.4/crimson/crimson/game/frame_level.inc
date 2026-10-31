// Level Test (mode 3) and the level editor (mode 4) in the 1.4.0 image.
// The shipping menu only cycles through modes 1 and 2.
#ifndef CRIMSON_FREEWARE_CLIENT
extern "C" {
extern int freeware_editor_brush, freeware_editor_layer;
extern float freeware_editor_rotation, freeware_editor_light, freeware_editor_alpha, freeware_editor_radius;
extern vec2f_t freeware_editor_offset;
extern freeware_level_object **freeware_brush_begin, **freeware_brush_end;
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
struct editor_object : freeware_level_object {
    editor_object(float w, float h) {
        position.x = position.y = rotation = 0;
        width = w;
        height = h;
        flags = 0;
        color.r = color.g = color.b = color.a = 1;
#ifdef CRIMSON_FREEWARE_CLIENT
        texture = 0;
#else
        texture = grim_interface_ptr->grim_get_texture_handle("0");
#endif
    }
};
__forceinline void editor() {
    int &index = FIELD(freeware_editor_brush, editor_brush), &layer = FIELD(freeware_editor_layer, editor_layer);
    float &rotation = FIELD(freeware_editor_rotation, editor_rotation),
          &light = FIELD(freeware_editor_light, editor_light), &alpha = FIELD(freeware_editor_alpha, editor_alpha),
          &radius = FIELD(freeware_editor_radius, editor_radius);
    vec2f_t &offset = FIELD(freeware_editor_offset, editor_offset);
    freeware_level_map *map = freeware_current_map;
    if (editor_key(0x4a, true))
        --index;
    if (editor_key(0x4e, true))
        ++index;
    if (editor_key(0xc9, false))
        rotation -= frame_dt;
    if (editor_key(0xd1, false))
        rotation += frame_dt;
    if (editor_key(0xc7, false))
        rotation = 0;
    if (editor_key(0xcf, false))
        rotation = (crt_rand() % 628) * .01f;
    bool shift = editor_key(0x2a, false);
    float &channel = shift ? alpha : light;
    if (editor_key(0xd2, false))
        channel -= frame_dt;
    if (editor_key(0xd3, false))
        channel += frame_dt;
    light = saturate(light);
    alpha = saturate(alpha);
    float stride = shift ? 32.f : 1.f;
    if (editor_key(0xcb, true))
        offset.x -= stride;
    if (editor_key(0xcd, true))
        offset.x += stride;
    if (editor_key(0xc8, true))
        offset.y -= stride;
    if (editor_key(0xd0, true))
        offset.y += stride;
#ifdef CRIMSON_FREEWARE_CLIENT
    int count = (int)G.brushes.size();
#else
    int count = freeware_brush_begin ? (int)(freeware_brush_end - freeware_brush_begin) : 0;
#endif
    if (index < 0)
        index = 0;
    if (index >= count)
        index = count - 1;
    if (editor_key(2, true))
        layer = 0;
    if (editor_key(3, true))
        layer = 1;
    if (editor_key(4, true))
        layer = 2;
    if (editor_key(0x1f, true))
        map->save("levels\\level_5.lvl");
    if (editor_key(0x26, true)) {
        map->load("levels\\level_5.lvl");
        rebuild_terrain();
    }
    if (editor_key(0x13, true)) {
        map->clear();
        rebuild_terrain();
    }
    vec2f_t world = {MOUSE_X - CAM.x, MOUSE_Y - CAM.y};
    if (editor_key(0x2e, true)) {
        map->start = world;
        map->start_heading = 0;
    }
    if (editor_key(0x11, true)) {
        freeware_level_trigger *t = new freeware_level_trigger();
        t->type = 2;
        t->enabled = 0;
        t->position = world;
        t->heading = 0;
        t->velocity.x = t->velocity.y = 0;
        t->radius = 20;
        t->weapon = 2;
        map->add_trigger(t);
    }
    // With no brush catalog there is no selected texture to preview or stamp.
    if (index < 0)
        return;
#ifdef CRIMSON_FREEWARE_CLIENT
    const freeware_level_object &brush = G.brushes[index].object;
    bool place = INPUT.click, place_trigger = INPUT.perk_button;
#else
    const freeware_level_object &brush = *freeware_brush_begin[index];
    bool place = grim_interface_ptr->grim_was_mouse_button_pressed(0);
    bool place_trigger = grim_interface_ptr->grim_was_mouse_button_pressed(1);
#endif
    map->texture = brush.texture;
    current_player_index = 0;
    map->render_layer(1, 0);
    map->render_triggers(0);
    map->render_layer(2, 0);
    if (place || editor_key(0x39, true)) {
#ifdef CRIMSON_FREEWARE_CLIENT
        freeware_level_object *object = new freeware_level_object();
        object->width = brush.width;
        object->height = brush.height;
#else
        freeware_level_object *object = new editor_object(brush.width, brush.height);
#endif
        object->texture = brush.texture;
        object->rotation = rotation;
        object->position.x = (float)(int)(world.x + offset.x);
        object->position.y = (float)(int)(world.y + offset.y);
        object->flags = editor_key(0x13, false) ? 2 : 0;
        if (editor_key(0x2f, false)) {
            object->flags |= 1;
            object->color.r = .9f;
            object->color.g = object->color.b = .1f;
            object->color.a = 1;
        } else {
            object->color.r = object->color.g = object->color.b = light;
            object->color.a = alpha;
        }
        map->add_object(layer, object);
        rebuild_terrain();
    }
    if (editor_key(0x1e, false))
        radius += frame_dt * 10;
    if (editor_key(0x2c, false))
        radius -= frame_dt * 10;
    if (editor_key(0x14, true))
        map->flag = !map->flag;
    if (editor_key(0x1f, false))
        sprite("radius", CAM.x + MOUSE_X - radius, CAM.y + MOUSE_Y - radius, radius * 2, radius * 2, 0, 1, 1, 1,
               .6f);
    if (place_trigger) {
        freeware_level_trigger *t = new freeware_level_trigger();
        t->type = 0;
        t->enabled = 0;
        t->position.x = MOUSE_X - CAM.x;
        t->position.y = MOUSE_Y - CAM.y;
        t->heading = rotation;
        t->velocity.x = t->velocity.y = 0;
        t->radius = radius;
        map->add_trigger(t);
    }
    bool black = editor_key(0x30, false);
#ifdef CRIMSON_FREEWARE_CLIENT
    sprite(G.brushes[index].name.c_str(), offset.x + MOUSE_X, offset.y + MOUSE_Y, brush.width, brush.height,
           rotation, black ? 0 : light, black ? 0 : light, black ? 0 : light, black ? 1 : alpha);
#else
    grim_interface_ptr->grim_bind_texture(map->texture, 0);
    grim_interface_ptr->grim_set_rotation(rotation);
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(black ? 0 : light, black ? 0 : light, black ? 0 : light, black ? 1 : alpha);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(offset.x + MOUSE_X, offset.y + MOUSE_Y, brush.width, brush.height);
    grim_interface_ptr->grim_end_batch();
#endif
    sprite("aim32", MOUSE_X - 16, MOUSE_Y - 16, 32, 32, 0, 1, 1, 1, 1);
    char buf[96];
    sprintf(buf, "Layer: %d\nLightness: %d\nAlpha: %d\nBlackback: %d", layer, (int)(light * 100),
            (int)(alpha * 100), map->flag);
    label(buf, 10, 10, 1, 1, 1, 1, 1);
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
