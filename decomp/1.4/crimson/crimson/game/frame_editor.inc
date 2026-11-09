// The 1.3.0 and 1.4.0 level editor runs inside the frame callback.
int &index = FIELD(freeware_editor_brush, editor_brush), &layer = FIELD(freeware_editor_layer, editor_layer);
float &rotation = FIELD(freeware_editor_rotation, editor_rotation),
      &light = FIELD(freeware_editor_light, editor_light), &alpha = FIELD(freeware_editor_alpha, editor_alpha),
      &radius = FIELD(freeware_editor_radius, editor_radius);
#ifdef CRIMSON_FREEWARE_CLIENT
vec2f_t &offset = G.editor_offset;
#else
static editor_point offset(0, 0);
#endif
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
if (!editor_key(0x2a, false)) {
    if (editor_key(0xd2, false))
        light -= frame_dt;
    if (editor_key(0xd3, false))
        light += frame_dt;
} else {
    if (editor_key(0xd2, false))
        alpha -= frame_dt;
    if (editor_key(0xd3, false))
        alpha += frame_dt;
}
if (light < 0)
    light = 0;
else if (light > 1)
    light = 1;
if (alpha < 0)
    alpha = 0;
else if (alpha > 1)
    alpha = 1;
float stride = 1;
if (editor_key(0x2a, false))
    stride = 32;
if (editor_key(0xcb, true))
    offset.x -= stride;
if (editor_key(0xcd, true))
    offset.x += stride;
if (editor_key(0xc8, true))
    offset.y -= stride;
if (editor_key(0xd0, true))
    offset.y += stride;
if (index < 0)
    index = 0;
if ((unsigned)index >= editor_brush_count())
    index = editor_brush_count() - 1;
if (editor_key(2, true))
    layer = 0;
if (editor_key(3, true))
    layer = 1;
if (editor_key(4, true))
    layer = 2;
if (editor_key(0x1f, true))
    freeware_current_map->save("levels\\level_5.lvl");
if (editor_key(0x26, true)) {
    freeware_current_map->load("levels\\level_5.lvl");
    rebuild_terrain();
}
if (editor_key(0x13, true)) {
    freeware_current_map->clear();
    rebuild_terrain();
}
if (editor_key(0x2e, true)) {
    freeware_current_map->start = editor_point(MOUSE_X - CAM.x, MOUSE_Y - CAM.y);
    freeware_current_map->start_heading = 0;
}
if (editor_key(0x11, true)) {
    freeware_level_trigger *trigger = editor_make_trigger(2, 0, 20);
    trigger->weapon = 2;
    freeware_current_map->add_trigger(trigger);
}
#ifdef CRIMSON_FREEWARE_CLIENT
// An empty brush catalog can occur in the portable client's editor.
if (index >= 0)
#endif
{
#ifdef CRIMSON_FREEWARE_CLIENT
    freeware_current_map->texture = editor_brush(index).texture;
#else
    freeware_current_map->set_texture(freeware_brushes[index]->texture);
#endif
    current_player_index = 0;
    freeware_current_map->render_layer(1, 0);
    freeware_current_map->render_triggers(0);
#ifdef CRIMSON_FREEWARE_CLIENT
    G.ui.source_blend = 5;
    G.ui.destination_blend = 6;
#else
    grim_interface_ptr->grim_set_config_var(frame_src_blend, 5u);
    grim_interface_ptr->grim_set_config_var(frame_dst_blend, 6u);
#endif
    freeware_current_map->render_layer(2, 0);
    if (editor_click(0) || editor_key(0x39, true)) {
#ifdef CRIMSON_FREEWARE_CLIENT
        freeware_level_object *object = new freeware_level_object();
        object->width = editor_brush(index).width;
        object->height = editor_brush(index).height;
#elif FREEWARE_EDITION == 10300
        freeware_level_object *object =
            new ::freeware_editor_brush("0", freeware_brushes[index]->width, freeware_brushes[index]->height);
#else
        freeware_level_object *object =
            new ::freeware_editor_brush("0", editor_brush(index).width, editor_brush(index).height);
#endif
        object->texture = editor_brush(index).texture;
        object->rotation = rotation;
        const editor_point &ground = editor_point(MOUSE_X - CAM.x, MOUSE_Y - CAM.y);
        object->position = editor_point(ground.x + offset.x, ground.y + offset.y);
        object->position.x = (float)(int)object->position.x;
        object->position.y = (float)(int)object->position.y;
        if (editor_key(0x13, false))
            object->flags |= 2;
        if (editor_key(0x2f, false)) {
            object->color = editor_tint(.9f, .1f, .1f, 1);
            object->flags |= 1;
        } else {
            object->color = editor_tint(light, light, light, alpha);
        }
        freeware_current_map->add_object(layer, object);
        rebuild_terrain();
    }
    if (editor_key(0x1e, false))
        radius += frame_dt * 10;
    if (editor_key(0x2c, false))
        radius -= frame_dt * 10;
    if (editor_key(0x14, true))
        freeware_current_map->flag = !freeware_current_map->flag;
    if (editor_key(0x1f, false)) {
#ifdef CRIMSON_FREEWARE_CLIENT
        sprite("radius", CAM.x + MOUSE_X - radius, CAM.y + MOUSE_Y - radius, radius * 2, radius * 2, 0, 1, 1, 1, .6f);
#else
        grim_interface_ptr->grim_set_color(1, 1, 1, .6f);
        frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("radius"));
        grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
        grim_interface_ptr->grim_set_rotation(0);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(CAM.x + MOUSE_X - radius, CAM.y + MOUSE_Y - radius, radius * 2, radius * 2);
        grim_interface_ptr->grim_end_batch();
#endif
    }
    if (editor_click(1)) {
        freeware_current_map->add_trigger(editor_make_trigger(0, rotation, radius));
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    bool black = editor_key(0x30, false);
    sprite(G.brushes[index].name.c_str(), offset.x + MOUSE_X, offset.y + MOUSE_Y, editor_brush(index).width,
           editor_brush(index).height, rotation, black ? 0 : light, black ? 0 : light, black ? 0 : light, black ? 1 : alpha);
    sprite("aim32", MOUSE_X - 16, MOUSE_Y - 16, 32, 32, 0, 1, 1, 1, 1);
    char text[96];
#else
    frame_bind_texture(freeware_current_map->texture);
    grim_interface_ptr->grim_set_rotation(rotation);
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    if (editor_key(0x30, false))
        grim_interface_ptr->grim_set_color(0, 0, 0, 1);
    else
        grim_interface_ptr->grim_set_color(light, light, light, alpha);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(offset.x + MOUSE_X, offset.y + MOUSE_Y,
                                       editor_brush(index).width, editor_brush(index).height);
    grim_interface_ptr->grim_end_batch();
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("aim32"));
    grim_interface_ptr->grim_set_rotation(0);
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(MOUSE_X - 16, MOUSE_Y - 16, 32, 32);
    grim_interface_ptr->grim_end_batch();
    char *text = freeware_ui_buffer;
#endif
    sprintf(text, "Layer: %d\nLightness: %d\nAlpha: %d\nBlackback: %d", layer, (int)(light * 100),
            (int)(alpha * 100), freeware_current_map->flag);
#ifdef CRIMSON_FREEWARE_CLIENT
    G.frame_labels.push_back({text, 10, 10, G.ui.scale, {1, 1, 1, 1}, G.frame_sprites.size()});
#else
    grim_interface_ptr->grim_draw_text_mono(10, 10, text);
#endif
}
