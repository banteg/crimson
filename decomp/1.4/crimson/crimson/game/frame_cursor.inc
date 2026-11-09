// Menu and score-entry cursor draws use the two clock samples from their calling state.
{
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION < 10300
    float x = MOUSE_X - 32, y = MOUSE_Y - 32;
#endif
#ifndef CRIMSON_FREEWARE_CLIENT
    grim_interface_ptr->grim_set_config_var(frame_src_blend, 5u);
    grim_interface_ptr->grim_set_config_var(frame_dst_blend, 2u);
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("part"));
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_begin_batch();
#if FREEWARE_EDITION >= 10300
    grim_interface_ptr->grim_draw_quad(MOUSE_X - 32.f, MOUSE_Y - 32.f, 64, 64);
#else
    grim_interface_ptr->grim_draw_quad(x, y, 64, 64);
#endif
#else
    G.ui.destination_blend = 2;
    const float rotation = G.frame_sprites.empty() ? 0 : G.frame_sprites.back().angle;
    sprite("part", x, y, 64, 64, rotation, 1, 1, 1, 1);
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
    alpha = ((float)pow((float)cos(pulse), 2) + 1.f) * .5f;
#else
    float alpha = (float)((pow(cos(pulse), 2) + 1) * .5);
#endif
    for (index = 0; index < 6; index += 2) {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
        grim_interface_ptr->grim_set_color(1, 1, 1, alpha);
        float angle = orbit + index * 1.0471976f;
        grim_interface_ptr->grim_draw_quad(MOUSE_X - 32.f + (float)cos(angle) * 16.f,
                                           MOUSE_Y - 32.f + (float)sin(angle) * 16.f, 64, 64);
#else
        double angle = orbit + (double)index * 1.0471976f;
        float px = (float)(x + cos(angle) * 16), py = (float)(y + sin(angle) * 16);
#ifdef CRIMSON_FREEWARE_CLIENT
        sprite("part", px, py, 64, 64, rotation, 1, 1, 1, alpha);
#else
        grim_interface_ptr->grim_set_color(1, 1, 1, alpha);
        grim_interface_ptr->grim_draw_quad(px, py, 64, 64);
#endif
#endif
    }
#ifndef CRIMSON_FREEWARE_CLIENT
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(frame_src_blend, 5u);
    grim_interface_ptr->grim_set_config_var(frame_dst_blend, 6u);
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("aim32"));
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(1, 1, 1, .64f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(MOUSE_X - 16, MOUSE_Y - 16, 32, 32);
    grim_interface_ptr->grim_end_batch();
#else
    G.ui.destination_blend = 6;
    sprite("aim32", MOUSE_X - 16, MOUSE_Y - 16, 32, 32, rotation, 1, 1, 1, .64f);
#endif
}
