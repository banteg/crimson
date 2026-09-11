"""Reconstruct the SDK particle vector boundaries and angle field owner."""

a = """                        float move_x = frame_dt * particle->velocity.x;
                        vec2f_t movement = {
                            move_x * particle->intensity,
                            frame_dt * particle->velocity.y
                                * particle->intensity,
                        };
                        vec2_add(
                            &particle->position,
                            &movement,
                            3.0f);"""
aa = """                        projectile_vec2_t movement =
                            frame_dt * particle_velocity * particle->intensity;
                        vec2_add(
                            &particle->position,
                            (vec2f_t *)&movement,
                            3.0f);"""
b = """                    float move_x = frame_dt * particle->velocity.x;
                    particle->position.x += move_x * 2.5f * 0.15f;
                    particle->position.y += frame_dt * particle->velocity.y
                        * 2.5f * 0.15f;"""
bb = """                    particle_position +=
                        frame_dt * particle_velocity * 2.5f * 0.15f;"""
d = """                    float move_x = frame_dt * particle->velocity.x;
                    vec2f_t movement = {
                        move_x * 2.5f * particle->intensity,
                        frame_dt * particle->velocity.y * 2.5f
                            * particle->intensity,
                    };
                    vec2_add(
                        &particle->position,
                        &movement,
                        3.0f);"""
dd = """                    projectile_vec2_t movement =
                        frame_dt * particle_velocity * 2.5f * particle->intensity;
                    vec2_add(
                        &particle->position,
                        (vec2f_t *)&movement,
                        3.0f);"""


def recover(source, mask=7, angle_owner=True, velocity_owner=False):
    for bit, (old, new) in enumerate(((a, aa), (b, bb), (d, dd))):
        assert source.count(old) == 1
        if mask & (1 << bit):
            source = source.replace(old, new)
    if angle_owner:
        old = "            unsigned char style_id = particle->style_id;"
        assert source.count(old) == 1
        source = source.replace(old, "            float &angle = particle->angle;\n" + old)
        start = source.index("                if (particle->render_flag == 1) {")
        end = source.index("                if (particle->intensity <= 1.0f)", start)
        source = source[:start] + source[start:end].replace("particle->angle", "angle") + source[end:]
    if velocity_owner:
        assert not angle_owner
        source = source.replace(
            "particle->velocity.x =\n                            (float)cos(particle->angle)",
            "particle_velocity.x =\n                            (float)cos(particle->angle)",
        )
        source = source.replace(
            "particle->velocity.y =\n                            (float)sin(particle->angle)",
            "particle_velocity.y =\n                            (float)sin(particle->angle)",
        )
    return source
