"""Recover particle bounce scaling and the creature displacement temporary."""


def replace_once(source, old, new):
    assert source.count(old) == 1, old
    return source.replace(old, new)


def recover(source, *, displacement=True, sdk_geometry=False):
    source = replace_once(
        source,
        """                            int speed_scale = crt_rand() % 10;
                            particle->velocity.x *= (float)speed_scale * 0.1f;
                            particle->velocity.y *= (float)speed_scale * 0.1f;""",
        """                            float speed_scale = (float)(crt_rand() % 10) * 0.1f;
                            particle->velocity.x *= speed_scale;
                            particle->velocity.y *= speed_scale;""",
    )
    if displacement:
        source = replace_once(
            source,
            """                            hit_creature->position.x +=
                                frame_dt * particle->velocity.x;
                            hit_creature->position.y +=
                                frame_dt * particle->velocity.y;""",
            """                            vec2f_t creature_displacement = {
                                frame_dt * particle->velocity.x,
                                frame_dt * particle->velocity.y,
                            };
                            hit_creature->position.x += creature_displacement.x;
                            hit_creature->position.y += creature_displacement.y;""",
        )
    if sdk_geometry:
        start = source.index("                            vec2f_t displacement = {")
        end = source.index("                            while (6.2831855f < hit_angle)", start)
        source = (
            source[:start]
            + """                            projectile_vec2_t displacement = frame_dt * particle_velocity;
                            projectile_vec2_t previous_position = particle_position - displacement;
                            projectile_vec2_t hit_direction = previous_position
                                - *(projectile_vec2_t *)&creature_pool[hit_id].position;
                            float hit_angle = projectile_vec2_angle(hit_direction);
"""
            + source[end:]
        )
    return source
