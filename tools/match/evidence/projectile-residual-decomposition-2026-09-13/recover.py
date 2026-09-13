"""Recover independently identified particle residuals from the pinned source.

These are diagnostic candidates. No matcher rule or canonical source is changed.
"""

BEFORE_SHA = "90b9bb4a39f0efd852395367bd11f71113b8812b15144301b4914f18423ac730"
BODY_SHA = "223f9383676027b5b70b48ecdca73e7470ba66ac061333fab04f16f77c95c871"
STEPS = (
    "expiry-branches",
    "expiry-reload",
    "expiry-sound",
    "geometry",
    "hit-position",
    "clamp",
    "bubble-copy",
    "age",
    "angle-branches",
    "displacement",
    "rng-value",
)


def edit(source, old, new):
    assert source.count(old) == 1, old
    return source.replace(old, new)


def recover(source, steps=STEPS):
    for step in steps:
        if step == "expiry-branches":
            source = edit(
                source,
                """            if ((style_id != 0 && particle->intensity <= 0.8f)
                || (style_id == 0 && particle->intensity <= 0.0f)) {
                particle->active = 0;""",
                """            if (style_id == 0 && particle->intensity <= 0.0f) {
                particle->active = 0;
            } else if (style_id != 0 && particle->intensity <= 0.8f) {
                particle->active = 0;""",
            )
        elif step == "expiry-reload":
            marker = "            if (style_id == 0 && particle->intensity <= 0.0f) {"
            source = edit(source, marker, "            style_id = particle->style_id;\n" + marker)
        elif step == "expiry-sound":
            start = source.index("                    int target_id = particle->target_id;")
            end = source.index("                    creature_handle_death(particle->target_id, 0);", start)
            source = (
                source[:start]
                + """                    if (creature_pool[particle->target_id].active) {
                        sfx_play_panned(
                            creature_type_table[
                                creature_pool[particle->target_id].type_id]
                                .sfx_bank_a[crt_rand() % 3],
                            &creature_pool[particle->target_id].position,
                            1.0f);
                    }
"""
                + source[end:]
            )
        elif step == "geometry":
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
        elif step == "hit-position":
            source = edit(
                source,
                """                            projectile_vec2_t hit_direction = previous_position
                                - *(projectile_vec2_t *)&creature_pool[hit_id].position;""",
                """                            projectile_vec2_t &hit_position =
                                *(projectile_vec2_t *)&creature_pool[hit_id].position;
                            projectile_vec2_t hit_direction = previous_position - hit_position;""",
            )
            start = source.index("                            projectile_vec2_t &hit_position =")
            tail = source[start:].replace("&hit_creature->position", "(vec2f_t *)&hit_position")
            tail = tail.replace("hit_creature->position.x", "hit_position.x")
            tail = tail.replace("hit_creature->position.y", "hit_position.y")
            source = source[:start] + tail
        elif step == "clamp":
            start = source.index("static __inline float projectile_clamp_tint")
            end = source.index('extern "C" void projectile_update', start)
            source = (
                source[:start]
                + """static __inline void projectile_clamp_tint(float *value)
{
    if (*value < 0.0f) {
        *value = 0.0f;
    } else if (*value > 1.0f) {
        *value = 1.0f;
    }
}

"""
                + source[end:]
            )
            for channel in "rgba":
                source = edit(
                    source,
                    f"""                                hit_creature->tint_{channel} =
                                    projectile_clamp_tint(hit_creature->tint_{channel});""",
                    f"                                projectile_clamp_tint(&hit_creature->tint_{channel});",
                )
        elif step == "bubble-copy":
            source = edit(
                source,
                """                            particle->position.x = creature_pool[hit_id].position.x;
                            particle->position.y = creature_pool[hit_id].position.y;""",
                """                            particle_position =
                                *(projectile_vec2_t *)&creature_pool[hit_id].position;""",
            )
        elif step == "age":
            source = edit(
                source,
                """                if (particle->intensity <= 1.0f) {
                    particle->age = particle->intensity;
                } else {
                    particle->age = 1.0f;
                }""",
                """                particle->age = particle->intensity > 1.0f
                    ? 1.0f : particle->intensity;""",
            )
        elif step == "angle-branches":
            for value in ("particle->angle", "hit_angle"):
                source = edit(source, f"while (6.2831855f < {value})", f"while ({value} > 6.2831855f)")
            source = edit(
                source,
                """                            if (particle->angle <= hit_angle) {
                                particle->angle += 1.2566371f;
                            } else {
                                particle->angle -= 1.2566371f;
                            }""",
                """                            if (hit_angle < particle->angle) {
                                particle->angle -= 1.2566371f;
                            } else {
                                particle->angle += 1.2566371f;
                            }""",
            )
        elif step == "displacement":
            source = edit(
                source,
                """                            vec2f_t creature_displacement = {
                                frame_dt * particle->velocity.x,
                                frame_dt * particle->velocity.y,
                            };
                            hit_position.x += creature_displacement.x;
                            hit_position.y += creature_displacement.y;""",
                """                            projectile_vec2_t reflected_velocity(
                                particle->velocity.x, particle->velocity.y);
                            float displacement_dt = frame_dt;
                            projectile_vec2_t creature_displacement =
                                reflected_velocity * displacement_dt;
                            hit_position += creature_displacement;""",
            )
        elif step == "rng-value":
            new = """                                int velocity_x = crt_rand() % 60 - 30;
                                projectile_vec2_t velocity(
                                    (float)velocity_x,
                                    (float)(crt_rand() % 60 - 30));"""
            source = edit(
                source,
                """                                vec2f_t velocity = {
                                    (float)(crt_rand() % 60 - 30),
                                    (float)(crt_rand() % 60 - 30),
                                };""",
                new,
            )
            start = source.index(new)
            end = source.index("sprite_effect_pool[effect_id].color_a = 0.7f;", start)
            source = source[:start] + source[start:end].replace("&velocity,", "(vec2f_t *)&velocity,") + source[end:]
        else:
            raise ValueError(step)
    return source
