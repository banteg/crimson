// The thermal camera's ironbow ramp, from cold indigo through magenta and orange to white: linear RGB.
vec3 ironbow(float t) {
    const vec3 stops[6] = vec3[6](
        vec3(.02, .01, .10), vec3(.22, .03, .50), vec3(.75, .05, .38),
        vec3(1., .33, .03), vec3(1., .80, .20), vec3(1., 1., .92));
    const float at[6] = float[6](0., .2, .42, .62, .82, 1.);
    t = clamp(t, 0., 1.);
    vec3 c = stops[0];
    for (int i = 1; i < 6; i++)
        c = mix(c, stops[i], clamp((t - at[i - 1]) / (at[i] - at[i - 1]), 0., 1.));
    return pow(c, vec3(2.2));
}
