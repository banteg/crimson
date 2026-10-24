// The thermal camera's ironbow ramp, from cold indigo through magenta and orange to white: linear RGB.
// Piecewise linear between its stops; spelled without arrays so WGSL needs no runtime-indexed array.
vec3 ironbow(float t) {
    t = clamp(t, 0., 1.);
    vec3 c = mix(vec3(.02, .01, .10), vec3(.22, .03, .50), clamp(t / .2, 0., 1.));
    c = mix(c, vec3(.75, .05, .38), clamp((t - .2) / .22, 0., 1.));
    c = mix(c, vec3(1., .33, .03), clamp((t - .42) / .2, 0., 1.));
    c = mix(c, vec3(1., .80, .20), clamp((t - .62) / .2, 0., 1.));
    c = mix(c, vec3(1., 1., .92), clamp((t - .82) / .18, 0., 1.));
    return pow(c, vec3(2.2));
}
