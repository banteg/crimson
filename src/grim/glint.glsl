// The burst atlas stores a painted light-intensity profile in alpha, with white
// RGB. Decode that artwork independently of the particle's linear lifetime fade.
// Keep its asymmetric rays; a brighter, slightly whiter core reads as a sparkle.
vec4 glintEmission(vec4 art, vec4 tint) {
    // Art and tint arrive in linear RGB; only the painted mask still needs decoding.
    vec3 hue = mix(tint.rgb, vec3(1.), .25);
    return vec4(3. * art.rgb * pow(max(art.a, 0.), ART_GAMMA) * hue, tint.a);
}
