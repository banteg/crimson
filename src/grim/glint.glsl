// The burst atlas stores a painted light-intensity profile in alpha, with white
// RGB. Decode that artwork independently of the particle's linear lifetime fade.
// Keep its asymmetric rays; a brighter, slightly whiter core reads as a sparkle.
vec4 glintEmission(vec4 art, vec4 tint) {
    vec3 hue = mix(decodeArt(tint.rgb), vec3(1.), .25);
    return vec4(3. * decodeArt(art.rgb) * pow(max(art.a, 0.), ART_GAMMA) * hue, tint.a);
}
