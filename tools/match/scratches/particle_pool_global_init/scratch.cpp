struct particle_scale_t {
    float x;
    float y;
    float z;
    float age;

    particle_scale_t(float x_value, float y_value, float z_value, float age_value)
        : x(x_value), y(y_value), z(z_value), age(age_value) {}
};

struct particle_native_t {
    unsigned char active;
    unsigned char render_flag;
    unsigned char padding0[2];
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    particle_scale_t scale;
    float intensity;
    float angle;
    float spin;
    unsigned char style_id;
    unsigned char padding1[3];
    int target_id;
};

extern "C" particle_native_t particle_pool[0x80];
extern "C" int crt_rand(void);

extern "C" void particle_pool_global_init(void)
{
    int remaining = 0x80;
    particle_native_t *entry = particle_pool;

    do {
        entry->style_id = 0;
        entry->active = 0;
        entry->intensity = 1.0f;
        entry->scale = particle_scale_t(1.0f, 1.0f, 1.0f, 1.0f);
        entry->spin = (float)(crt_rand() % 0x274) * 0.01f;
        entry->render_flag = 1;
        entry->target_id = -1;
        ++entry;
    } while (--remaining != 0);
}
