#ifndef CRIMSONLAND_MOD_API_H
#define CRIMSONLAND_MOD_API_H

struct mod_vertex2_t;
struct mod_var_t;

// C++ projection of the native mod API object installed by mod_api_init.
// The existing mod_api_t/mod_api_vtbl_t declarations remain the portable C
// layout used by the Python parity layer; these methods recover the native
// x86 __thiscall surface.
class mod_api_cpp_t {
public:
    virtual void mod_api_core_printf(char *format, ...);
    virtual mod_var_t *mod_api_core_get_var(char *id);
    virtual unsigned char mod_api_core_del_var(char *id);
    virtual void mod_api_core_execute(char *string);
    virtual void mod_api_core_add_command(char *id, void (*command)(void));
    virtual unsigned char mod_api_core_del_command(char *id);
    virtual void *mod_api_core_get_extension(char *extension);
    virtual void mod_api_gfx_clear(float r, float g, float b, float a);
    virtual int mod_api_gfx_get_string_width(char *string);
    virtual void mod_api_gfx_printf(float x, float y, char *format, ...);
    virtual int mod_api_gfx_load_texture(char *filename);
    virtual unsigned char mod_api_gfx_free_texture(int texture_id);
    virtual void mod_api_gfx_set_texture(int texture_id);
    virtual void mod_api_gfx_set_texture_filter(int filter);
    virtual void mod_api_gfx_set_blend_mode(int src, int dst);
    virtual void mod_api_gfx_set_color(float r, float g, float b, float a);
    virtual void mod_api_gfx_set_subset(float x1, float y1, float x2, float y2);
    virtual void mod_api_gfx_begin(void);
    virtual void mod_api_gfx_end(void);
    virtual void mod_api_gfx_quad(float x, float y, float w, float h);
    virtual void mod_api_gfx_quad_rot(float x, float y, float w, float h, float angle);
    virtual void mod_api_gfx_draw_quads(mod_vertex2_t *vertices, int quad_count);
    virtual int mod_api_sfx_load_sample(char *filename);
    virtual unsigned char mod_api_sfx_free_sample(int sample_id);
    virtual void mod_api_sfx_play_sample(int sample_id, float pan, float volume);
    virtual int mod_api_sfx_load_tune(char *filename);
    virtual unsigned char mod_api_sfx_free_tune(int tune_id);
    virtual void mod_api_sfx_play_tune(int tune_id);
    virtual void mod_api_sfx_stop_tune(int tune_id);
    virtual unsigned char mod_api_inp_key_down(int key);
    virtual float mod_api_inp_get_analog(int key);
    virtual char mod_api_inp_get_pressed_char(void);
    virtual char *mod_api_inp_get_key_name(int key);
    virtual void mod_api_cl_enter_menu(char *menu);
};

#endif
