#include "grim2d_cpp.h"
#include "grim_texture.h"

extern grim_config_value_t grim_config_values[128];
extern IDirect3DVertexBuffer8 *grim_vertex_buffer;
extern IDirect3DIndexBuffer8 *grim_index_buffer;

void grim_apply_render_state(void)
{
    grim_d3d_device->SetRenderState(D3DRS_LIGHTING, 0);
    grim_d3d_device->SetRenderState(D3DRS_SPECULARENABLE, 0);
    grim_d3d_device->SetRenderState(D3DRS_ZENABLE, 0);
    grim_d3d_device->SetRenderState(D3DRS_ZWRITEENABLE, 0);
    grim_d3d_device->SetRenderState(D3DRS_FOGENABLE, 0);
    grim_d3d_device->SetRenderState(D3DRS_NORMALIZENORMALS, 0);
    grim_d3d_device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
    grim_d3d_device->SetRenderState(D3DRS_SHADEMODE, D3DSHADE_GOURAUD);
    grim_d3d_device->SetRenderState(
        D3DRS_DITHERENABLE, grim_config_values[0x58].words[0] & 0xff);
    grim_d3d_device->SetRenderState(D3DRS_ALPHATESTENABLE, 1);
    grim_d3d_device->SetRenderState(D3DRS_ALPHAFUNC, D3DCMP_GREATEREQUAL);
    grim_d3d_device->SetRenderState(D3DRS_ALPHAREF, 4);

    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_MINFILTER, D3DTEXF_LINEAR);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_MAGFILTER, D3DTEXF_LINEAR);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_MIPFILTER, D3DTEXF_NONE);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_COLOROP, D3DTOP_MODULATE);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
    grim_d3d_device->SetTextureStageState(
        1, D3DTSS_COLOROP, D3DTOP_DISABLE);
    grim_d3d_device->SetTextureStageState(
        1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
    grim_d3d_device->SetTextureStageState(0, D3DTSS_TEXCOORDINDEX, 0);
    grim_d3d_device->SetTextureStageState(1, D3DTSS_TEXCOORDINDEX, 0);

    grim_d3d_device->SetRenderState(D3DRS_WRAP0, 0);
    grim_d3d_device->SetRenderState(D3DRS_WRAP1, 0);
    grim_d3d_device->SetRenderState(D3DRS_WRAP2, 0);
    grim_d3d_device->SetRenderState(D3DRS_WRAP3, 0);

    grim_d3d_device->SetStreamSource(0, grim_vertex_buffer, 0x1c);
    grim_d3d_device->SetIndices(grim_index_buffer, 0);
    grim_d3d_device->SetVertexShader(0x144);

    grim_d3d_device->SetRenderState(
        D3DRS_ALPHABLENDENABLE,
        grim_config_values[0x12].words[0] & 0xff);
    grim_d3d_device->SetRenderState(
        D3DRS_SRCBLEND, grim_config_values[0x13].words[0]);
    grim_d3d_device->SetRenderState(
        D3DRS_DESTBLEND, grim_config_values[0x14].words[0]);
}
