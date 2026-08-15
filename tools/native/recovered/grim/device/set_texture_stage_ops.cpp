#include "grim_d3d8.h"

extern IDirect3DDevice8 *grim_d3d_device;

unsigned char grim_set_texture_stage_ops(unsigned int mode)
{
    switch (mode) {
    case 0:
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG2);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG2);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_DISABLE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        return 1;

    case 1:
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_DISABLE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        return 1;

    case 2:
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLORARG2, D3DTA_CURRENT);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAARG2, D3DTA_CURRENT);
        grim_d3d_device->SetTextureStageState(2, D3DTSS_COLOROP, D3DTOP_DISABLE);
        grim_d3d_device->SetTextureStageState(2, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        return 1;

    case 3:
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_ADD);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_ADD);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLORARG2, D3DTA_CURRENT);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAARG2, D3DTA_CURRENT);
        grim_d3d_device->SetTextureStageState(2, D3DTSS_COLOROP, D3DTOP_DISABLE);
        grim_d3d_device->SetTextureStageState(2, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        return 1;

    case 4:
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_DOTPRODUCT3);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_TFACTOR);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_DISABLE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        return 1;

    case 5:
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_DOTPRODUCT3);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_DISABLE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        return 1;

    case 6:
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_DOTPRODUCT3);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_COLORARG2, D3DTA_CURRENT);
        grim_d3d_device->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        grim_d3d_device->SetTextureStageState(2, D3DTSS_COLOROP, D3DTOP_DISABLE);
        grim_d3d_device->SetTextureStageState(2, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        return 1;
    }

    return 0;
}
