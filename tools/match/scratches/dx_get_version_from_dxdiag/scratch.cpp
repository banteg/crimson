#include <windows.h>
#include <oleauto.h>

struct dxdiag_init_params_t {
    DWORD size;
    DWORD header_version;
    BOOL allow_whql_checks;
    void *reserved;
};

struct dxdiag_container_t;

struct dxdiag_provider_t : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE initialize(
        dxdiag_init_params_t *params) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_root_container(
        dxdiag_container_t **container) = 0;
};

struct dxdiag_container_t : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE get_child_count(DWORD *count) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_child_name(
        DWORD index,
        WCHAR *name,
        DWORD name_chars) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_child_container(
        WCHAR *name,
        dxdiag_container_t **container) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_property_count(DWORD *count) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_property_name(
        DWORD index,
        WCHAR *name,
        DWORD name_chars) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_property(
        WCHAR *name,
        VARIANT *value) = 0;
};

extern "C" const GUID IID_IDxDiagProvider;
extern "C" const GUID CLSID_DxDiagProvider;

extern "C" HRESULT dx_get_version_from_dxdiag(
    int *major_out,
    int *minor_out,
    char *letter_out)
{
    bool got_major = false;
    bool got_minor = false;
    bool got_letter = false;

    bool cleanup_com = SUCCEEDED(CoInitialize(0));
    bool got_version = false;

    dxdiag_provider_t *provider = 0;
    HRESULT result = CoCreateInstance(
        CLSID_DxDiagProvider,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IDxDiagProvider,
        (void **)&provider);
    if (SUCCEEDED(result)) {
        dxdiag_init_params_t params;
        ZeroMemory(&params, sizeof(params));
        params.size = sizeof(params);
        params.header_version = 111;
        params.allow_whql_checks = FALSE;
        params.reserved = 0;

        result = provider->initialize(&params);
        if (SUCCEEDED(result)) {
            dxdiag_container_t *root = 0;
            dxdiag_container_t *system_info = 0;
            result = provider->get_root_container(&root);
            if (SUCCEEDED(result)) {
                result = root->get_child_container(
                    L"DxDiag_SystemInfo", &system_info);
                if (SUCCEEDED(result)) {
                    VARIANT value;
                    VariantInit(&value);

                    result = system_info->get_property(
                        L"dwDirectXVersionMajor", &value);
                    if (SUCCEEDED(result) && value.vt == VT_UI4) {
                        if (major_out != 0) {
                            *major_out = value.ulVal;
                        }
                        got_major = true;
                    }
                    VariantClear(&value);

                    result = system_info->get_property(
                        L"dwDirectXVersionMinor", &value);
                    if (SUCCEEDED(result) && value.vt == VT_UI4) {
                        if (minor_out != 0) {
                            *minor_out = value.ulVal;
                        }
                        got_minor = true;
                    }
                    VariantClear(&value);

                    result = system_info->get_property(
                        L"szDirectXVersionLetter", &value);
                    if (SUCCEEDED(result) && value.vt == VT_BSTR
                        && value.bstrVal != 0) {
                        char letter[10];
                        WideCharToMultiByte(
                            CP_ACP,
                            0,
                            value.bstrVal,
                            -1,
                            letter,
                            sizeof(letter),
                            0,
                            0);
                        if (letter_out != 0) {
                            *letter_out = letter[0];
                        }
                        got_letter = true;
                    }
                    VariantClear(&value);

                    if (got_major && got_minor && got_letter) {
                        got_version = true;
                    }
                    system_info->Release();
                }
                root->Release();
            }
        }
        provider->Release();
    }

    if (cleanup_com) {
        CoUninitialize();
    }
    return got_version ? S_OK : E_FAIL;
}
