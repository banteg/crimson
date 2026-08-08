#ifndef _OBJBASE_H_
#define _OBJBASE_H_

#include <minwindef.h>
#include <guiddef.h>

#ifndef STDMETHODCALLTYPE
#define STDMETHODCALLTYPE __stdcall
#endif

#ifndef interface
#define interface struct
#endif

#ifdef __cplusplus

#ifndef STDMETHOD
#define STDMETHOD(method) virtual HRESULT STDMETHODCALLTYPE method
#endif
#ifndef STDMETHOD_
#define STDMETHOD_(type, method) virtual type STDMETHODCALLTYPE method
#endif
#ifndef PURE
#define PURE = 0
#endif

#ifndef THIS_
#define THIS_
#endif
#ifndef THIS
#define THIS void
#endif

#ifndef DECLARE_INTERFACE
#define DECLARE_INTERFACE(iface) interface iface
#endif

#ifndef DECLARE_INTERFACE_
#define DECLARE_INTERFACE_(iface, baseiface) interface iface : public baseiface
#endif

typedef interface IUnknown IUnknown;
interface IUnknown {
    STDMETHOD(QueryInterface)(REFIID riid, void **ppvObject) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
};

#else

#ifndef STDMETHOD
#define STDMETHOD(method) HRESULT (STDMETHODCALLTYPE *method)
#endif
#ifndef STDMETHOD_
#define STDMETHOD_(type, method) type (STDMETHODCALLTYPE *method)
#endif
#ifndef PURE
#define PURE
#endif

#ifndef THIS_
#define THIS_ void *This,
#endif
#ifndef THIS
#define THIS void *This
#endif

#ifndef DECLARE_INTERFACE
#define DECLARE_INTERFACE(iface) \
    typedef interface iface iface; \
    typedef struct iface##Vtbl iface##Vtbl; \
    struct iface { const iface##Vtbl *lpVtbl; }; \
    struct iface##Vtbl
#endif

#ifndef DECLARE_INTERFACE_
#define DECLARE_INTERFACE_(iface, baseiface) DECLARE_INTERFACE(iface)
#endif

typedef interface IUnknown IUnknown;
typedef struct IUnknownVtbl {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void **ppvObject) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
} IUnknownVtbl;

struct IUnknown {
    const IUnknownVtbl *lpVtbl;
};

#endif

typedef IUnknown *LPUNKNOWN;

#endif
