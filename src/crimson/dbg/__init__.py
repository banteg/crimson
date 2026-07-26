from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .frida_finalize import FinalizedTrace, FinalizeResult, FridaFinalizeError
    from .schema import TickRecord, TraceMeta
    from .trace import TraceError, TraceReader

__all__ = [
    "TRACE_FORMAT_VERSION",
    "TRACE_MAGIC",
    "TRACE_SCHEMA_VERSION",
    "FinalizeResult",
    "FinalizedTrace",
    "FridaFinalizeError",
    "TickRecord",
    "TraceError",
    "TraceMeta",
    "TraceReader",
    "finalize_frida_jsonl_to_traces",
    "load_trace",
    "load_trace_meta",
    "write_trace",
    "write_trace_iter",
]

_EXPORT_MODULES = {
    "FinalizeResult": ".frida_finalize",
    "FinalizedTrace": ".frida_finalize",
    "FridaFinalizeError": ".frida_finalize",
    "finalize_frida_jsonl_to_traces": ".frida_finalize",
    "TRACE_FORMAT_VERSION": ".schema",
    "TRACE_MAGIC": ".schema",
    "TRACE_SCHEMA_VERSION": ".schema",
    "TickRecord": ".schema",
    "TraceMeta": ".schema",
    "TraceError": ".trace",
    "TraceReader": ".trace",
    "load_trace": ".trace",
    "load_trace_meta": ".trace",
    "write_trace": ".trace",
    "write_trace_iter": ".trace",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value
