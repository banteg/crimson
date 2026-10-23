# ruff: noqa: ARG001, TRY002 - Emscripten calls a port's get and clear with these arguments.
# Emdawnwebgpu, Dawn's webgpu.h over the browser's WebGPU, as an Emscripten remote port pinned to one release, so
# every Emscripten version builds the same bindings (client/build.py passes --use-port with this file, named apart from the one Emscripten carries). The same
# definition Emscripten 6.0.13 vendors (tools/ports/emdawnwebgpu.py), under its licence; the package's own port file
# does the work.
_VERSION = 'v20260423.175430'
EXTERNAL_PORT = f'https://github.com/google/dawn/releases/download/{_VERSION}/emdawnwebgpu_pkg-{_VERSION}.zip'
SHA512 = '42784f70b67197c614322f9fabb0f1dc64228a0de10e88f99941fa9d29bee9ad6683f4651d4eefd5a7a9fbd1f976eb522b190b683219ed1793e9b531c602ffa6'
PORT_FILE = 'emdawnwebgpu_pkg/emdawnwebgpu.port.py'
LICENSE = "Some files: BSD 3-Clause License. Other files: Emscripten's license (available under both MIT License and University of Illinois/NCSA Open Source License)"
DESCRIPTION = 'Emdawnwebgpu implements webgpu.h on WebGPU.'
URL = 'https://dawn.googlesource.com/dawn/+/01940842b667a7812d0e4ca0ef4367fbec294241/src/emdawnwebgpu/pkg/README.md'


def get(ports, settings, shared):
    raise Exception('Remote ports require Emscripten 4.0.10+.')


def clear(ports, settings, shared):
    pass
