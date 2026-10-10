"""PEP 517 wrapper: stamp Python build metadata into wheels and sdists."""

import json
from contextlib import contextmanager

import uv_build

from scripts.build_identity import ROOT, python_identity, write_manifest


def __getattr__(name):
    return getattr(uv_build, name)


@contextmanager
def metadata():
    path = ROOT / "src/crimson/_build.json"
    previous = path.read_bytes() if path.exists() else None
    try:
        build = python_identity()
        if previous is not None and build["origin"]["commit"] is None:
            source = json.loads(previous)
            if source["fingerprint"] == build["fingerprint"]:
                build["origin"] = source["origin"]
        write_manifest(path, build, [])
        yield
    finally:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(previous)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    with metadata():
        return uv_build.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_sdist(sdist_directory, config_settings=None):
    with metadata():
        return uv_build.build_sdist(sdist_directory, config_settings)
