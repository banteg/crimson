"""The original builds whose rules a run can play.

Values are the decomp's `CL_BUILD` (`major*10000 + minor*100 + patch`, decomp/README.md). A run plays
1.9.93 unless it picks 1.9.8; the 1.9.8 rules are the guarded 1.9.8 branches that change a run, and
1.9.8's own bugs follow original-bug policy (docs/rewrite/original-bugs.md).
"""

from __future__ import annotations

from enum import IntEnum


class ClBuild(IntEnum):
    V1_9_8 = 10908
    V1_9_93 = 10993

    @property
    def label(self) -> str:
        return {ClBuild.V1_9_8: "1.9.8", ClBuild.V1_9_93: "1.9.93"}[self]

    @classmethod
    def from_label(cls, label: str) -> ClBuild:
        """The build `label` names, as the `--build` options take it."""
        for build in cls:
            if build.label == label:
                return build
        raise ValueError(f"unknown build {label!r}")
