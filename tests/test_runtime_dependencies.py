"""Exercise player entry points without the optional/development import surface."""

from __future__ import annotations

import subprocess
import sys
import textwrap


def test_player_imports_and_quest_install_hint_without_tooling_dependencies() -> None:
    probe = textwrap.dedent("""\
        import importlib.abc
        import sys
        from pathlib import Path
        from tempfile import TemporaryDirectory

        class BlockTooling(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname.split(".")[0] in {"numpy", "lark", "tqdm"}:
                    raise ModuleNotFoundError(f"blocked tooling dependency: {fullname}", name=fullname)

        sys.meta_path.insert(0, BlockTooling())
        from crimson.cli.app import app
        from crimson.game import GameConfig
        from crimson.render.rtx.gpu_smoke import GpuSmokeSimulation
        from crimson.render.rtx.smoke import SmokeRenderer
        from crimson.replay.driver import replay_benchmark, replay_render
        from crimson.world.render_resources import RenderResources
        from typer.testing import CliRunner

        smoke = SmokeRenderer()
        assert isinstance(smoke.simulation, GpuSmokeSimulation)
        smoke.consume((), dt_sim=1 / 60)
        smoke.close()
        runner = CliRunner()
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0, result.output
        with TemporaryDirectory() as directory:
            recipe = Path(directory) / "test.quest"
            recipe.write_text("test")
            for command in ("build", "play", "publish"):
                result = runner.invoke(app, ["quest", command, str(recipe)])
                assert result.exit_code == 1, result.output
                assert "crimsonland[quests]" in result.output, result.output
                assert "repository checkout" in result.output, result.output
    """)
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
