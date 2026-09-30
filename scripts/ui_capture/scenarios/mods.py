import os

from common import *

from crimson.screens.actions import Route

# `grim_get_config_var(100)` turns on the other-games entry; a mod DLL turns on Mods.
os.environ["CRIMSON_GRIM_CONFIG_VAR_100"] = "1"


def add_mod(gs):
    mods = gs.base_dir / "mods"
    mods.mkdir(exist_ok=True)
    (mods / "capture.dll").write_bytes(b"")


STEPS = [*boot(), ("hook", add_mod), go(Route.MENU), ("wait", 150), ("shot", "main_mods"),
         *go_nav("mods_in", Route.MODS), *key_nav("mods_out"), *go_nav("other_in", Route.OTHER_GAMES), *key_nav("other_out")]
