# Modern Android build (v1.4.2.8) name mining

We have Ghidra exports from the Android arm64 build (libNativeGame.so). The
library is stripped, but it still exports a large set of game-related symbols,
so it is useful for naming hints and string mining.

## Artifacts

Location in this repo:

- `source/decompiled-modern/crimsonland_android_1_4_2_8/libNativeGame.so_symbols.json`
- `source/decompiled-modern/crimsonland_android_1_4_2_8/libNativeGame.so_functions.json`
- `source/decompiled-modern/crimsonland_android_1_4_2_8/libNativeGame.so_calls.json`
- `source/decompiled-modern/crimsonland_android_1_4_2_8/libNativeGame.so_strings.json`


## Suggested mining workflow

1. Start with `libNativeGame.so_symbols.json` and pull `Crimsonland_*`,
   `GAME_*`, `QUEST_*`, `SND_*`, `AI*`, `Weapon*`, and `Powerup*` names.
2. Use `libNativeGame.so_calls.json` to cluster related functions.
3. Check `libNativeGame.so_strings.json` for UI labels and event names.


Example: quick name dictionary (Python, no dependencies):

```python
import json

data = json.load(open("source/decompiled-modern/crimsonland_android_1_4_2_8/libNativeGame.so_symbols.json"))
exports = [e["name"] for e in data["exports"]]
prefixes = ("Crimsonland_", "GAME_", "QUEST_", "SND_")
names = [n for n in exports if n.startswith(prefixes)]

print("count", len(names))
print("sample", names[:25])
```

## Caveats

- Stripped binary: many functions are still `FUN_`-style in the function list.
- JNI exports and Android SDK bindings dominate some name ranges.
- Treat names as hints; always validate against classic behavior.
