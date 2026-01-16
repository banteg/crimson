# Modern Linux build (1.35) name mining

We have Ghidra exports from the modern Crimsonland Linux build (1.35). The
engine is different from classic, but the gameplay concepts are the same, so
the symbol names are useful as hints and naming candidates.

## Artifacts

Location in this repo:

- `source/decompiled-modern/crimsonland_linux_135/crimsonland_symbols.json`
- `source/decompiled-modern/crimsonland_linux_135/crimsonland_functions.json`
- `source/decompiled-modern/crimsonland_linux_135/crimsonland_calls.json`
- `source/decompiled-modern/crimsonland_linux_135/crimsonland_strings.json`

## Suggested mining workflow

1. Start with `crimsonland_symbols.json` to extract named APIs (e.g.
   `Crimsonland_*`, `GAME_*`, `QUEST_*`, `SND_*`, `AI*`, `Weapon*`).
2. Use `crimsonland_calls.json` to find call clusters around known names.
3. Validate candidate names against classic behavior and data formats.

Example: quick name dictionary (Python, no dependencies):

```python
import json
from collections import Counter

data = json.load(open("source/decompiled-modern/crimsonland_linux_135/crimsonland_symbols.json"))
exports = [e["name"] for e in data["exports"]]
prefixes = ("Crimsonland_", "GAME_", "QUEST_", "SND_")
names = [n for n in exports if n.startswith(prefixes)]

print("count", len(names))
print("top prefixes", Counter(n.split("_", 1)[0] for n in names).most_common())
```

## Caveats

- This build is x86_64 Linux and not stripped, so names are intact.
- External libs (SDL/OpenAL/libstdc++) were not resolved during headless runs.
- The engine is likely different; treat names as suggestions, not ground truth.
