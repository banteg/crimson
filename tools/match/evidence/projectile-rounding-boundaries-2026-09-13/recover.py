"""Reconstruct the microstep and ion-chain math boundaries independently."""

BEFORE_SHA = "d14bf9bff5dc43497c64fd56fcac0a63447d53b9e63007f3e1d46fc85f1fe28f"
RECOVERED_BODY_SHA = "83ab20fde04ca82d064ef5d4cd3e36ce8563e62db2fd5a9fb3e97ed057c101cd"
EDITS = (
    (
        """                            float distance = (float)sqrt(
                                delta.x * delta.x
                                + delta.y * delta.y);""",
        """                            float distance_sq = delta.x * delta.x;
                            distance_sq += delta.y * delta.y;
                            float distance = (float)sqrt(distance_sq);""",
    ),
    ("float chain_angle = (float)atan2(", "float chain_angle = (float)atan2f("),
)


def recover(before, mask=3):
    source = before
    for bit, (old, new) in enumerate(EDITS):
        assert source.count(old) == 1
        if mask & (1 << bit):
            source = source.replace(old, new)
    return source
