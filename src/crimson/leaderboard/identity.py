"""The player's leaderboard identity: an Ed25519 key the game makes on first launch.

docs/rewrite/leaderboard-identity.md is the contract. The key's public half is the account; the private half never
leaves the runtime directory except through an explicit export.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from nacl.signing import SigningKey

from grim.atomic_write import atomic_write_bytes

IDENTITY_FILE = "identity.key"
# Each signed message starts with its purpose, so a run signature can never pass as a login and back.
RUN_SIGNATURE_DOMAIN = b"crimson-run-v1\n"
LOGIN_SIGNATURE_DOMAIN = b"crimson-login-v1\n"


class IdentityError(ValueError):
    pass


def run_message(payload: bytes, name: str) -> bytes:
    """What an upload's signature covers: the replay's canonical payload, by hash, and the run's name."""
    return RUN_SIGNATURE_DOMAIN + hashlib.sha256(payload).digest() + name.encode("latin-1")


def login_message(challenge: str) -> bytes:
    return LOGIN_SIGNATURE_DOMAIN + challenge.encode("ascii")


def key_fingerprint(public_key: bytes) -> str:
    """The four hex digits the boards add when two unlinked accounts show the same name."""
    return hashlib.sha256(public_key).hexdigest()[:4]


class Identity:
    def __init__(self, key: SigningKey) -> None:
        self._key = key

    @classmethod
    def load(cls, path: Path) -> Identity:
        seed = path.read_bytes()
        if len(seed) != 32:
            raise IdentityError(f"{path} is not an identity key ({len(seed)} bytes, expected 32)")
        return cls(SigningKey(seed))

    @classmethod
    def load_or_create(cls, base_dir: Path) -> Identity:
        path = base_dir / IDENTITY_FILE
        if path.exists():
            return cls.load(path)
        identity = cls(SigningKey.generate())
        base_dir.mkdir(parents=True, exist_ok=True)
        identity.save(path)
        return identity

    def save(self, path: Path) -> None:
        # atomic_write_bytes stages through mkstemp, so the key file is readable by its owner only.
        atomic_write_bytes(path, bytes(self._key))

    @property
    def public_key(self) -> bytes:
        return self._key.verify_key.encode()

    @property
    def fingerprint(self) -> str:
        return key_fingerprint(self.public_key)

    def sign_run(self, payload: bytes, name: str) -> bytes:
        return self._key.sign(run_message(payload, name)).signature

    def sign_login(self, challenge: str) -> bytes:
        return self._key.sign(login_message(challenge)).signature


__all__ = [
    "IDENTITY_FILE",
    "Identity",
    "IdentityError",
    "key_fingerprint",
    "login_message",
    "run_message",
]
