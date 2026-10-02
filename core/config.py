"""core/config.py — Central configuration loaded from environment variables.

All settings use the ``MERKLETRUST_`` prefix and may also be placed in a local
``.env`` file (git-ignored). Nothing secret has a default value.

    MERKLETRUST_ENV                   development | test | production
    MERKLETRUST_SIGNING_KEY_PATH      PEM (PKCS#8) ECDSA P-256 private key
    MERKLETRUST_SIGNING_KEY_PASSWORD  password if that PEM is encrypted
    MERKLETRUST_TRUSTED_KEYS_DIR      directory of *.pem public keys of retired
                                      signing keys (still accepted for verification)
    MERKLETRUST_DEV_KEY_DIR           where a development key is auto-created when
                                      no key is configured (never in production)
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MERKLETRUST_", env_file=".env", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    data_dir: Path = Path("data")

    signing_key_path: Path | None = None
    signing_key_password: SecretStr | None = None
    trusted_keys_dir: Path | None = None
    dev_key_dir: Path = Path.home() / ".merkletrust" / "keys"

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
