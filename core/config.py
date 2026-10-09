"""core/config.py — Central configuration loaded from environment variables.

All settings use the ``MERKLETRUST_`` prefix and may also be placed in a local
``.env`` file (git-ignored). Nothing secret has a default value.

    MERKLETRUST_ENV                   development | test | production
    MERKLETRUST_DATA_DIR              runtime data (SQLite DB, job workspaces); default ./data
    MERKLETRUST_DATABASE_URL          SQLAlchemy URL; default sqlite:///<data_dir>/merkletrust.db
    MERKLETRUST_SIGNING_KEY_PATH      PEM (PKCS#8) ECDSA P-256 private key
    MERKLETRUST_SIGNING_KEY_PASSWORD  password if that PEM is encrypted
    MERKLETRUST_TRUSTED_KEYS_DIR      directory of *.pem public keys of retired
                                      signing keys (still accepted for verification)
    MERKLETRUST_DEV_KEY_DIR           where a development key is auto-created when
                                      no key is configured (never in production)

  API / server
    MERKLETRUST_CORS_ORIGINS          JSON list of allowed browser origins (default: none,
                                      i.e. same-origin only)
    MERKLETRUST_MAX_UPLOAD_MB         maximum APK upload size (default 100)
    MERKLETRUST_SESSION_TTL_MINUTES   login session lifetime (default 480)
    MERKLETRUST_JOB_WORKERS           concurrent analysis jobs (default 2)
    MERKLETRUST_MAX_QUEUED_JOBS       queued jobs before uploads get HTTP 503 (default 20)
    MERKLETRUST_JOB_EXECUTION         "thread" (default) or "inline" (tests: run synchronously)
    MERKLETRUST_ENABLE_DEMO           tamper/restore demo endpoints (default: on unless production)
    MERKLETRUST_AUTO_MIGRATE          apply database migrations at startup (default true)
    MERKLETRUST_LOG_LEVEL / MERKLETRUST_LOG_JSON

  Dynamic (emulator) analysis — runs the uploaded app, so it is off by default
    MERKLETRUST_DYNAMIC_ENABLED       observe the app in a running emulator (default false)
    MERKLETRUST_DYNAMIC_TIMEOUT_S     time budget for the whole stage (default 120)
    MERKLETRUST_DYNAMIC_OBSERVE_S     observation window after launch (default 20)
    MERKLETRUST_ADB_PATH              adb executable (default: PATH, then the Android SDK)
    MERKLETRUST_ADB_SERIAL            device to use when several are connected
    MERKLETRUST_FRIDA_PATH            frida CLI for API hooks (optional; needs frida-server on the emulator)
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
    database_url: str | None = None

    signing_key_path: Path | None = None
    signing_key_password: SecretStr | None = None
    trusted_keys_dir: Path | None = None
    dev_key_dir: Path = Path.home() / ".merkletrust" / "keys"

    kms_provider: Literal["none", "mock", "aws", "gcp", "azure", "pkcs11"] = "none"
    kms_key_id: str | None = None
    kms_endpoint: str | None = None
    pkcs11_module_path: Path | None = None
    pkcs11_pin: SecretStr | None = None
    pkcs11_token_label: str | None = None

    cors_origins: list[str] = []
    max_upload_mb: int = 100
    session_ttl_minutes: int = 480
    job_workers: int = 2
    max_queued_jobs: int = 20
    job_execution: Literal["thread", "inline"] = "thread"
    enable_demo: bool | None = None
    auto_migrate: bool = True
    log_level: str = "INFO"
    log_json: bool = True
    login_rate_per_minute: int = 10
    upload_rate_per_minute: int = 20

    dynamic_enabled: bool = False
    dynamic_timeout_s: int = 120
    dynamic_observe_s: int = 20
    adb_path: str | None = None
    adb_serial: str | None = None
    frida_path: str | None = "frida"  # the CLI's name: used only if it resolves on PATH (shutil.which)

    @property
    def resolved_database_url(self) -> str:
        return self.database_url or f"sqlite:///{(self.data_dir / 'merkletrust.db').resolve().as_posix()}"

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def demo_enabled(self) -> bool:
        return (not self.is_production) if self.enable_demo is None else self.enable_demo

    @property
    def jobs_dir(self) -> Path:
        return self.data_dir / "jobs"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"


@lru_cache
def get_settings() -> Settings:
    return Settings()
