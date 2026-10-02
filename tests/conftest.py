import os
import sys

import pytest

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FIXTURE_APKS = os.path.join(os.path.dirname(__file__), "fixtures", "apks")


@pytest.fixture(scope="session", autouse=True)
def isolated_signing_key(tmp_path_factory):
    """Never touch a developer's real keys: use a throwaway key directory for the whole run."""
    from core.crypto import reset_key_cache

    os.environ["MERKLETRUST_ENV"] = "test"
    os.environ["MERKLETRUST_DEV_KEY_DIR"] = str(tmp_path_factory.mktemp("keys"))
    for var in ("MERKLETRUST_SIGNING_KEY_PATH", "MERKLETRUST_SIGNING_KEY_PASSWORD", "MERKLETRUST_TRUSTED_KEYS_DIR"):
        os.environ.pop(var, None)
    reset_key_cache()
    yield
    reset_key_cache()


@pytest.fixture
def fixture_apk():
    """Return the path of a committed, real signed APK fixture by file name."""
    def _get(name: str) -> str:
        path = os.path.join(FIXTURE_APKS, name)
        if not os.path.exists(path):
            pytest.fail(f"missing fixture {name}; run: python -m scripts.build_fixtures")
        return path
    return _get
