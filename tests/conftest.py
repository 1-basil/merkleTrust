import os
import sys
import tempfile

import pytest

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Isolate ALL runtime state before any application module is imported:
# tests must never read or write the developer's data/ directory or real keys.
_TEST_ROOT = tempfile.mkdtemp(prefix="merkletrust_tests_")
os.environ["MERKLETRUST_ENV"] = "test"
os.environ["MERKLETRUST_DATA_DIR"] = os.path.join(_TEST_ROOT, "data")
os.environ["MERKLETRUST_DATABASE_URL"] = "sqlite:///" + os.path.join(_TEST_ROOT, "data", "test.db").replace("\\", "/")
os.environ["MERKLETRUST_DEV_KEY_DIR"] = os.path.join(_TEST_ROOT, "keys")
os.environ["MERKLETRUST_JOB_EXECUTION"] = "inline"   # analyses run synchronously in tests
os.environ["MERKLETRUST_LOG_JSON"] = "false"
os.environ["MERKLETRUST_DYNAMIC_DEVICE_WAIT_S"] = "0"  # no emulator in tests: do not wait for one
for _var in ("MERKLETRUST_SIGNING_KEY_PATH", "MERKLETRUST_SIGNING_KEY_PASSWORD", "MERKLETRUST_TRUSTED_KEYS_DIR"):
    os.environ.pop(_var, None)

FIXTURE_APKS = os.path.join(os.path.dirname(__file__), "fixtures", "apks")


@pytest.fixture(scope="session", autouse=True)
def isolated_signing_key(tmp_path_factory):
    """Never touch a developer's real keys: use a throwaway key directory for the whole run."""
    from core.crypto import reset_key_cache

    reset_key_cache()
    yield
    reset_key_cache()


@pytest.fixture
def db(tmp_path):
    """A fresh, empty database for one test; the app's session factory is bound to it."""
    from db.database import SessionLocal, configure_database, init_db

    configure_database("sqlite:///" + (tmp_path / "test.db").as_posix())
    init_db()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        configure_database()


@pytest.fixture
def fixture_apk():
    """Return the path of a committed, real signed APK fixture by file name."""
    def _get(name: str) -> str:
        path = os.path.join(FIXTURE_APKS, name)
        if not os.path.exists(path):
            pytest.fail(f"missing fixture {name}; run: python -m scripts.build_fixtures")
        return path
    return _get
