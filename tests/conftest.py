import os
import sys

import pytest

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FIXTURE_APKS = os.path.join(os.path.dirname(__file__), "fixtures", "apks")


@pytest.fixture
def fixture_apk():
    """Return the path of a committed, real signed APK fixture by file name."""
    def _get(name: str) -> str:
        path = os.path.join(FIXTURE_APKS, name)
        if not os.path.exists(path):
            pytest.fail(f"missing fixture {name}; run: python -m scripts.build_fixtures")
        return path
    return _get
