"""Dynamic (emulator) engine: graceful degradation without a device, simulated device
flows, and protection against code injection into the generated Frida script."""

import json
import shutil
import subprocess

import pytest

from core import dynamic
from core.contracts import JobContext
from core.findings import normalize

pytestmark = pytest.mark.unit

STATIC = {"package_name": "com.merkletrust.demo",
          "components": {"activities": ["com.merkletrust.demo.MainActivity"]},
          "component_details": [{"type": "activity", "name": "com.merkletrust.demo.MainActivity",
                                 "exported_effective": True, "has_intent_filter": True}]}


def _ctx(tmp_path, fixture_apk, prior=None):
    return JobContext(apk_path=fixture_apk("signed_v1v2_ec.apk"), workspace=str(tmp_path),
                      prior=prior if prior is not None else {"static": STATIC, "tamper": {"suspicious_targets": []}},
                      config={"dynamic_timeout_s": 3})


def test_without_device_degrades_to_partial(tmp_path, fixture_apk, monkeypatch):
    monkeypatch.setattr(dynamic, "_wait_for_device", lambda timeout: False)
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    assert r["status"] == "partial"
    assert r["installed"] is False and r["launched"] is False
    assert r["findings"][0]["id"] == "DYN_001"
    assert (tmp_path / "dynamic" / "frida_hooks.js").exists()
    # Operational problems are reported, never turned into app risk.
    assert all(normalize(f, "dynamic")["points"] == 0 for f in r["findings"])


def test_simulated_device_install_and_launch(tmp_path, fixture_apk, monkeypatch):
    monkeypatch.setattr(dynamic, "_wait_for_device", lambda timeout: True)
    monkeypatch.setattr(dynamic, "_get_emulator_info", lambda: (30, True))
    monkeypatch.setattr(dynamic, "_install_apk", lambda path, timeout_s=60: (True, "Success"))
    monkeypatch.setattr(dynamic, "_launch_app", lambda pkg, activity=None, timeout_s=15: (True, "am_start", "ok"))
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    assert r["installed"] is True and r["launched"] is True
    assert r["status"] == "ok"


@pytest.mark.parametrize("install,launch,expected_id", [
    ((False, "INSTALL_FAILED_INVALID_APK"), None, "DYN_003"),
    ((True, "Success"), (False, "failed", "Activity not found"), "DYN_005"),
])
def test_simulated_device_failures(tmp_path, fixture_apk, monkeypatch, install, launch, expected_id):
    monkeypatch.setattr(dynamic, "_wait_for_device", lambda timeout: True)
    monkeypatch.setattr(dynamic, "_get_emulator_info", lambda: (30, False))
    monkeypatch.setattr(dynamic, "_install_apk", lambda path, timeout_s=60: install)
    if launch:
        monkeypatch.setattr(dynamic, "_launch_app", lambda pkg, activity=None, timeout_s=15: launch)
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    assert r["status"] == "partial"
    assert expected_id in {f["id"] for f in r["findings"]}
    assert all(normalize(f, "dynamic")["points"] == 0 for f in r["findings"])


def test_command_timeouts_are_bounded(monkeypatch):
    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout"))
    monkeypatch.setattr(dynamic.subprocess, "run", slow)
    code, _, err = dynamic._run_cmd(["adb", "devices"], timeout_s=1)
    assert code == -1 and "timed out" in err


INJECTIONS = [
    "http://c2.example/');Java.perform(function(){send('pwned')});//",
    "http://c2.example/\nconsole.log('second line')",
    "La/B';Java.use('x').y();//;",
    "evil*/ code /*",
]


@pytest.mark.security
@pytest.mark.parametrize("payload", INJECTIONS)
def test_frida_script_is_not_injectable(payload):
    """suspicious_targets come from the APK; they must stay inert string data."""
    script = dynamic.generate_frida_script(
        [{"type": "url", "value": payload}, {"type": "class", "value": payload},
         {"type": "service", "value": payload}], package=payload)
    literal = json.dumps(payload)
    code_only = script.replace(literal, '""')
    clean_class = json.dumps(payload.strip("L;").replace("/", "."))
    code_only = code_only.replace(clean_class, '""')
    comment_free = "\n".join(line for line in code_only.splitlines() if not line.strip().startswith("//"))
    assert "pwned" not in comment_free and "second line" not in comment_free
    assert "Java.use('x')" not in comment_free
    for line in script.splitlines():
        if line.strip().startswith("//"):
            assert "\n" not in line and "*/" not in line


@pytest.mark.security
@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_frida_script_with_hostile_values_is_valid_javascript(tmp_path):
    script = dynamic.generate_frida_script([{"type": "url", "value": p} for p in INJECTIONS], package="p'\"\n")
    path = tmp_path / "hooks.js"
    path.write_text(script, encoding="utf-8")
    result = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
