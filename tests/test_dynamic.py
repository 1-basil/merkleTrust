"""Unit tests for the dynamic engine's runtime capture (logcat + Frida).

adb, time and the Frida bindings are replaced with fakes, so these run without
an emulator or device.
"""

import json
import sys
import types

import pytest

from core import dynamic
from core.contracts import JobContext


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(dynamic.time, "sleep", lambda _s: None)


def _fake_frida(monkeypatch, *, messages=(), attach_error=None, pid_seen=None):
    """Install a fake `frida` module whose session delivers the given messages."""
    class FakeSession:
        def create_script(self, code):
            self._code = code
            return self

        def on(self, _event, handler):
            self._handler = handler

        def load(self):
            for msg in messages:
                self._handler(msg, None)

        def detach(self):
            pass

    class FakeDevice:
        def attach(self, pid):
            if pid_seen is not None:
                pid_seen.append(pid)
            if attach_error:
                raise RuntimeError(attach_error)
            return FakeSession()

    fake = types.ModuleType("frida")
    fake.get_usb_device = lambda timeout=5: FakeDevice()
    monkeypatch.setitem(sys.modules, "frida", fake)


def test_frida_script_contains_default_hooks_and_targets():
    targets = [
        {"type": "class", "value": "Lcom/evil/Loader;", "reason": "x"},
        {"type": "url", "value": "http://203.0.113.9", "reason": "x"},
    ]
    code = dynamic.generate_frida_script(targets, "com.example.app")
    assert "dalvik.system.DexClassLoader" in code
    assert "java.lang.Runtime" in code
    assert "com.evil.Loader" in code
    assert "http://203.0.113.9" in code
    assert "com.example.app" in code


def test_capture_logcat_keeps_only_lifecycle_lines(monkeypatch, no_sleep, tmp_path):
    dump = "\n".join([
        "10-03 00:00:01.000 I/ActivityManager(513): Start proc 5821:com.example.app",
        "10-03 00:00:02.000 D/SomethingElse(1): unrelated noise",
        "10-03 00:00:03.000 E/AndroidRuntime(9): FATAL EXCEPTION: main",
    ])
    calls = []

    def fake_adb(*args, timeout_s=30):
        calls.append(args)
        return (0, dump, "") if args[:2] == ("logcat", "-d") else (0, "", "")

    monkeypatch.setattr(dynamic, "_adb", fake_adb)
    text, events = dynamic._capture_logcat(str(tmp_path), duration_s=1)

    assert text == dump
    assert ("logcat", "-c") in calls
    assert len(events) == 2
    assert all("unrelated" not in e["line"] for e in events)


def test_attach_frida_reports_missing_pid(monkeypatch, no_sleep):
    monkeypatch.setattr(dynamic, "_adb", lambda *a, **k: (1, "", "not found"))
    _fake_frida(monkeypatch)
    messages, reason = dynamic._attach_frida("com.example.app", "code", duration_s=1)
    assert messages == []
    assert "pidof" in reason


def test_attach_frida_reports_missing_bindings(monkeypatch, no_sleep):
    monkeypatch.setattr(dynamic, "_adb", lambda *a, **k: (0, "4321", ""))
    monkeypatch.setitem(sys.modules, "frida", None)  # makes `import frida` fail
    messages, reason = dynamic._attach_frida("com.example.app", "code", duration_s=1)
    assert messages == []
    assert "not installed" in reason


def test_attach_frida_collects_send_log_and_error_messages(monkeypatch, no_sleep):
    pids = []
    monkeypatch.setattr(dynamic, "_adb", lambda *a, **k: (0, "4321", ""))
    _fake_frida(monkeypatch, pid_seen=pids, messages=[
        {"type": "send", "payload": "hook-a"},
        {"type": "log", "payload": "hook-b"},
        {"type": "error", "description": "boom"},
    ])
    messages, reason = dynamic._attach_frida("com.example.app", "code", duration_s=1)
    assert reason is None
    assert pids == [4321]
    assert messages == ["hook-a", "hook-b", "[frida-error] boom"]


def test_attach_frida_reports_attach_refusal(monkeypatch, no_sleep):
    monkeypatch.setattr(dynamic, "_adb", lambda *a, **k: (0, "4321", ""))
    _fake_frida(monkeypatch, attach_error="access denied")
    messages, reason = dynamic._attach_frida("com.example.app", "code", duration_s=1)
    assert messages == []
    assert "access denied" in reason


def _ctx(tmp_path, apk, prior=None):
    return JobContext(apk_path=str(apk), workspace=str(tmp_path / "ws"),
                      prior=prior or {}, config={"emulator_avd": "Pixel_6", "dynamic_timeout_s": 60})


def test_run_without_device_is_partial_and_writes_artifacts(monkeypatch, tmp_path):
    monkeypatch.setattr(dynamic, "_wait_for_device", lambda _t: False)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"x")
    report = dynamic.run("job-1", _ctx(tmp_path, apk))
    assert report["status"] == "partial"
    assert report["findings"][0]["id"] == "DYN_001"
    assert json.loads((tmp_path / "ws" / "dynamic.json").read_text())["engine"] == "dynamic"


def test_run_happy_path_populates_process_events_and_hooks(monkeypatch, no_sleep, tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"x")
    monkeypatch.setattr(dynamic, "_wait_for_device", lambda _t: True)
    monkeypatch.setattr(dynamic, "_get_emulator_info", lambda: (33, True))
    monkeypatch.setattr(dynamic, "_install_apk", lambda *a, **k: (True, "Success"))
    monkeypatch.setattr(dynamic, "_resolve_launch_activity", lambda ctx, pkg: (f"{pkg}.Main", "prior"))
    monkeypatch.setattr(dynamic, "_launch_app", lambda *a, **k: (True, "am_start", "ok"))
    monkeypatch.setattr(dynamic, "_capture_logcat",
                        lambda d, duration_s: ("log", [{"line": "ActivityManager start"}]))
    monkeypatch.setattr(dynamic, "_attach_frida", lambda pkg, code, duration_s: (["hook fired"], None))

    prior = {"static": {"package_name": "com.example.app"}, "tamper": {"suspicious_targets": []}}
    report = dynamic.run("job-2", _ctx(tmp_path, apk, prior))

    assert report["status"] == "ok"
    assert report["launched"] is True
    assert report["process_events"] == [{"line": "ActivityManager start"}]
    assert report["hooks"] == ["hook fired"]
    assert any(f["id"] == "DYN_007" for f in report["findings"])
    assert (tmp_path / "ws" / "dynamic" / "logcat.txt").read_text() == "log"
