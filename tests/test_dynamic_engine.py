"""Dynamic (emulator) engine: safety gates, a full run against a simulated emulator,
runtime findings and their de-duplication with static findings, adb output
parsers, the packet-capture reader, and injection safety of generated scripts."""

import ipaddress
import json
import os
import random
import shutil
import struct
import subprocess

import pytest

from core import dynamic, pcap
from core.contracts import JobContext
from core.findings import normalize
from core.scoring import score_findings

pytestmark = pytest.mark.unit

PKG = "com.sample.booster"
UID = 10153
STATIC = {"package_name": PKG,
          "component_details": [
              {"type": "activity", "name": f"{PKG}.MainActivity", "exported_effective": True,
               "intent_actions": ["android.intent.action.MAIN"]},
              {"type": "receiver", "name": f"{PKG}.OnBoot", "exported_effective": True,
               "intent_actions": ["android.intent.action.BOOT_COMPLETED"]},
              {"type": "service", "name": f"{PKG}.Sync", "exported_effective": False, "intent_actions": []}]}
ENABLED = {"dynamic_enabled": True, "adb": "adb", "dynamic_observe_s": 0, "dynamic_device_wait_s": 0,
           "dynamic_timeout_s": 60}


# ---------------------------------------------------------- pcap builders --

def _eth(ip_packet: bytes, v6: bool = False) -> bytes:
    return b"\x02" * 6 + b"\x04" * 6 + (b"\x86\xdd" if v6 else b"\x08\x00") + ip_packet


def _ipv4(src: str, dst: str, proto: int, body: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header + body


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x18, 65535, 0, 0) + payload


def _dns_query(ident: int, name: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + qname + b"\x00\x01\x00\x01"


def _dns_answer(ident: int, name: str, ip: str) -> bytes:
    q = _dns_query(ident, name)
    msg = struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + q[12:]
    return msg + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.IPv4Address(ip).packed


def _client_hello(host: str) -> bytes:
    name = host.encode()
    sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack("!H", len(sni)) + sni
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _pcap(frames: list[bytes], linktype: int = 1) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(f), len(f)) + f
    return out


SAMPLE_PCAP = _pcap([
    _eth(_ipv4("10.0.2.16", "10.0.2.3", 17, _udp(40000, 53, _dns_query(7, "c2.evil-boost.xyz")))),
    _eth(_ipv4("10.0.2.3", "10.0.2.16", 17, _udp(53, 40000, _dns_answer(7, "c2.evil-boost.xyz", "93.184.216.34")))),
    _eth(_ipv4("10.0.2.16", "93.184.216.34", 6, _tcp(51000, 443, _client_hello("c2.evil-boost.xyz")))),
    _eth(_ipv4("93.184.216.34", "10.0.2.16", 6, _tcp(443, 51000, b"\x16\x03\x03\x00\x05hello"))),
])


# Real ftrace output format (record-tgid) from the API 30 emulator kernel.
TRACE = """# tracer: nop
          <...>-4321    ( 4321) [001] ....   900.100000: sched_process_fork: comm=booster pid=4330 child_comm=booster child_pid=4400
             su-4400    ( 4400) [000] d..1   900.100500: exec: (__x64_sys_execve+0x0/0x50) path="/product/bin/su" a1="-c" a2="setenforce" a3="0" a4=(fault)
             su-4400    ( 4400) [000] d..1   900.100600: exec: (__x64_sys_execve+0x0/0x50) path="/system/xbin/su" a1="-c" a2="setenforce" a3="0" a4=(fault)
             sh-7000    ( 7000) [002] d..1   900.200000: exec: (__x64_sys_execve+0x0/0x50) path="/system/bin/ls" a1=(fault) a2=(fault) a3=(fault) a4=(fault)
"""


# ------------------------------------------------------- fake emulator --

def _proc_net_line(ip: str, port: int, uid: int, state: str = "01") -> str:
    hexip = ipaddress.IPv4Address(ip).packed[::-1].hex().upper()
    return f"   0: 1002000A:C738 {hexip}:{port:04X} {state} 00000000:00000000 00:00000000 00000000 {uid} 0 1 1"


class FakeEmulator:
    """Answers adb commands like a rooted API 30 emulator running a malicious booster app."""

    def __init__(self, serial="emulator-5554", devices=None, install_ok=True, launch_ok=True, rooted=True):
        self.serial, self.install_ok, self.launch_ok, self.rooted = serial, install_ok, launch_ok, rooted
        self.devices = devices if devices is not None else [(serial, "device")]
        self.calls: list[list[str]] = []
        self.shell_cmds: list[str] = []
        self.installed = False
        self.capture_path = None
        self.sms_rows = ["Row: 0 _id=1, address=555, date=1"]
        self.pm_ready = True

    def __call__(self, args, timeout_s=30, binary=False):
        self.calls.append(list(args))
        if args[1:] == ["devices"]:
            rows = "".join(f"{s}\t{st}\n" for s, st in self.devices)
            return 0, f"List of devices attached\n{rows}", ""
        if args[1:3] == ["-s", self.serial]:
            return self.device(args[3:], binary)
        return 1, "", "unexpected command"

    def device(self, a, binary):
        if a[0] == "shell":
            self.shell_cmds.append(a[1])
            return self.shell(a[1])
        if a[0] == "root":
            return 0, "restarting adbd as root", ""
        if a[0] == "wait-for-device":
            return 0, "", ""
        if a[0] == "install":
            self.installed = self.install_ok
            return (0, "Performing Streamed Install\nSuccess", "") if self.install_ok else \
                (1, "", "adb: failed to install: INSTALL_PARSE_FAILED_NO_CERTIFICATES")
        if a[0] == "uninstall":
            self.installed = False
            return 0, "Success", ""
        if a[:3] == ["emu", "network", "capture"]:
            if a[3] == "start":
                self.capture_path = a[4]
                with open(a[4], "wb") as fh:
                    fh.write(SAMPLE_PCAP)
            return 0, "OK", ""
        if a[:2] == ["exec-out", "screencap"]:
            return 0, b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, ""
        if a[:2] == ["logcat", "-d"]:
            return 0, ("1700000001.000  1000  1000 I ActivityManager: Start proc 4321:com.sample.booster/u0a153\n"
                       "1700000002.000  4321  4321 W booster: type=1400 audit(0.0:99): avc: denied { execute } for "
                       'name="su" dev="dm-0" ino=123 scontext=u:r:untrusted_app:s0:c153,c256,c512,c768 '
                       "tcontext=u:object_r:su_exec:s0 tclass=file permissive=0 app=com.sample.booster\n"), ""
        return 1, "", f"unknown {a}"

    def shell(self, cmd):
        props = {"getprop ro.kernel.qemu": "1" if self.serial.startswith("emulator-") else "",
                 "getprop ro.boot.qemu": "", "getprop sys.boot_completed": "1", "getprop ro.build.version.sdk": "30"}
        if cmd in props:
            return 0, props[cmd] + "\n", ""
        if cmd == dynamic.TRACE_START:
            return 0, "MT_TRACE_OK", ""
        if cmd == dynamic.TRACE_STOP:
            return 0, TRACE, ""
        if cmd == "id":
            return 0, "uid=0(root) gid=0(root)" if self.rooted else "uid=2000(shell)", ""
        if cmd == "pm path android":
            return (0, "package:/system/framework/framework-res.apk", "") if self.pm_ready else (255, "", "Can't find service: package")
        if cmd.startswith("pm path"):
            return (0, "package:/data/app/x/base.apk", "") if self.installed else (1, "", "")
        if cmd.startswith("dumpsys package"):
            return 0, (f"Packages:\n  Package [{PKG}] (abc):\n    userId={UID}\n"
                       "    User 0: installed=true hidden=false\n"
                       f"      disabledComponents:\n        {PKG}.MainActivity\n"
                       "      runtime permissions:\n"
                       "        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET ]\n"), ""
        if cmd.startswith("logcat -b all -c"):
            return 0, "", ""
        if cmd.startswith("am start"):
            return (0, "Status: ok\nActivity: x", "") if self.launch_ok else (0, "", "Error: Activity class does not exist")
        if cmd.startswith("monkey"):
            return (0, "Events injected: 1", "") if self.launch_ok else (252, "** No activities found to run, monkey aborted.", "")
        if cmd.startswith("am broadcast") or cmd.startswith("am startservice"):
            return 0, "Broadcast completed: result=0", ""
        if cmd.startswith("ps -A"):
            return 0, ("PID PPID UID NAME ARGS\n"
                       "1 0 0 init /system/bin/init\n"
                       f"4321 300 {UID} {PKG} {PKG}\n"
                       f"4400 4321 {UID} su su -c setenforce 0\n"
                       f"4410 4321 {UID} sh sh -c sleep 100\n"
                       "4500 400 2000 ps ps -A -o PID,PPID,UID,NAME,ARGS\n"), ""
        if cmd.startswith("for f in tcp"):
            return 0, ("## tcp\n  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"
                       + _proc_net_line("93.184.216.34", 443, UID) + "\n"
                       + _proc_net_line("8.8.8.8", 443, 10999) + "\n"
                       + _proc_net_line("0.0.0.0", 0, UID, "0A") + "\n## tcp6\n  sl\n## udp\n  sl\n## udp6\n  sl\n"), ""
        if cmd.startswith("find "):
            return 0, (f"/data/data/{PKG}/files/p.dex\n/data/data/{PKG}/shared_prefs/a.xml\n"), ""
        if cmd.startswith("content query"):
            return 0, "\n".join(self.sms_rows), ""
        return 1, "", f"unknown shell {cmd}"


def _ctx(tmp_path, fixture_apk, config=None, prior=None):
    return JobContext(apk_path=fixture_apk("signed_v1v2_ec.apk"), workspace=str(tmp_path),
                      prior=prior if prior is not None else {"static": STATIC, "tamper": {"suspicious_targets": []}},
                      config=config if config is not None else ENABLED)


@pytest.fixture
def emulator(monkeypatch):
    def install(**kw):
        fake = FakeEmulator(**kw)
        monkeypatch.setattr(dynamic, "_run", fake)
        monkeypatch.setattr(dynamic, "find_adb", lambda cfg: "adb")
        monkeypatch.setattr(dynamic.time, "sleep", lambda s: None)
        return fake
    return install


# ------------------------------------------------------------ gates --

def test_disabled_by_default(tmp_path, fixture_apk, emulator):
    fake = emulator()
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk, config={}))
    assert r["status"] == "partial" and [f["id"] for f in r["findings"]] == ["DYN_006"]
    assert fake.calls == []                                      # nothing touched a device
    assert (tmp_path / "dynamic" / "frida_hooks.js").exists()
    assert all(normalize(f, "dynamic")["points"] == 0 for f in r["findings"])


def test_without_device_degrades_to_partial(tmp_path, fixture_apk, emulator):
    emulator(devices=[("emulator-5554", "offline")])
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    assert r["status"] == "partial" and r["installed"] is False
    assert r["findings"][0]["id"] == "DYN_001"


def test_without_adb(tmp_path, fixture_apk, monkeypatch):
    monkeypatch.setattr(dynamic, "find_adb", lambda cfg: None)
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    assert r["findings"][0]["id"] == "DYN_001" and "adb was not found" in r["findings"][0]["evidence"]


def test_physical_device_is_refused(tmp_path, fixture_apk, emulator):
    fake = emulator(serial="R58M12ABCDE")
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    assert [f["id"] for f in r["findings"]] == ["DYN_007"]
    assert not any(c[3:4] == ["install"] for c in fake.calls)


def test_emulator_whose_system_is_not_ready(tmp_path, fixture_apk, emulator):
    fake = emulator()
    fake.pm_ready = False
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk, config={**ENABLED, "dynamic_ready_wait_s": 0}))
    assert [f["id"] for f in r["findings"]] == ["DYN_001"] and "not responding" in r["findings"][0]["evidence"]
    assert not any(c[3:4] == ["install"] for c in fake.calls)


def test_slow_emulator_cannot_silently_shrink_the_window(tmp_path, fixture_apk, emulator, monkeypatch):
    emulator()
    clock = iter(range(0, 10_000, 40))                       # every clock read: 40 s later
    monkeypatch.setattr(dynamic.time, "monotonic", lambda: next(clock))
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk, config={**ENABLED, "dynamic_observe_s": 20}))
    assert r["status"] == "partial" and "DYN_013" in {f["id"] for f in r["findings"]}


def test_busy_emulator_is_not_shared(tmp_path, fixture_apk, emulator):
    emulator()
    with dynamic._DEVICE_LOCK:
        r = dynamic.run("job", _ctx(tmp_path, fixture_apk, config={**ENABLED, "dynamic_timeout_s": 1}))
    assert r["findings"][-1]["id"] == "DYN_008" and r["installed"] is False


# --------------------------------------------------------- full run --

def test_full_run_observes_malicious_behaviour(tmp_path, fixture_apk, emulator):
    fake = emulator()
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    ids = {f["id"] for f in r["findings"]}
    assert r["status"] == "ok" and r["installed"] and r["launched"]
    assert r["emulator"] == {"avd": "mt_api30_root", "serial": "emulator-5554", "api_level": 30, "rooted": True}
    assert {"RUNTIME_PRIV_ESC", "RUNTIME_CODE_LOADED", "RUNTIME_HIDES_ICON", "RUNTIME_NETWORK", "DYN_000"} <= ids
    # the boot receiver was triggered, the non-exported service was not
    assert r["observation"]["triggers"] == [{"component": f"{PKG}.OnBoot",
                                              "action": "android.intent.action.BOOT_COMPLETED", "ok": True}]
    # kernel trace (with its PATH search de-duplicated) plus the long-lived child seen by ps
    assert [p["args"] for p in r["process_events"]] == ["su -c setenforce 0", "sh -c sleep 100"]
    assert r["observation"]["exec_trace"] is True
    # only the app's own socket, named from the DNS answer / TLS SNI in the capture
    assert r["network"] == [{"ts": 0.0, "proto": "tcp", "dst_ip": "93.184.216.34", "dst_port": 443,
                             "host": "c2.evil-boost.xyz", "sni": "c2.evil-boost.xyz", "bytes": 168,
                             "state": "ESTABLISHED"}]
    assert [d["query"] for d in r["dns"]] == ["c2.evil-boost.xyz"]
    assert set(r["timings_s"]) == {"connect", "install", "launch", "triggers", "observe", "collect"}
    assert r["logcat"]["su_attempts"] and r["runtime_permissions"][0]["name"] == "android.permission.READ_CONTACTS"
    assert r["artifacts"]["pcap"] == "dynamic/capture.pcap" and r["artifacts"]["screenshots"] == ["dynamic/screen.png"]
    assert os.path.isabs(fake.capture_path)
    assert fake.installed is False                            # uninstalled afterwards
    assert any(c[3:] == ["emu", "network", "capture", "stop"] for c in fake.calls)
    assert json.loads((tmp_path / "dynamic.json").read_text())["status"] == "ok"


def test_sms_sent_during_run(tmp_path, fixture_apk, emulator):
    fake = emulator()
    original = fake.shell

    def shell(cmd):
        if cmd.startswith("am broadcast"):        # the boot receiver sends a premium SMS
            fake.sms_rows.append("Row: 1 _id=2, address=90901, date=2")
        return original(cmd)
    fake.shell = shell
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    sms = [f for f in r["findings"] if f["id"] == "RUNTIME_SMS_SENT"]
    assert sms and sms[0]["evidence"] == "to 90901"


@pytest.mark.parametrize("kw,expected", [({"install_ok": False}, "DYN_003"), ({"launch_ok": False}, "DYN_005")])
def test_device_failures_are_operational(tmp_path, fixture_apk, emulator, kw, expected):
    emulator(**kw)
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    assert r["status"] == "partial" and expected in {f["id"] for f in r["findings"]}
    assert all(normalize(f, "dynamic")["points"] == 0 for f in r["findings"] if f["id"].startswith("DYN_"))


def test_unrooted_emulator_limits_observation(tmp_path, fixture_apk, emulator):
    fake = emulator(rooted=False)
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk))
    assert "DYN_011" in {f["id"] for f in r["findings"]} and r["file_ops"] == []
    assert not any(c.startswith("find ") or c.startswith("content query") for c in fake.shell_cmds)


@pytest.mark.security
def test_hostile_names_never_reach_the_device_shell(tmp_path, fixture_apk, emulator):
    fake = emulator()
    evil = {"package_name": "com.x; reboot", "component_details": []}
    r = dynamic.run("job", _ctx(tmp_path, fixture_apk, prior={"static": evil}))
    assert "DYN_004" in {f["id"] for f in r["findings"]}
    assert not any("reboot" in c for c in fake.shell_cmds)

    fake = emulator()
    sneaky = {**STATIC, "component_details": STATIC["component_details"] + [
        {"type": "receiver", "name": f"{PKG}.R", "exported_effective": True, "intent_actions": ["a;reboot"]},
        {"type": "receiver", "name": "x$(reboot)", "exported_effective": True, "intent_actions": ["a.b"]}]}
    dynamic.run("job", _ctx(tmp_path, fixture_apk, prior={"static": sneaky}))
    assert not any("reboot" in c for c in fake.shell_cmds)


# ------------------------------------------------- findings and score --

def test_runtime_findings_are_not_double_counted_with_static():
    static = normalize({"id": "STATIC_CMD_EXEC", "evidence": "Runtime.exec"}, "static")
    runtime = normalize({"id": "RUNTIME_CMD_EXEC", "evidence": "sh -c id"}, "dynamic")
    risk = score_findings([static, runtime])
    assert risk["score"] == 15 and len(risk["suppressed_duplicates"]) == 1


def test_privilege_escalation_raises_level():
    f = [normalize({"id": "RUNTIME_PRIV_ESC", "evidence": "su -c setenforce 0"}, "dynamic")]
    assert score_findings(f)["level"] in ("HIGH", "CRITICAL")


def test_behaviour_findings_mapping():
    obs = {"child_processes": [{"args": "/system/bin/sh -c id"}],
           "hooks": [{"api": "Runtime.exec", "args_sample": "su -c id"},
                     {"api": "InMemoryDexClassLoader", "args_sample": "<in-memory dex>"},
                     {"api": "SmsManager.sendTextMessage", "args_sample": "90901: SUB"}],
           "file_ops": [{"path": "/data/data/x/files/a.txt"}],
           "network": [{"proto": "tcp", "dst_ip": "1.2.3.4", "dst_port": 80, "host": ""}]}
    ids = [f["id"] for f in dynamic.behaviour_findings(obs)]
    assert ids == ["RUNTIME_PRIV_ESC", "RUNTIME_CMD_EXEC", "RUNTIME_CODE_LOADED", "RUNTIME_SMS_SENT",
                   "RUNTIME_CLEARTEXT", "RUNTIME_NETWORK"]
    assert dynamic.behaviour_findings({}) == []


# ------------------------------------------------------------ parsers --

def test_parse_proc_net_ipv4_and_ipv6():
    v4 = "sl\n" + _proc_net_line("93.184.216.34", 443, UID) + "\n" + _proc_net_line("127.0.0.1", 5037, UID)
    assert dynamic.parse_proc_net(v4, "tcp", UID) == [
        {"proto": "tcp", "dst_ip": "93.184.216.34", "dst_port": 443, "state": "ESTABLISHED"}]
    mapped = "0000000000000000FFFF0000" + ipaddress.IPv4Address("1.2.3.4").packed[::-1].hex().upper()
    v6 = f"sl\n   0: 00:0 {mapped}:0050 01 0:0 0:0 0 {UID} 0 1"
    assert dynamic.parse_proc_net(v6, "tcp6", UID)[0]["dst_ip"] == "1.2.3.4"
    assert dynamic.parse_proc_net("garbage\nnot a table", "udp", UID) == []


def test_parse_exec_trace_follows_the_app_process_tree():
    execs = dynamic.parse_exec_trace(TRACE, {4321})
    assert [(e["pid"], e["args"]) for e in execs] == [(4400, "su -c setenforce 0")]   # sh-7000 is not the app's
    assert dynamic.parse_exec_trace(TRACE, set()) == []
    assert dynamic.parse_exec_trace("garbage\n# comment\n", {1}) == []


def test_parse_ps_handles_user_names():
    rows = dynamic.parse_ps("PID PPID UID NAME ARGS\n10 1 u0_a153 com.x com.x\nbad line\n")
    assert rows == [{"pid": 10, "ppid": 1, "uid": 10153, "name": "com.x", "args": "com.x"}]


def test_parse_content_rows_and_logcat():
    rows = dynamic.parse_content_rows("Row: 0 _id=4, address=+1 555, date=9\nNo result found.")
    assert rows == [{"_id": "4", "address": "+1 555", "date": "9"}]
    log = ("E AndroidRuntime: FATAL EXCEPTION: main\nE AndroidRuntime: Process: com.x, PID: 1\n"
           "E AndroidRuntime: java.lang.RuntimeException\n")
    assert dynamic.parse_logcat(log, "com.x", None)["crashes"]
    assert not dynamic.parse_logcat(log, "com.y", None)["crashes"]


def test_parse_hooks_ignores_malformed_lines():
    out = ('[MT] {"api": "Runtime.exec", "args": "su", "ts": 1}\nnoise\n[MT] {not json\n[MT] ["list"]\n')
    assert dynamic.parse_hooks(out) == [{"ts": 1, "target": "", "api": "Runtime.exec", "args_sample": "su"}]


def test_command_timeouts_are_bounded(monkeypatch):
    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout"))
    monkeypatch.setattr(dynamic.subprocess, "run", slow)
    code, _, err = dynamic._run(["adb", "devices"], timeout_s=1)
    assert code == -1 and "timed out" in err


# --------------------------------------------------------------- pcap --

def test_pcap_summary_names_flows():
    s = pcap.summarize(pcap.read_pcap(SAMPLE_PCAP))
    assert s["dns"] == [{"ts": 1700000000.0, "query": "c2.evil-boost.xyz", "answers": ["93.184.216.34"]}]
    tls = [f for f in s["flows"] if f["dst_port"] == 443][0]
    assert tls["sni"] == tls["host"] == "c2.evil-boost.xyz" and tls["packets"] == 2


def test_pcap_http_host_and_raw_linktype():
    req = b"GET /a HTTP/1.1\r\nHost: Plain.Example\r\nAccept: */*\r\n\r\n"
    data = _pcap([_ipv4("10.0.2.16", "1.2.3.4", 6, _tcp(5000, 80, req))], linktype=101)
    flow = pcap.summarize(pcap.read_pcap(data))["flows"][0]
    assert flow["http_host"] == "plain.example" and flow["dst_port"] == 80


@pytest.mark.security
def test_pcap_reader_never_raises_on_garbage():
    rng = random.Random(1)
    valid = bytearray(SAMPLE_PCAP)
    for _ in range(300):
        blob = bytearray(valid)
        for _ in range(rng.randint(1, 20)):
            blob[rng.randrange(24, len(blob))] = rng.randrange(256)
        pcap.summarize(pcap.read_pcap(bytes(blob[:rng.randrange(24, len(blob) + 1)])))
    assert pcap.read_pcap(b"") == [] and pcap.read_pcap(b"\x00" * 64) == []
    loop = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + b"\xc0\x0c"   # self-referencing name pointer
    assert pcap.parse_dns(loop) is None


# --------------------------------------------------------------- Frida --

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
    code_only = script.replace(json.dumps(payload), '""')
    code_only = code_only.replace(json.dumps(payload.strip("L;").replace("/", ".")), '""')
    comment_free = "\n".join(line for line in code_only.splitlines() if not line.strip().startswith("//"))
    assert "pwned" not in comment_free and "second line" not in comment_free
    assert "Java.use('x')" not in comment_free
    for line in script.splitlines():
        if line.strip().startswith("//"):
            assert "*/" not in line


@pytest.mark.security
@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_frida_script_with_hostile_values_is_valid_javascript(tmp_path):
    script = dynamic.generate_frida_script([{"type": "url", "value": p} for p in INJECTIONS]
                                           + [{"type": "class", "value": p} for p in INJECTIONS], package="p'\"\n")
    path = tmp_path / "hooks.js"
    path.write_text(script, encoding="utf-8")
    result = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
