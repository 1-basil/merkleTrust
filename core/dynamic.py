"""core/dynamic.py — Dynamic analysis: what the app actually does when it runs.

Static analysis sees what an app *can* do. This engine installs the app in an
Android emulator, starts it, triggers the components the system would trigger
(boot and other broadcast receivers, exported services) and records what
happens during a fixed observation window:

    processes   every program the app (or its children) tried to execute — a
                kernel kprobe on execve plus fork events, so short-lived and
                *failed* attempts (``su`` refused by the kernel) are seen too —
                and longer-lived child processes from ``ps``
    network     the app's own sockets (``/proc/net/*``, filtered by its UID),
                named via DNS answers / TLS SNI from an emulator packet capture
    dns         DNS lookups in the capture (``adb emu network capture``)
    files       files the app created in its private and external storage
    sms         text messages sent while nobody touched the device
    icon        whether the app disabled its own launcher activity
    logcat      crashes and SELinux denials for the app's process
    hooks       optional Frida instrumentation (when ``frida`` and frida-server
                are available), driven by the tamper engine's suspicious targets

Observed behaviour becomes catalogued RUNTIME_* findings (core/findings.py) that
share their de-duplication group with the matching static finding, so "can run
commands" (static) and "ran a command" (runtime) count once. Problems running
the analysis itself are DYN_* findings with 0 risk points: a failure to analyse
is never turned into risk, and an app that does nothing suspicious during the
window is *not* proven benign (it may wait for a trigger the run did not give).

Safety rules:
  * disabled unless MERKLETRUST_DYNAMIC_ENABLED is set (it runs untrusted code);
  * emulators only — a physical phone is refused unless explicitly allowed,
    because the engine installs, grants permissions to and uninstalls apps;
  * one analysis at a time per process (the emulator is a shared resource);
  * every adb call is time-boxed; the whole run respects dynamic_timeout_s;
  * values taken from the APK (package, component and action names) are
    validated before they reach a device shell, and are emitted as JSON string
    literals in the generated Frida script.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from core import pcap
from core.contracts import JobContext, emit

log = logging.getLogger("merkletrust.dynamic")

DEFAULTS = {
    "dynamic_enabled": False,
    "dynamic_timeout_s": 120,
    "dynamic_observe_s": 20,
    "dynamic_device_wait_s": 10,
    "dynamic_ready_wait_s": 60,
    "dynamic_allow_physical": False,
    "emulator_avd": "mt_api30_root",
}
MAX_TRIGGERS = 10
COLLECT_RESERVE_S = 30      # time kept back for collecting results after the observation window
MAX_LOGCAT_BYTES = 5 * 1024 * 1024
CODE_EXTENSIONS = (".dex", ".jar", ".apk", ".so", ".odex", ".vdex", ".oat")

_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_COMPONENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z0-9_$]+)+$")
_ACTION = re.compile(r"^[A-Za-z0-9_.]+$")
_HOOK_PREFIX = "[MT] "

_DEVICE_LOCK = threading.Lock()


# ------------------------------------------------------------ processes --

def _run(args: list[str], timeout_s: float = 30, binary: bool = False) -> tuple[int, Any, str]:
    """Run a command with a timeout. Returns (returncode, stdout, stderr); never raises."""
    try:
        proc = subprocess.run(args, capture_output=True, timeout=max(1, timeout_s))
    except subprocess.TimeoutExpired:
        return -1, b"" if binary else "", f"timed out after {timeout_s:.0f}s: {' '.join(args[:4])}"
    except OSError as exc:
        return -1, b"" if binary else "", f"could not run {args[0]}: {exc}"
    err = proc.stderr.decode("utf-8", "replace").strip()
    return proc.returncode, proc.stdout if binary else proc.stdout.decode("utf-8", "replace"), err


def _sdk_tool(*parts: str) -> str | None:
    sdk = (os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
           or os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"))
    for suffix in ("", ".exe"):
        candidate = os.path.join(sdk, *parts) + suffix
        if os.path.isfile(candidate):
            return candidate
    return None


def find_adb(config: dict[str, Any]) -> str | None:
    """adb from config, PATH or the Android SDK."""
    configured = config.get("adb")
    if configured:
        return configured if os.path.isfile(configured) or shutil.which(configured) else None
    return shutil.which("adb") or _sdk_tool("platform-tools", "adb")


def find_aapt(config: dict[str, Any]) -> str | None:
    configured = config.get("aapt")
    if configured:
        return configured
    path = shutil.which("aapt")
    if path:
        return path
    sdk = (os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
           or os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"))
    bt = os.path.join(sdk, "build-tools")
    if os.path.isdir(bt):
        for version in sorted(os.listdir(bt), reverse=True):
            found = _sdk_tool("build-tools", version, "aapt")
            if found:
                return found
    return None


class Device:
    """One adb-connected device, addressed by serial."""

    def __init__(self, adb: str, serial: str):
        self.adb_path, self.serial = adb, serial

    def adb(self, *args: str, timeout_s: float = 30, binary: bool = False) -> tuple[int, Any, str]:
        return _run([self.adb_path, "-s", self.serial, *args], timeout_s, binary)

    def shell(self, command: str, timeout_s: float = 30) -> tuple[int, str, str]:
        return self.adb("shell", command, timeout_s=timeout_s)

    def prop(self, name: str) -> str:
        rc, out, _ = self.shell(f"getprop {name}", timeout_s=10)
        return out.strip() if rc == 0 else ""


# -------------------------------------------------------------- parsers --
# Pure functions over adb output, unit-tested with captured device output.

def parse_devices(out: str) -> list[tuple[str, str]]:
    """`adb devices` -> [(serial, state)]."""
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            rows.append((parts[0], parts[1]))
    return rows


def parse_ps(out: str) -> list[dict[str, Any]]:
    """`ps -A -o PID,PPID,UID,NAME,ARGS` -> [{pid, ppid, uid, name, args}]."""
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split(None, 4)
        if len(parts) < 4 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        uid = int(parts[2]) if parts[2].isdigit() else _uid_from_name(parts[2])
        rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "uid": uid, "name": parts[3],
                     "args": parts[4].strip() if len(parts) > 4 else parts[3]})
    return rows


def _uid_from_name(user: str) -> int | None:
    """u0_a153 -> 10153 (Android app user names)."""
    m = re.fullmatch(r"u(\d+)_a(\d+)", user)
    return int(m.group(1)) * 100000 + 10000 + int(m.group(2)) if m else None


def _hex_ip(value: str) -> str:
    raw = bytes.fromhex(value)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    addr = ipaddress.IPv6Address(words)
    return str(addr.ipv4_mapped) if addr.ipv4_mapped else str(addr)


_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
               "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN",
               "0B": "CLOSING"}


def parse_proc_net(text: str, proto: str, uid: int) -> list[dict[str, Any]]:
    """Remote endpoints of `uid`'s sockets from /proc/net/{tcp,tcp6,udp,udp6}."""
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8 or ":" not in parts[2]:
            continue
        try:
            if int(parts[7]) != uid:
                continue
            rip_hex, rport_hex = parts[2].split(":")
            rip, rport = _hex_ip(rip_hex), int(rport_hex, 16)
        except ValueError:
            continue
        addr = ipaddress.ip_address(rip)
        if rport == 0 or addr.is_unspecified or addr.is_loopback:
            continue
        state = _TCP_STATES.get(parts[3].upper(), parts[3]) if proto.startswith("tcp") else ""
        if state == "LISTEN":
            continue
        out.append({"proto": proto.rstrip("6"), "dst_ip": rip, "dst_port": rport, "state": state})
    return out


def parse_package_dump(text: str) -> dict[str, Any]:
    """`dumpsys package <pkg>` -> uid, runtime permissions, disabled components."""
    info: dict[str, Any] = {"uid": None, "runtime_permissions": [], "disabled_components": []}
    m = re.search(r"\buserId=(\d+)", text)
    if m:
        info["uid"] = int(m.group(1))
    section, section_indent = None, 0
    for line in text.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if section and (indent <= section_indent or not stripped):
            section = None
        if stripped in ("runtime permissions:", "disabledComponents:"):
            section, section_indent = stripped, indent
            continue
        if section == "runtime permissions:":
            pm = re.match(r"([\w.]+): granted=(true|false)", stripped)
            if pm and not any(p["name"] == pm.group(1) for p in info["runtime_permissions"]):
                info["runtime_permissions"].append({"name": pm.group(1), "granted": pm.group(2) == "true"})
        elif section == "disabledComponents:" and stripped not in info["disabled_components"]:
            info["disabled_components"].append(stripped)
    return info


def parse_content_rows(out: str) -> list[dict[str, str]]:
    """`content query` output ("Row: 0 _id=1, address=90901") -> [{column: value}]."""
    rows = []
    for line in out.splitlines():
        if not line.startswith("Row:"):
            continue
        body = line.split(" ", 2)[2] if line.count(" ") >= 2 else ""
        rows.append(dict(kv.split("=", 1) for kv in re.split(r", (?=\w+=)", body) if "=" in kv))
    return rows


def parse_logcat(text: str, package: str, uid: int | None) -> dict[str, list[str]]:
    """Crashes, SELinux denials and su attempts attributable to the app."""
    crashes, denials, su, pids = [], [], [], []
    lines = text.splitlines()
    start = re.compile(rf"Start proc (\d+):{re.escape(package)}[/:]")
    for i, line in enumerate(lines):
        m = start.search(line)
        if m:
            pids.append(int(m.group(1)))
        elif "FATAL EXCEPTION" in line:
            window = " ".join(lines[i:i + 3])
            if f"Process: {package}" in window:
                crashes.append(" | ".join(x.strip() for x in lines[i:i + 4])[:400])
        elif "avc: denied" in line and (f"app={package}" in line or (uid is not None and _selinux_categories(uid) in line)):
            denials.append(line.strip()[:400])
            if re.search(r'(name|path|comm)="?[^"\s]*\bsu"?(\s|$)', line) or "su_exec" in line:
                su.append(line.strip()[:400])
        elif package in line and re.search(r"\bsu\b.*(not allowed|denied|permission)", line, re.IGNORECASE):
            su.append(line.strip()[:400])
    return {"crashes": crashes, "denials": denials[:50], "su_attempts": su[:20], "pids": pids}


def _selinux_categories(uid: int) -> str:
    """MLS categories Android assigns to an app's processes (untrusted_app:s0:cA,cB)."""
    app_id = uid % 100000 - 10000
    return f":c{app_id & 0xFF},c{256 + ((app_id >> 8) & 0xFF)}"


# Kernel exec tracing (root). A kprobe on execve sees every exec *attempt* — also
# ones the kernel refuses, which never become a process that ps could list —
# and sched_process_fork links each process to its parent. Both are recorded in a
# private ftrace instance so Android's own tracing (perfetto) is not disturbed.
# The argument offsets are x86_64 pt_regs: rdi = filename, rsi = argv.
_TRACE = "/sys/kernel/tracing"
_TRACE_INSTANCE = f"{_TRACE}/instances/merkletrust"
_KPROBE = ("p:merkletrust/exec __x64_sys_execve path=+0(+112(%di)):string a1=+0(+8(+104(%di))):string "
           "a2=+0(+16(+104(%di))):string a3=+0(+24(+104(%di))):string a4=+0(+32(+104(%di))):string")
# Leftovers of an interrupted run are removed first (instance before probe: an
# enabled probe cannot be deleted).
TRACE_START = (f"rmdir {_TRACE_INSTANCE} 2>/dev/null; echo '-:merkletrust/exec' >> {_TRACE}/kprobe_events 2>/dev/null; "
               f"echo '{_KPROBE}' >> {_TRACE}/kprobe_events && mkdir {_TRACE_INSTANCE} && "
               f"echo 4096 > {_TRACE_INSTANCE}/buffer_size_kb && echo 1 > {_TRACE_INSTANCE}/options/record-tgid && "
               f"echo 1 > {_TRACE_INSTANCE}/events/merkletrust/exec/enable && "
               f"echo 1 > {_TRACE_INSTANCE}/events/sched/sched_process_fork/enable && "
               f"echo 1 > {_TRACE_INSTANCE}/tracing_on && echo MT_TRACE_OK")
TRACE_STOP = (f"echo 0 > {_TRACE_INSTANCE}/tracing_on; cat {_TRACE_INSTANCE}/trace; "
              f"echo 0 > {_TRACE_INSTANCE}/events/merkletrust/exec/enable; rmdir {_TRACE_INSTANCE}; "
              f"echo '-:merkletrust/exec' >> {_TRACE}/kprobe_events")
_TRACE_LINE = re.compile(r"^\s*(?P<comm>.+?)-(?P<pid>\d+)\s+\(\s*(?P<tgid>\d+|-+)\)\s+\[\d+\]\s+\S+\s+"
                         r"(?P<ts>\d+\.\d+):\s+(?P<event>\w+):\s+(?P<rest>.*)$")
_TRACE_FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse_exec_trace(text: str, app_pids: set[int]) -> list[dict[str, Any]]:
    """Exec attempts by the app's processes and all their descendants, in order."""
    family = set(app_pids)
    execs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        m = _TRACE_LINE.match(line)
        if not m:
            continue
        pid = int(m.group("pid"))
        tgid = int(m.group("tgid")) if m.group("tgid").isdigit() else pid
        fields = {k: v[1:-1] if v.startswith('"') else v for k, v in _TRACE_FIELD.findall(m.group("rest"))}
        if m.group("event") == "sched_process_fork":
            child = fields.get("child_pid", "")
            if (pid in family or tgid in family) and child.isdigit():
                family.add(int(child))
        elif m.group("event") == "exec" and (pid in family or tgid in family) and fields.get("path"):
            args = [fields[k] for k in ("a1", "a2", "a3", "a4") if fields.get(k) and fields[k] != "(fault)"]
            command = " ".join([os.path.basename(fields["path"]), *args])[:300]
            if command not in seen:          # a PATH search tries several directories for one command
                seen.add(command)
                execs.append({"ts": float(m.group("ts")), "event": "exec", "pid": pid, "path": fields["path"],
                              "name": os.path.basename(fields["path"]), "args": command})
            if len(execs) >= 200:
                break
    return execs


def parse_hooks(out: str) -> list[dict[str, Any]]:
    """Structured lines written by the generated Frida script."""
    hooks = []
    for line in out.splitlines():
        idx = line.find(_HOOK_PREFIX)
        if idx < 0:
            continue
        try:
            event = json.loads(line[idx + len(_HOOK_PREFIX):])
        except ValueError:
            continue
        if isinstance(event, dict) and isinstance(event.get("api"), str):
            hooks.append({"ts": event.get("ts"), "target": str(event.get("target", "")), "api": event["api"],
                          "args_sample": str(event.get("args", ""))[:300]})
    return hooks[:500]


# ----------------------------------------------------- Frida generation --

def _js(value: object) -> str:
    """A JavaScript string literal for untrusted text.

    Values here come from the uploaded APK (class names, URLs, component names),
    so they are emitted with JSON escaping — never pasted inside quotes — to
    prevent code injection into the generated instrumentation script.
    """
    return json.dumps(str(value))  # a JSON string is a valid JavaScript string literal


def _comment(value: object) -> str:
    """Single-line comment text: no line breaks or comment terminators can escape it."""
    return "".join(ch if ch.isprintable() else " " for ch in str(value)).replace("*/", "* /")[:200]


_FRIDA_PRELUDE = """\
Java.perform(function () {
    function report(api, args, target) {
        console.log('[MT] ' + JSON.stringify({ts: Date.now() / 1000, api: api, args: String(args), target: target || ''}));
    }
    function hook(cls, method, overload, api, describe) {
        try {
            var m = Java.use(cls)[method].overload.apply(Java.use(cls)[method], overload);
            m.implementation = function () {
                report(api, describe(arguments));
                return m.apply(this, arguments);
            };
        } catch (e) {}
    }
    var first = function (a) { return a[0]; };
    hook('java.lang.Runtime', 'exec', ['java.lang.String'], 'Runtime.exec', first);
    hook('java.lang.Runtime', 'exec', ['[Ljava.lang.String;'], 'Runtime.exec', function (a) { return a[0].join(' '); });
    hook('java.lang.ProcessBuilder', 'start', [], 'ProcessBuilder.start', function () { return ''; });
    hook('dalvik.system.DexClassLoader', '$init',
         ['java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'], 'DexClassLoader', first);
    hook('dalvik.system.InMemoryDexClassLoader', '$init', ['java.nio.ByteBuffer', 'java.lang.ClassLoader'],
         'InMemoryDexClassLoader', function () { return '<in-memory dex>'; });
    hook('android.telephony.SmsManager', 'sendTextMessage',
         ['java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent'],
         'SmsManager.sendTextMessage', function (a) { return a[0] + ': ' + a[2]; });
    hook('java.net.URL', '$init', ['java.lang.String'], 'URL', first);
    hook('javax.crypto.Cipher', 'getInstance', ['java.lang.String'], 'Cipher.getInstance', first);
"""


def generate_frida_script(targets: list[dict], package: str) -> str:
    """Frida instrumentation: a fixed set of security-relevant hooks plus targeted
    hooks from the tamper engine's suspicious_targets (APK-derived, untrusted)."""
    lines = ["// MerkleTrust dynamic instrumentation", f"// Target package: {_comment(package)}", _FRIDA_PRELUDE]
    for t in targets[:50]:
        kind, value = t.get("type"), t.get("value", "")
        if not value:
            continue
        if kind == "class":
            clean = str(value).strip("L;").replace("/", ".")
            lines += [f"    // Suspicious class {_comment(clean)}",
                      f"    try {{ Java.use({_js(clean)}); report('class-loaded', {_js(clean)}, {_js(clean)}); }} catch (e) {{}}"]
        elif kind == "service":
            lines += [f"    // Suspicious service {_comment(value)}",
                      "    hook('android.content.ContextWrapper', 'startService', ['android.content.Intent'],",
                      f"         'startService', function (a) {{ return a[0]; }});"]
        elif kind == "url":
            lines += [f"    // Suspicious URL / indicator {_comment(value)}",
                      "    try {",
                      "        var U = Java.use('java.net.URL'), init = U.$init.overload('java.lang.String');",
                      "        init.implementation = function (u) {",
                      f"            if (String(u).indexOf({_js(value)}) !== -1) {{ report('ioc-url', u, {_js(value)}); }}",
                      "            return init.call(this, u);",
                      "        };",
                      "    } catch (e) {}"]
    lines.append("});\n")
    return "\n".join(lines)


# ------------------------------------------------------- interpretation --

def _is_su(command: str) -> bool:
    first = command.strip().split(" ")[0] if command.strip() else ""
    return os.path.basename(first.strip("'\"")) == "su"


def behaviour_findings(obs: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn observations into catalogued RUNTIME_* findings (one per kind)."""
    findings: list[dict[str, Any]] = []

    def add(fid: str, evidence: list[str]) -> None:
        if evidence:
            uniq = list(dict.fromkeys(evidence))
            text = "; ".join(uniq[:5]) + (f" (+{len(uniq) - 5} more)" if len(uniq) > 5 else "")
            findings.append({"id": fid, "evidence": text[:600]})

    commands = [p["args"] for p in obs.get("child_processes", [])]
    commands += [h["args_sample"] for h in obs.get("hooks", []) if h["api"] in ("Runtime.exec", "ProcessBuilder.start")]
    su = [c for c in commands if _is_su(c)] + [f"SELinux: {d}" for d in obs.get("su_attempts", [])]
    add("RUNTIME_PRIV_ESC", su)
    add("RUNTIME_CMD_EXEC", [c for c in commands if c and not _is_su(c)])

    code = [f"wrote {f['path']}" for f in obs.get("file_ops", []) if f["path"].lower().endswith(CODE_EXTENSIONS)]
    code += [f"{h['api']}({h['args_sample']})" for h in obs.get("hooks", [])
             if h["api"] in ("DexClassLoader", "InMemoryDexClassLoader")]
    add("RUNTIME_CODE_LOADED", code)

    sms = [f"to {m.get('address', '?')}" for m in obs.get("sms_sent", [])]
    sms += [h["args_sample"] for h in obs.get("hooks", []) if h["api"] == "SmsManager.sendTextMessage"]
    add("RUNTIME_SMS_SENT", sms)

    add("RUNTIME_HIDES_ICON", [f"disabled {c}" for c in obs.get("icon_hidden", [])])

    net = obs.get("network", [])
    add("RUNTIME_CLEARTEXT", [f"http://{n['host'] or n['dst_ip']}:{n['dst_port']}" for n in net
                              if n["proto"] == "tcp" and n["dst_port"] == 80])
    add("RUNTIME_NETWORK", [f"{n['host'] or n['dst_ip']}:{n['dst_port']}/{n['proto']}" for n in net])
    return findings


# ------------------------------------------------------------- the run --

class _Run:
    """State of one dynamic analysis; methods are the steps of `run`."""

    def __init__(self, job_id: str, ctx: JobContext):
        self.job_id, self.ctx = job_id, ctx
        self.cfg = {**DEFAULTS, **{k: v for k, v in ctx.config.items() if v is not None}}
        self.start = time.monotonic()
        self.deadline = self.start + float(self.cfg["dynamic_timeout_s"])
        # Steps before the observation window may not eat into it or into collection.
        self.reserved = float(self.cfg["dynamic_observe_s"]) + COLLECT_RESERVE_S
        self.last_mark = self.start
        self.dir = ctx.subdir("dynamic")
        self.findings: list[dict[str, Any]] = []
        self.dev: Device | None = None
        self.package = ""
        self.uid: int | None = None
        self.capturing = False
        self.tracing = False
        self.report: dict[str, Any] = {
            "job_id": job_id, "engine": "dynamic", "status": "partial",
            "emulator": {"avd": self.cfg["emulator_avd"], "serial": "", "api_level": 0, "rooted": False},
            "package": "", "installed": False, "launched": False, "duration_s": 0,
            "observation": {"window_s": 0, "triggers": [], "capture": False, "exec_trace": False, "frida": False,
                            "root": False, "dns_unattributed": 0},
            "timings_s": {},
            "network": [], "dns": [], "file_ops": [], "process_events": [], "hooks": [],
            "runtime_permissions": [], "logcat": {"crashes": [], "denials": [], "su_attempts": []},
            "artifacts": {"pcap": None, "logcat": None, "frida_script": "dynamic/frida_hooks.js", "screenshots": []},
        }

    # -- helpers --
    def remaining(self, cap: float) -> float:
        """Timeout for a step before the observation window (keeps the reserve intact)."""
        return max(1.0, min(cap, self.deadline - self.reserved - time.monotonic()))

    def mark(self, step: str) -> None:
        now = time.monotonic()
        self.report["timings_s"][step] = round(now - self.last_mark, 1)
        self.last_mark = now

    def op(self, fid: str, severity: str, title: str, evidence: str) -> None:
        self.findings.append({"id": fid, "severity": severity, "title": title, "evidence": evidence[:400]})

    def finish(self) -> dict[str, Any]:
        self.report["duration_s"] = int(time.monotonic() - self.start)
        self.report["findings"] = self.findings
        return emit(self.ctx, "dynamic.json", self.report)

    # -- steps --
    def connect(self) -> bool:
        if not self.cfg["dynamic_enabled"]:
            self.op("DYN_006", "info", "Emulator analysis is switched off",
                    "Set MERKLETRUST_DYNAMIC_ENABLED=true and start an emulator to observe the app at runtime")
            return False
        adb = find_adb(self.cfg)
        if adb is None:
            self.op("DYN_001", "info", "No emulator available", "adb was not found (PATH, Android SDK or config)")
            return False
        wait_until = time.monotonic() + min(float(self.cfg["dynamic_device_wait_s"]), self.remaining(60))
        wanted = self.cfg.get("adb_serial")
        while True:
            rc, out, err = _run([adb, "devices"], timeout_s=10)
            ready = [s for s, state in parse_devices(out) if state == "device" and (not wanted or s == wanted)]
            if ready:
                self.dev = Device(adb, ready[0])
                break
            if time.monotonic() >= wait_until:
                self.op("DYN_001", "info", "No emulator available",
                        f"adb sees no ready device{f' {wanted}' if wanted else ''}: {(out or err).strip()[:200]}")
                return False
            time.sleep(1)
        emu = self.report["emulator"]
        emu["serial"] = self.dev.serial
        is_emulator = self.dev.serial.startswith("emulator-") or "1" in (self.dev.prop("ro.kernel.qemu"),
                                                                         self.dev.prop("ro.boot.qemu"))
        if not is_emulator and not self.cfg["dynamic_allow_physical"]:
            self.op("DYN_007", "info", "Refused to run on a physical device",
                    f"{self.dev.serial} is not an emulator; set dynamic_allow_physical to override")
            return False
        if self.dev.prop("sys.boot_completed") != "1":
            self.op("DYN_001", "info", "Emulator has not finished starting", f"{self.dev.serial}: sys.boot_completed != 1")
            return False
        sdk = self.dev.prop("ro.build.version.sdk")
        emu["api_level"] = int(sdk) if sdk.isdigit() else 0
        self.dev.adb("root", timeout_s=self.remaining(15))
        _run([adb, "-s", self.dev.serial, "wait-for-device"], timeout_s=self.remaining(15))
        rc, out, _ = self.dev.shell("id", timeout_s=10)
        emu["rooted"] = self.report["observation"]["root"] = rc == 0 and "uid=0" in out
        # boot_completed is set before the system is usable; a freshly booted (or
        # overloaded) emulator can still be restarting system_server.
        ready_until = time.monotonic() + min(float(self.cfg["dynamic_ready_wait_s"]), self.remaining(120))
        while "package:" not in self.dev.shell("pm path android", timeout_s=10)[1]:
            if time.monotonic() >= ready_until:
                self.op("DYN_001", "info", "Emulator is not ready",
                        f"{self.dev.serial}: the package manager is not responding (system still starting?)")
                return False
            time.sleep(2)
        if not emu["rooted"]:
            self.op("DYN_011", "info", "Limited observation (no root on the emulator)",
                    "Files written, SMS sent and boot broadcasts need a rooted (google_apis) emulator image")
        return True

    def resolve_package(self) -> bool:
        static = self.ctx.prior.get("static") or {}
        pkg = static.get("package_name") or ""
        if not pkg:
            aapt = find_aapt(self.cfg)
            if aapt:
                rc, out, _ = _run([aapt, "dump", "badging", self.ctx.apk_path], timeout_s=15)
                m = re.search(r"package: name='([^']+)'", out) if rc == 0 else None
                pkg = m.group(1) if m else ""
        if not _PACKAGE.match(pkg):
            self.op("DYN_004", "high", "Could not determine a valid package name", f"package name: {pkg[:100]!r}")
            return False
        self.package = self.report["package"] = pkg
        return True

    def install(self) -> bool:
        if not os.path.isfile(self.ctx.apk_path):
            self.op("DYN_002", "high", "APK file not found", self.ctx.apk_path)
            return False
        q = shlex.quote(self.package)
        rc, out, _ = self.dev.shell(f"pm path {q}", timeout_s=self.remaining(15))
        if out.strip().startswith("package:"):    # leftovers from an earlier run would pollute the observation
            self.dev.adb("uninstall", self.package, timeout_s=self.remaining(30))
        # -g grants every runtime permission so that permission-gated behaviour can be observed.
        rc, out, err = self.dev.adb("install", "-r", "-g", self.ctx.apk_path, timeout_s=self.remaining(90))
        detail = f"{out} {err}".strip()
        if rc != 0 or "Success" not in detail:
            self.op("DYN_003", "high", "The emulator refused to install the app", detail[-300:])
            return False
        self.report["installed"] = True
        dump = self.dev.shell(f"dumpsys package {q}", timeout_s=self.remaining(20))[1]
        self.uid = parse_package_dump(dump)["uid"]
        return True

    def start_capture(self) -> None:
        if not self.dev.serial.startswith("emulator-"):
            return
        path = os.path.abspath(os.path.join(self.dir, "capture.pcap"))
        rc, out, err = self.dev.adb("emu", "network", "capture", "start", path, timeout_s=10)
        if rc == 0 and "KO" not in out:
            self.capturing = self.report["observation"]["capture"] = True
            self.report["artifacts"]["pcap"] = "dynamic/capture.pcap"
        else:
            self.op("DYN_010", "info", "Network capture unavailable", (out or err).strip()[:200] or "emulator console refused")

    def start_trace(self) -> None:
        if self.report["observation"]["root"]:
            out = self.dev.shell(TRACE_START, timeout_s=15)[1]
            self.tracing = self.report["observation"]["exec_trace"] = "MT_TRACE_OK" in out
            if not self.tracing:
                self.op("DYN_014", "info", "Kernel exec tracing unavailable",
                        "kprobe on execve could not be installed; only processes visible to ps are reported")

    def stop_trace(self) -> str:
        if not self.tracing:
            return ""
        self.tracing = False
        return self.dev.shell(TRACE_STOP, timeout_s=30)[1]

    def stop_capture(self) -> None:
        if self.capturing:
            self.capturing = False
            self.dev.adb("emu", "network", "capture", "stop", timeout_s=10)

    def launch(self, frida_script: str) -> subprocess.Popen | None:
        """Start the app: under Frida when available, else via the launcher intent."""
        self.dev.shell("logcat -b all -c", timeout_s=10)
        frida = self.cfg.get("frida")
        if frida and (os.path.isfile(frida) or shutil.which(frida)):
            try:
                proc = subprocess.Popen([frida, "-D", self.dev.serial, "-f", self.package, "-l", frida_script, "-q",
                                         "-t", str(int(self.cfg["dynamic_observe_s"]))],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                self.report["observation"]["frida"] = True
                self.report["launched"] = True
                return proc
            except OSError as exc:
                self.op("DYN_012", "info", "Frida could not be started", str(exc))
        static = self.ctx.prior.get("static") or {}
        launcher = next((c["name"] for c in static.get("component_details", [])
                         if c.get("type") == "activity" and "android.intent.action.MAIN" in c.get("intent_actions", [])
                         and _COMPONENT.match(c.get("name", ""))), None)
        if launcher:
            rc, out, err = self.dev.shell(f"am start -W -n {shlex.quote(self.package + '/' + launcher)}",
                                          timeout_s=self.remaining(30))
            ok = rc == 0 and "Error" not in out + err
        else:
            ok = False
        if not ok:
            rc, out, err = self.dev.shell(f"monkey -p {shlex.quote(self.package)} -c android.intent.category.LAUNCHER 1",
                                          timeout_s=self.remaining(30))
            ok = rc == 0 and "No activities found" not in out + err and "aborted" not in out
        self.report["launched"] = ok
        if not ok:
            self.op("DYN_005", "medium", "The app could not be started", (out + " " + err).strip()[-300:])
        return None

    def trigger_components(self) -> None:
        """Send the broadcasts and service starts the system would send (boot, SMS, ...)."""
        static = self.ctx.prior.get("static") or {}
        triggers = self.report["observation"]["triggers"]
        for comp in static.get("component_details", []):
            if len(triggers) >= MAX_TRIGGERS or time.monotonic() > self.deadline - 10:
                break
            name = comp.get("name", "")
            if not comp.get("exported_effective") or not _COMPONENT.match(name):
                continue
            target = shlex.quote(f"{self.package}/{name}")
            if comp.get("type") == "receiver":
                for action in [a for a in comp.get("intent_actions", []) if _ACTION.match(a)][:3]:
                    rc, out, err = self.dev.shell(f"am broadcast -a {shlex.quote(action)} -n {target}", timeout_s=15)
                    triggers.append({"component": name, "action": action, "ok": rc == 0 and "Error" not in out + err})
            elif comp.get("type") == "service":
                rc, out, err = self.dev.shell(f"am startservice -n {target}", timeout_s=15)
                triggers.append({"component": name, "action": "startservice", "ok": rc == 0 and "Error" not in out + err})

    def sent_sms(self) -> list[dict[str, str]]:
        if not self.report["observation"]["root"]:
            return []
        rc, out, _ = self.dev.shell("content query --uri content://sms/sent --projection _id:address:date",
                                    timeout_s=15)
        return parse_content_rows(out) if rc == 0 else []

    def observe(self) -> dict[str, Any]:
        """Poll processes and sockets for the observation window."""
        wanted = float(self.cfg["dynamic_observe_s"])
        window = min(wanted, max(0.0, self.deadline - time.monotonic() - COLLECT_RESERVE_S))
        if window < 0.75 * wanted:
            self.op("DYN_013", "info", "Observation window cut short",
                    f"observed {window:.0f}s of {wanted:.0f}s: earlier steps used the time budget (slow emulator?)")
        end = time.monotonic() + window
        children: dict[int, dict[str, Any]] = {}
        all_app_pids: set[int] = set()
        sockets: dict[tuple, dict[str, Any]] = {}
        t0 = time.time()
        while True:
            now = round(time.time() - t0, 1)
            rc, out, _ = self.dev.shell("ps -A -o PID,PPID,UID,NAME,ARGS", timeout_s=10)
            procs = parse_ps(out) if rc == 0 else []
            app_pids = {p["pid"] for p in procs if p["uid"] == self.uid and p["name"].split(":")[0] == self.package}
            all_app_pids |= app_pids
            for p in procs:
                own = p["uid"] == self.uid and p["name"].split(":")[0] != self.package
                if (own or p["ppid"] in app_pids) and p["pid"] not in children and p["name"] != "ps":
                    children[p["pid"]] = {"ts": now, "event": "spawn", "pid": p["pid"], "ppid": p["ppid"],
                                          "name": p["name"], "args": p["args"][:300]}
            if self.uid is not None:
                rc, out, _ = self.dev.shell("for f in tcp tcp6 udp udp6; do echo \"## $f\"; cat /proc/net/$f; done",
                                            timeout_s=10)
                for block in out.split("## ")[1:]:
                    proto, _, body = block.partition("\n")
                    for s in parse_proc_net(body, proto.strip(), self.uid):
                        sockets.setdefault((s["proto"], s["dst_ip"], s["dst_port"]), {"ts": now, **s})
            if time.monotonic() >= end:
                break
            time.sleep(min(2.0, max(0.0, end - time.monotonic())))
        self.report["observation"]["window_s"] = round(window)
        return {"children": list(children.values()), "sockets": list(sockets.values()), "app_pids": all_app_pids}

    def collect(self, observed: dict[str, Any], sms_before: list[dict[str, str]], frida: subprocess.Popen | None) -> None:
        q = shlex.quote(self.package)
        rc, png, _ = self.dev.adb("exec-out", "screencap", "-p", timeout_s=15, binary=True)
        if rc == 0 and png[:8] == b"\x89PNG\r\n\x1a\n":
            with open(os.path.join(self.dir, "screen.png"), "wb") as fh:
                fh.write(png)
            self.report["artifacts"]["screenshots"].append("dynamic/screen.png")

        rc, text, _ = self.dev.adb("logcat", "-d", "-b", "all", "-v", "epoch", timeout_s=30)
        with open(os.path.join(self.dir, "logcat.txt"), "w", encoding="utf-8") as fh:
            fh.write(text[-MAX_LOGCAT_BYTES:])
        self.report["artifacts"]["logcat"] = "dynamic/logcat.txt"
        self.report["logcat"] = parse_logcat(text, self.package, self.uid)
        for crash in self.report["logcat"]["crashes"][:1]:
            self.op("DYN_009", "info", "The app crashed during the test", crash)

        hooks: list[dict[str, Any]] = []
        if frida is not None:
            try:
                out, _ = frida.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                frida.kill()
                out, _ = frida.communicate()
            hooks = parse_hooks(out.decode("utf-8", "replace"))
        self.report["hooks"] = hooks

        info = parse_package_dump(self.dev.shell(f"dumpsys package {q}", timeout_s=20)[1])
        self.report["runtime_permissions"] = info["runtime_permissions"]
        static = self.ctx.prior.get("static") or {}
        launchers = {c["name"] for c in static.get("component_details", [])
                     if "android.intent.action.MAIN" in c.get("intent_actions", [])}
        hidden = [c for c in info["disabled_components"] if c in launchers or c.replace("/", "") in launchers]

        files: list[dict[str, Any]] = []
        if self.report["observation"]["root"]:
            roots = " ".join(shlex.quote(p.format(self.package))
                             for p in ("/data/data/{}", "/data/user_de/0/{}", "/sdcard/Android/data/{}"))
            rc, out, _ = self.dev.shell(f"find {roots} -type f 2>/dev/null", timeout_s=20)
            files = [{"ts": None, "op": "created", "path": p.strip()} for p in out.splitlines() if p.strip()][:500]
        self.report["file_ops"] = files

        before = {r.get("_id") for r in sms_before}
        sms_sent = [r for r in self.sent_sms() if r.get("_id") not in before]

        names: dict[str, str] = {}
        flows: list[dict[str, Any]] = []
        if self.report["observation"]["capture"]:
            time.sleep(1)  # let the emulator flush the capture file
            try:
                with open(os.path.join(self.dir, "capture.pcap"), "rb") as fh:
                    summary = pcap.summarize(pcap.read_pcap(fh.read(64 * 1024 * 1024)))
                names, flows = summary["ip_names"], summary["flows"]
                app_ips = {s["dst_ip"] for s in observed["sockets"]}
                # The capture holds the whole emulator's traffic; keep the lookups that
                # resolved to an address the app itself connected to.
                own = [d for d in summary["dns"] if app_ips & set(d["answers"])]
                self.report["dns"] = own
                self.report["observation"]["dns_unattributed"] = len(summary["dns"]) - len(own)
            except OSError as exc:
                self.op("DYN_010", "info", "Network capture unavailable", f"capture file unreadable: {exc}")
        network = []
        for s in observed["sockets"]:
            flow = next((f for f in flows if f["dst_ip"] == s["dst_ip"] and f["dst_port"] == s["dst_port"]), {})
            network.append({"ts": s["ts"], "proto": s["proto"], "dst_ip": s["dst_ip"], "dst_port": s["dst_port"],
                            "host": flow.get("host") or names.get(s["dst_ip"], ""), "sni": flow.get("sni", ""),
                            "bytes": flow.get("bytes", 0), "state": s["state"]})
        self.report["network"] = network
        trace = self.stop_trace()
        app_pids = set(observed.get("app_pids", ())) | set(self.report["logcat"].pop("pids", []))
        execs = parse_exec_trace(trace, app_pids) if trace else []
        traced = {e["pid"] for e in execs}
        children = execs + [c for c in observed["children"] if c["pid"] not in traced]
        self.report["process_events"] = children

        self.findings += behaviour_findings({
            "child_processes": children, "hooks": hooks, "su_attempts": self.report["logcat"]["su_attempts"],
            "file_ops": files, "sms_sent": sms_sent, "icon_hidden": hidden, "network": network})

    def cleanup(self) -> None:
        if self.report["installed"] and not self.cfg.get("dynamic_keep_installed"):
            self.dev.adb("uninstall", self.package, timeout_s=30)


def run(job_id: str, ctx: JobContext) -> dict:
    r = _Run(job_id, ctx)
    static = ctx.prior.get("static") or {}
    targets = (ctx.prior.get("tamper") or {}).get("suspicious_targets") or []
    script_path = os.path.join(r.dir, "frida_hooks.js")
    with open(script_path, "w", encoding="utf-8") as fh:
        fh.write(generate_frida_script(targets, static.get("package_name", "")))

    if not r.connect():
        return r.finish()
    if not _DEVICE_LOCK.acquire(timeout=r.remaining(60)):
        r.op("DYN_008", "info", "The emulator is busy with another analysis", "timed out waiting for the device")
        return r.finish()
    try:
        r.mark("connect")
        if not r.resolve_package() or not r.install():
            return r.finish()
        r.mark("install")
        try:
            sms_before = r.sent_sms()
            r.start_capture()
            r.start_trace()
            frida = r.launch(script_path)
            r.mark("launch")
            observed = {"children": [], "sockets": [], "app_pids": set()}
            if r.report["launched"]:
                r.trigger_components()
                r.mark("triggers")
                observed = r.observe()
                r.mark("observe")
            r.stop_capture()
            r.collect(observed, sms_before, frida)
            r.mark("collect")
        finally:
            r.stop_trace()
            r.stop_capture()
            r.cleanup()
        complete = (r.report["installed"] and r.report["launched"]
                    and not any(f["id"] == "DYN_013" for f in r.findings))
        r.report["status"] = "ok" if complete else "partial"
        r.op("DYN_000", "info", "Emulator analysis completed" if complete else "Emulator analysis incomplete",
             f"package={r.package}, window={r.report['observation']['window_s']}s, "
             f"triggers={len(r.report['observation']['triggers'])}, capture={r.report['observation']['capture']}, "
             f"frida={r.report['observation']['frida']}")
        return r.finish()
    finally:
        _DEVICE_LOCK.release()


if __name__ == "__main__":
    import argparse

    from core import static as static_engine

    parser = argparse.ArgumentParser(description="MerkleTrust dynamic analysis of one APK on a running emulator")
    parser.add_argument("apk")
    parser.add_argument("--observe", type=int, default=DEFAULTS["dynamic_observe_s"], help="observation window (s)")
    parser.add_argument("--frida", default=None, help="path to the frida CLI (optional)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    workspace = tempfile.mkdtemp(prefix="mt_dynamic_")
    base = JobContext(apk_path=args.apk, workspace=workspace, prior={}, config={})
    prior = {"static": static_engine.run("local", base)}
    cfg = {"dynamic_enabled": True, "dynamic_observe_s": args.observe, "frida": args.frida}
    result = run("local", JobContext(apk_path=args.apk, workspace=workspace, prior=prior, config=cfg))
    print(json.dumps({k: v for k, v in result.items() if k != "job_id"}, indent=2))
    print(f"\nworkspace: {workspace}", file=sys.stderr)
