"""core/dynamic.py — BHAVISH.

Dynamic Analysis Engine for MerkleTrust.

Phase 3: Emulator connection, APK installation, and APK launch.

The engine:
  - Connects to the configured AVD emulator via adb
  - Installs the APK from ctx.apk_path
  - Launches the APK using package/activity from ctx.prior["static"]
  - Falls back to aapt/monkey when static prior data is unavailable
  - Respects ctx.config["dynamic_timeout_s"] — never hangs the pipeline
  - Returns status "partial" on runtime problems with a DYN_xxx finding

Later phases will add:
  - logcat, pcap, DNS, file ops, process monitoring (Phase 4)
  - Frida hooks driven by suspicious_targets (Phase 5)
  - Stable findings for Trust Score (Phase 6)
  - Database integration (Phase 7)
"""

import sys
import os
import json
import time
import tempfile
import subprocess
import shutil

from core.contracts import JobContext, EngineError, emit


# ── ADB helpers ───────────────────────────────────────────────────────────────
# All adb interactions are timeboxed.  Every helper returns a result or raises
# on hard failures; soft failures are collected as findings by the caller.

def _run_cmd(args, timeout_s=30):
    """Run a command with a timeout. Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout_s}s: {' '.join(args)}"
    except FileNotFoundError:
        return -1, "", f"Command not found: {args[0]}"


def _adb(*args, timeout_s=30):
    """Convenience wrapper: adb <args>."""
    return _run_cmd(["adb"] + list(args), timeout_s=timeout_s)


def _find_aapt():
    """Locate aapt from PATH or the Android SDK build-tools directory.

    Returns the path to aapt/aapt.exe if found, or None.
    """
    # 1. Check PATH
    path = shutil.which("aapt")
    if path:
        return path

    # 2. Search SDK build-tools (same SDK resolution as setup_avd.ps1)
    sdk_root = (os.environ.get("ANDROID_HOME")
                or os.environ.get("ANDROID_SDK_ROOT")
                or os.path.join(os.environ.get("LOCALAPPDATA", ""),
                                "Android", "Sdk"))
    bt_dir = os.path.join(sdk_root, "build-tools")
    if os.path.isdir(bt_dir):
        # Pick the highest version directory
        versions = sorted(os.listdir(bt_dir), reverse=True)
        for ver in versions:
            candidate = os.path.join(bt_dir, ver, "aapt")
            # On Windows, try .exe
            if os.path.isfile(candidate):
                return candidate
            if os.path.isfile(candidate + ".exe"):
                return candidate + ".exe"
    return None


def _wait_for_device(timeout_s):
    """Wait until adb sees a device/emulator. Returns True if connected."""
    if shutil.which("adb") is None:
        return False
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        rc, out, _ = _adb("devices")
        if rc == 0:
            # Parse 'adb devices' output — lines after header like
            # "emulator-5554\tdevice"
            lines = [l for l in out.splitlines()[1:] if "\tdevice" in l]
            if lines:
                return True
        time.sleep(2)
    return False


def _get_emulator_info():
    """Query the connected emulator for api_level and root status."""
    api_level = 0
    rooted = False

    rc, out, _ = _adb("shell", "getprop", "ro.build.version.sdk")
    if rc == 0 and out.strip().isdigit():
        api_level = int(out.strip())

    # Try adb root — on userdebug/eng builds this enables root shell
    rc, out, _ = _adb("root")
    if rc == 0:
        # Verify uid=0
        rc2, id_out, _ = _adb("shell", "id")
        if rc2 == 0 and "uid=0" in id_out:
            rooted = True

    return api_level, rooted


def _install_apk(apk_path, timeout_s=60):
    """Install an APK via adb install -r. Returns (success, detail)."""
    rc, out, err = _adb("install", "-r", apk_path, timeout_s=timeout_s)
    combined = f"{out} {err}".strip()
    if rc == 0 and "Success" in combined:
        return True, combined
    return False, combined


def _resolve_package_name(ctx):
    """Determine the package name to launch.

    Priority (per the contract):
      1. ctx.prior["static"]["package_name"] — from Ashwini's static engine
      2. aapt dump badging — local fallback for standalone testing

    Returns (package_name, source) or ("", None) if undetermined.
    """
    # 1. From prior static analysis
    static = ctx.prior.get("static", {})
    pkg = static.get("package_name", "")
    if pkg and pkg != "com.example.stub":
        return pkg, "prior:static"

    # 2. Fallback: aapt dump badging
    aapt_cmd = ctx.config.get("aapt") or _find_aapt()
    if not aapt_cmd:
        return "", None
    rc, out, _ = _run_cmd([aapt_cmd, "dump", "badging", ctx.apk_path], timeout_s=15)
    if rc == 0:
        for line in out.splitlines():
            if line.startswith("package:"):
                # parse: package: name='com.example.app' ...
                for part in line.split():
                    if part.startswith("name='"):
                        pkg = part.split("'")[1]
                        if pkg:
                            return pkg, "aapt"
    return "", None


def _resolve_launch_activity(ctx, package):
    """Determine the activity to launch.

    Priority (per the contract):
      1. ctx.prior["static"]["components"]["activities"][0]
      2. aapt dump badging launchable-activity

    Returns (activity_fqn, source) or ("", None).
    """
    # 1. From prior static analysis
    static = ctx.prior.get("static", {})
    components = static.get("components", {})
    activities = components.get("activities", [])
    if activities and activities[0]:
        activity = activities[0]
        # Ensure fully qualified (contains '.')
        if "." in activity:
            return activity, "prior:static"

    # 2. Fallback: aapt dump badging
    aapt_cmd = ctx.config.get("aapt") or _find_aapt()
    if not aapt_cmd:
        return "", None
    rc, out, _ = _run_cmd([aapt_cmd, "dump", "badging", ctx.apk_path], timeout_s=15)
    if rc == 0:
        for line in out.splitlines():
            if line.startswith("launchable-activity:"):
                for part in line.split():
                    if part.startswith("name='"):
                        activity = part.split("'")[1]
                        if activity:
                            return activity, "aapt"
    return "", None


def _launch_app(package, activity=None, timeout_s=15):
    """Launch the app. Uses am start if activity is known, else monkey.

    Returns (success, method, detail).
    """
    if activity:
        # am start -n package/activity
        component = f"{package}/{activity}"
        rc, out, err = _adb("shell", "am", "start", "-n", component,
                            timeout_s=timeout_s)
        combined = f"{out} {err}".strip()
        if rc == 0 and "Error" not in combined:
            return True, "am_start", combined
        # am start failed — fall through to monkey
        am_err = combined
    else:
        am_err = None

    # Fallback: monkey sends a single launch intent
    rc, out, err = _adb("shell", "monkey", "-p", package, "1",
                        timeout_s=timeout_s)
    combined = f"{out} {err}".strip()
    if rc == 0:
        return True, "monkey", combined

    detail = combined
    if am_err:
        detail = f"am_start failed: {am_err}; monkey failed: {combined}"
    return False, "failed", detail


def _capture_logcat(dyn_dir, duration_s=6):
    """Clear logcat, let the app run for `duration_s`, then dump the buffer.

    Returns (logcat_text, process_events) where process_events is a light
    filter of lifecycle/crash lines — not a full parser, just enough to show
    the app actually did something during the window.
    """
    _adb("logcat", "-c", timeout_s=10)
    time.sleep(duration_s)
    rc, out, _ = _adb("logcat", "-d", "-v", "time", timeout_s=20)
    text = out if rc == 0 else ""
    events = [{"line": line.strip()[:300]} for line in text.splitlines()
              if any(tag in line for tag in ("ActivityManager", "AndroidRuntime", "Process", "FATAL"))][:50]
    return text, events


def _attach_frida(package, script_code, duration_s=6):
    """Attach Frida to the already-running process and collect console.log
    messages from the generated hook script for `duration_s` seconds.

    Frida's by-name attach matches the app's display label (e.g. "Hotel
    Booking"), not its Android package name, so the target PID is resolved
    via `adb shell pidof` first.

    Best-effort: any failure (bindings missing, attach refused, app not
    instrumentable) is reported as a reason string, never raised.
    """
    try:
        import frida
    except ImportError:
        return [], "frida Python bindings not installed"

    rc, out, _ = _adb("shell", "pidof", "-s", package, timeout_s=10)
    if rc != 0 or not out.strip().isdigit():
        return [], f"could not resolve a PID for package {package!r} via pidof"
    pid = int(out.strip())

    messages: list[str] = []

    def on_message(message, _data):
        kind = message.get("type")
        if kind == "send":
            messages.append(str(message.get("payload")))
        elif kind == "log":
            messages.append(str(message.get("payload")))
        elif kind == "error":
            messages.append(f"[frida-error] {message.get('description')}")

    try:
        device = frida.get_usb_device(timeout=5)
        session = device.attach(pid)
        script = session.create_script(script_code)
        script.on("message", on_message)
        script.load()
        time.sleep(duration_s)
        session.detach()
    except Exception as exc:
        return messages, f"frida attach failed: {exc}"
    return messages, None


def generate_frida_script(targets: list[dict], package: str) -> str:
    """Generate a dynamic Frida instrumentation script driven by suspicious_targets."""
    lines = [
        "// MerkleTrust Dynamic Frida Instrumentation Script",
        f"// Target Package: {package}",
        "Java.perform(function() {",
        "    console.log('[MerkleTrust] Hooking engine initialized for " + "package: " + package + "');",
        "",
        "    // Default security API monitoring",
        "    try {",
        "        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');",
        "        DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(a, b, c, d) {",
        "            console.log('[HOOK] DexClassLoader: ' + a);",
        "            return this.$init(a, b, c, d);",
        "        };",
        "    } catch(e) {}",
        "",
        "    try {",
        "        var Runtime = Java.use('java.lang.Runtime');",
        "        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {",
        "            console.log('[HOOK] Runtime.exec: ' + cmd);",
        "            return this.exec(cmd);",
        "        };",
        "    } catch(e) {}",
        "",
        "    try {",
        "        var Cipher = Java.use('javax.crypto.Cipher');",
        "        Cipher.getInstance.overload('java.lang.String').implementation = function(trans) {",
        "            console.log('[HOOK] Cipher algorithm: ' + trans);",
        "            return this.getInstance(trans);",
        "        };",
        "    } catch(e) {}",
        "",
    ]

    # Add custom hooks from tamper.suspicious_targets
    for t in targets:
        t_type = t.get("type")
        val = t.get("value", "")
        if t_type == "class" and val:
            clean_class = val.strip("L;").replace("/", ".")
            lines.extend([
                f"    // Targeted Hook: Suspicious Class {clean_class}",
                "    try {",
                f"        var TargetCls = Java.use('{clean_class}');",
                "        console.log('[HOOK TARGET] Attached to class: " + clean_class + "');",
                "    } catch(e) {}",
            ])
        elif t_type == "service" and val:
            lines.extend([
                f"    // Targeted Hook: Suspicious Service {val}",
                "    try {",
                "        var ContextWrapper = Java.use('android.content.ContextWrapper');",
                "        ContextWrapper.startService.implementation = function(intent) {",
                f"            console.log('[HOOK TARGET] startService invoked for target {val}: ' + intent);",
                "            return this.startService(intent);",
                "        };",
                "    } catch(e) {}",
            ])
        elif t_type == "url" and val:
            lines.extend([
                f"    // Targeted Hook: Suspicious URL / IOC {val}",
                "    try {",
                "        var URL = Java.use('java.net.URL');",
                "        URL.$init.overload('java.lang.String').implementation = function(u) {",
                f"            if (u.indexOf('{val}') !== -1) {{",
                f"                console.log('[HOOK ALERT] Network connection to suspicious IOC: {val}');",
                "            }",
                "            return this.$init(u);",
                "        };",
                "    } catch(e) {}",
            ])

    lines.append("});\n")
    return "\n".join(lines)


# ── Main engine ───────────────────────────────────────────────────────────────

def run(job_id: str, ctx: JobContext) -> dict:
    avd_name = ctx.config.get("emulator_avd", "mt_api30_root")
    timeout_s = ctx.config.get("dynamic_timeout_s", 90)
    start_time = time.time()

    findings = []

    # Read upstream suspicious_targets for Frida hook generation
    tamper = ctx.prior.get("tamper", {})
    targets = tamper.get("suspicious_targets", [])
    static = ctx.prior.get("static", {})
    package_hint = static.get("package_name", "")

    # --- Create dynamic scratch directory and artifact files ---
    dyn_dir = ctx.subdir("dynamic")
    pcap_path = os.path.join(dyn_dir, "capture.pcap")
    logcat_path = os.path.join(dyn_dir, "logcat.txt")
    frida_script_path = os.path.join(dyn_dir, "frida_hooks.js")

    if not os.path.exists(pcap_path):
        with open(pcap_path, "wb") as pf:
            pass
    if not os.path.exists(logcat_path):
        with open(logcat_path, "w", encoding="utf-8") as lf:
            pass

    # Generate and persist Frida dynamic hooks
    frida_code = generate_frida_script(targets, package_hint)
    with open(frida_script_path, "w", encoding="utf-8") as fs:
        fs.write(frida_code)

    # --- Emulator info (defaults until connected) ---
    emu_api_level = 0
    emu_rooted = False
    installed = False
    launched = False

    # --- Step 1: Wait for emulator / adb connection ---
    # The emulator is expected to be already running (started by the user or
    # the orchestrator). We wait up to a fraction of the timeout for adb to
    # see a device.
    device_wait = min(timeout_s // 3, 30)
    device_connected = _wait_for_device(device_wait)

    if not device_connected:
        findings.append({
            "id": "DYN_001",
            "severity": "info",
            "title": "No emulator/device connected via adb",
            "evidence": f"adb devices returned no connected device after {device_wait}s",
        })
        # Cannot continue — return partial
        elapsed = int(time.time() - start_time)
        return emit(ctx, "dynamic.json", {
            "job_id": job_id,
            "engine": "dynamic",
            "status": "partial",
            "findings": findings,
            "emulator": {"avd": avd_name, "api_level": 0, "rooted": False},
            "installed": False,
            "launched": False,
            "duration_s": elapsed,
            "network": [],
            "dns": [],
            "file_ops": [],
            "process_events": [],
            "hooks": [],
            "runtime_permissions": [],
            "artifacts": {"pcap": "dynamic/capture.pcap",
                          "logcat": "dynamic/logcat.txt",
                          "frida_script": "dynamic/frida_hooks.js",
                          "screenshots": []},
        })

    # --- Step 2: Query emulator properties ---
    emu_api_level, emu_rooted = _get_emulator_info()

    # --- Step 3: Install APK ---
    if not os.path.isfile(ctx.apk_path):
        findings.append({
            "id": "DYN_002",
            "severity": "critical",
            "title": "APK file not found",
            "evidence": f"ctx.apk_path = {ctx.apk_path}",
        })
    else:
        install_timeout = min(timeout_s // 2, 60)
        installed, install_detail = _install_apk(ctx.apk_path,
                                                 timeout_s=install_timeout)
        if not installed:
            findings.append({
                "id": "DYN_003",
                "severity": "high",
                "title": "APK installation failed",
                "evidence": install_detail[:300],
            })

    # --- Step 4: Determine package name ---
    package, pkg_source = _resolve_package_name(ctx)
    if not package:
        findings.append({
            "id": "DYN_004",
            "severity": "high",
            "title": "Could not determine package name",
            "evidence": "Neither ctx.prior['static'] nor aapt provided a package name",
        })

    # --- Step 5: Launch the app ---
    if installed and package:
        activity, act_source = _resolve_launch_activity(ctx, package)
        launched, launch_method, launch_detail = _launch_app(
            package, activity,
            timeout_s=min(timeout_s // 4, 15),
        )
        if not launched:
            findings.append({
                "id": "DYN_005",
                "severity": "medium",
                "title": "APK launch failed",
                "evidence": launch_detail[:300],
            })
    elif installed and not package:
        # Installed but can't determine what to launch
        launch_method = "skipped"
    else:
        # Not installed — can't launch
        launch_method = "skipped"

    # --- Step 6: Runtime capture (logcat + Frida), only if the app is actually
    # running. Timeboxed against whatever remains of dynamic_timeout_s so a
    # slow capture window can never make the pipeline hang.
    logcat_text, process_events, hooks = "", [], []
    frida_note = None
    if launched:
        remaining = timeout_s - (time.time() - start_time)
        capture_s = max(0, min(6, int(remaining // 2)))
        if capture_s > 0:
            logcat_text, process_events = _capture_logcat(dyn_dir, duration_s=capture_s)
            hooks, frida_note = _attach_frida(package, frida_code, duration_s=capture_s)
            if frida_note:
                findings.append({
                    "id": "DYN_006",
                    "severity": "info",
                    "title": "Frida instrumentation did not attach",
                    "evidence": frida_note,
                })
            elif hooks:
                findings.append({
                    "id": "DYN_007",
                    "severity": "info",
                    "title": f"Frida hooks observed {len(hooks)} event(s) during the capture window",
                    "evidence": "; ".join(hooks[:5])[:300],
                })

    with open(logcat_path, "w", encoding="utf-8") as lf:
        lf.write(logcat_text)
    if not os.path.exists(pcap_path):
        with open(pcap_path, "wb"):
            pass

    # --- Build the report ---
    elapsed = int(time.time() - start_time)

    status = "ok" if (installed and launched and not findings) else "partial"

    report = {
        "job_id": job_id,
        "engine": "dynamic",
        "status": status,
        "findings": findings or [{
            "id": "DYN_000",
            "severity": "info",
            "title": "Dynamic analysis: install and launch completed",
            "evidence": f"package={package}, method={launch_method}",
        }],
        "emulator": {
            "avd": avd_name,
            "api_level": emu_api_level,
            "rooted": emu_rooted,
        },
        "installed": installed,
        "launched": launched,
        "duration_s": elapsed,
        # Not implemented: packet capture requires pushing a tcpdump binary
        # onto the emulator, which this engine does not do.
        "network": [],
        "dns": [],
        "file_ops": [],
        "process_events": process_events,
        "hooks": hooks,
        "runtime_permissions": [],
        "artifacts": {
            "pcap": "dynamic/capture.pcap",
            "logcat": "dynamic/logcat.txt",
            "frida_script": "dynamic/frida_hooks.js",
            "screenshots": [],
        },
    }
    return emit(ctx, "dynamic.json", report)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MerkleTrust Dynamic Analysis Engine")
    parser.add_argument("--apk", required=True, help="Path to the APK file")
    parser.add_argument("--workspace", default=None,
                        help="Job workspace directory (default: auto-created temp dir)")
    parser.add_argument("--prior", default=None,
                        help="Path to prior.json with upstream engine results")
    args = parser.parse_args()

    workspace = args.workspace or tempfile.mkdtemp(prefix="mt_")
    os.makedirs(workspace, exist_ok=True)
    prior = json.load(open(args.prior, encoding="utf-8")) if args.prior else {}
    ctx = JobContext(apk_path=args.apk, workspace=workspace, prior=prior,
                     config={"emulator_avd": "mt_api30_root", "dynamic_timeout_s": 90})
    result = run("local-test", ctx)
    print(json.dumps(result, indent=2))
    print(f"\nwrote: {ctx.out('dynamic.json')}")
