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


# ── Main engine ───────────────────────────────────────────────────────────────

def run(job_id: str, ctx: JobContext) -> dict:
    avd_name = ctx.config.get("emulator_avd", "mt_api30_root")
    timeout_s = ctx.config.get("dynamic_timeout_s", 90)
    start_time = time.time()

    findings = []

    # --- Create dynamic scratch directory ---
    dyn_dir = ctx.subdir("dynamic")

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
            "severity": "critical",
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
        # Phase 4+ will populate these:
        "network": [],
        "dns": [],
        "file_ops": [],
        "process_events": [],
        "hooks": [],
        "runtime_permissions": [],
        "artifacts": {
            "pcap": "dynamic/capture.pcap",
            "logcat": "dynamic/logcat.txt",
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
