"""core/dynamic.py — BHAVISH.

Runs last in the parallel phase. Reads static + tamper, never reads integrity.

TODO for Bhavish:
  1. boot the AVD named ctx.config["emulator_avd"], wait for sys.boot_completed
  2. `adb install -r <apk>`; record installed=True/False
  3. start capture BEFORE launching:
       - tcpdump on the emulator (or -tcpdump flag) -> dynamic/capture.pcap
       - `adb logcat -c` then `adb logcat -v time` to dynamic/logcat.txt
  4. `adb shell monkey -p <package> 1` or `am start -n <package>/<activity>`
     activity comes from static.components.activities[0]
  5. attach Frida. Build the hook list from tamper.suspicious_targets:
       type "class"   -> Java.use(value), hook every method
       type "service" -> hook Context.startService
       type "url"     -> hook URL / OkHttp and match on value
     If suspicious_targets is EMPTY, fall back to a default hook set
     (crypto, DexClassLoader, Runtime.exec, getDeviceId, SmsManager).
  6. stop after ctx.config["dynamic_timeout_s"], kill the app, pull artifacts
  7. parse the pcap into network[] and dns[]; parse logcat into process_events[]

  Never let a dead emulator hang the pipeline. Wrap everything in a timeout
  and return status "partial" with a finding instead of raising.
"""

import sys
import json
import tempfile

from core.contracts import JobContext, emit


def run(job_id: str, ctx: JobContext) -> dict:
    static = ctx.prior.get("static", {})
    tamper = ctx.prior.get("tamper", {})
    targets = tamper.get("suspicious_targets", [])
    package = static.get("package_name", "")

    # TODO(bhavish): emulator, install, launch, capture, frida
    report = {
        "job_id": job_id,
        "engine": "dynamic",
        "status": "partial",
        "findings": [{
            "id": "DYNAMIC_STUB",
            "severity": "info",
            "title": "Dynamic engine not implemented yet",
            "evidence": f"package {package or '?'}, {len(targets)} hook targets",
        }],
        "emulator": {
            "avd": ctx.config.get("emulator_avd", ""),
            "api_level": 0,
            "rooted": False,
        },
        "installed": False,
        "launched": False,
        "duration_s": 0,
        "network": [],
        "dns": [],
        "file_ops": [],
        "process_events": [],
        "hooks": [],
        "runtime_permissions": [],
        "artifacts": {"pcap": "dynamic/capture.pcap", "logcat": "dynamic/logcat.txt"},
    }
    return emit(ctx, "dynamic.json", report)


if __name__ == "__main__":
    apk = sys.argv[1]
    prior = json.load(open(sys.argv[2], encoding="utf-8")) if len(sys.argv) > 2 else {}
    ctx = JobContext(apk_path=apk, workspace=tempfile.mkdtemp(prefix="mt_"), prior=prior,
                     config={"emulator_avd": "mt_api30_root", "dynamic_timeout_s": 90})
    print(json.dumps(run("local-test", ctx), indent=2))
