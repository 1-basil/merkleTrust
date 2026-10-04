# MerkleTrust — Emulator (dynamic) evaluation

Generated 2026-10-04T08:30:47+00:00 on Windows 11 (Python 3.14.7); emulator emulator-5554, Android API 30, rooted: True; observation window 20 s.
Produced by `python -m scripts.run_dynamic_evaluation`. Both columns are computed from the same engine reports; *with emulator* adds only the dynamic engine's findings.

**Disclosure:** the dynamic engine was finished after the held-out results of the static evaluation were known, so the held-out row is not an independent test of it.

## Install warning (risk HIGH/CRITICAL)

| Cases | n | Static only: TP / FP / TN / FN | With emulator: TP / FP / TN / FN |
|---|---|---|---|
| Development R* | 5 | 4 / 0 / 1 / 0 | 4 / 0 / 1 / 0 |
| Held-out H* | 7 | 3 / 1 / 2 / 1 | 4 / 1 / 2 / 0 |

## Per case

| ID | Case | Risky? | Static only | With emulator | Observed at runtime | Notes |
|---|---|---|---|---|---|---|
| R01 | Debuggable app with command execution, code loading and SMS sending | yes | CRITICAL (100) | CRITICAL (100) | RUNTIME_CMD_EXEC: id<br>RUNTIME_SMS_SENT: to +10000000000 | triggered: android.intent.action.BOOT_COMPLETED |
| R02 | Dropper: downloads and loads extra code | yes | HIGH (49) | HIGH (49) | nothing suspicious |  |
| R03 | Premium-SMS fraud on boot | yes | HIGH (66) | HIGH (66) | RUNTIME_SMS_SENT: to 90901 | triggered: android.intent.action.BOOT_COMPLETED |
| R04 | Spyware: identifiers, contacts, location, audio, command execution | yes | HIGH (68) | HIGH (68) | nothing suspicious |  |
| R05 | Benign app with debuggable/cleartext/backup enabled (should be review, not high risk) | no | MEDIUM (26) | MEDIUM (26) | nothing suspicious |  |
| H01 | Dropper using InMemoryDexClassLoader + HTTPS download | yes | HIGH (45) | HIGH (45) | nothing suspicious |  |
| H02 | SMS fraud triggered by incoming SMS (multipart send) | yes | HIGH (69) | HIGH (69) | RUNTIME_SMS_SENT: to 7726 | triggered: android.provider.Telephony.SMS_RECEIVED |
| H03 | Stalkerware: call log, location, phone number, hides its icon | yes | HIGH (55) | HIGH (55) | nothing suspicious |  |
| H04 | Runs 'su' to disable SELinux on boot | yes | MEDIUM (23) | HIGH (53) | RUNTIME_PRIV_ESC: su -c setenforce 0 | triggered: android.intent.action.BOOT_COMPLETED |
| H05 | Benign drawing app loading its own plugins (legitimate code loading) | no | HIGH (45) | HIGH (45) | nothing suspicious |  |
| H06 | Benign user-initiated SMS reminders | no | MEDIUM (28) | MEDIUM (28) | nothing suspicious |  |
| H07 | Benign fitness tracker with location | no | LOW (3) | LOW (3) | nothing suspicious |  |
