# MerkleTrust — Real-world apps (F-Droid)

Generated 2026-10-09T02:02:00+00:00 by `python -m scripts.run_realworld_evaluation` (Python 3.14.7).
Three open-source apps were downloaded from f-droid.org and verified against the SHA-256 pinned from F-Droid's
repository index. Each official app was enrolled as the trusted baseline; attack variants were built with zip
operations and apksigner only (no app was installed or run). Ground truth is fixed in the script before scanning.
DEX files up to 16 MB were fuzzy-hashed for this run (the default limit is 4 MB).

| App | Official signer matches F-Droid | Enrol time |
|---|---|---|
| `net.gsantner.markor` | yes | 12569 ms |
| `org.fossify.notes` | yes | 3708 ms |
| `de.danoeh.antennapod` | yes | 12256 ms |

C2 address used in `code_c2_swap`: `151.243.126.22:9443` — CraxsRAT, ThreatFox record #1956999, first seen 2026-10-08 06:26:07 (feed updated 2026-10-08 07:40:22 UTC).

| App | Variant | Integrity | Signed by someone else? | Changed files | Code similarity (ssdeep) | Threat feed | Risk | Time | As expected |
|---|---|---|---|---|---|---|---|---|---|
| `net.gsantner.markor` | official_copy | CLEAN | no (verified) | none | — | — | MEDIUM (37) | 14418 ms | ✓ |
| `net.gsantner.markor` | payload_resigned | CERTIFICATE_CHANGED | yes (verified) | added: assets/merkletrust_eval_payload.bin | — | — | CRITICAL (87) | 12417 ms | ✓ |
| `net.gsantner.markor` | code_endpoint_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex | classes.dex 96% (NEAR_DUPLICATE) | — | CRITICAL (100) | 10662 ms | ✓ |
| `net.gsantner.markor` | code_c2_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex | classes.dex 96% (NEAR_DUPLICATE) | 151.243.126.22:9443 (#1956999 CraxsRAT); 151.243.126.22 (#1956999 CraxsRAT) | CRITICAL (100) | 12395 ms | ✓ |
| `net.gsantner.markor` | signature_stripped | CERTIFICATE_CHANGED | yes (unsigned) | none | — | — | CRITICAL (77) | 8151 ms | ✓ |
| `org.fossify.notes` | official_copy | CLEAN | no (verified) | none | — | — | MEDIUM (30) | 3839 ms | ✓ |
| `org.fossify.notes` | payload_resigned | CERTIFICATE_CHANGED | yes (verified) | added: assets/merkletrust_eval_payload.bin | — | — | CRITICAL (80) | 4104 ms | ✓ |
| `org.fossify.notes` | code_endpoint_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex | classes.dex 97% (NEAR_DUPLICATE) | — | CRITICAL (100) | 4116 ms | ✓ |
| `org.fossify.notes` | code_c2_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex | classes.dex 97% (NEAR_DUPLICATE) | 151.243.126.22:9443 (#1956999 CraxsRAT); 151.243.126.22 (#1956999 CraxsRAT) | CRITICAL (100) | 3581 ms | ✓ |
| `org.fossify.notes` | signature_stripped | CERTIFICATE_CHANGED | yes (unsigned) | none | — | — | CRITICAL (70) | 3524 ms | ✓ |
| `de.danoeh.antennapod` | official_copy | CLEAN | no (verified) | none | — | — | HIGH (55) | 10737 ms | ✓ |
| `de.danoeh.antennapod` | payload_resigned | CERTIFICATE_CHANGED | yes (verified) | added: assets/merkletrust_eval_payload.bin | — | — | CRITICAL (100) | 10797 ms | ✓ |
| `de.danoeh.antennapod` | code_endpoint_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex | classes.dex 96% (NEAR_DUPLICATE) | — | CRITICAL (100) | 10993 ms | ✓ |
| `de.danoeh.antennapod` | code_c2_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex | classes.dex 96% (NEAR_DUPLICATE) | 151.243.126.22:9443 (#1956999 CraxsRAT); 151.243.126.22 (#1956999 CraxsRAT) | CRITICAL (100) | 10880 ms | ✓ |
| `de.danoeh.antennapod` | signature_stripped | CERTIFICATE_CHANGED | yes (unsigned) | none | — | — | CRITICAL (95) | 10481 ms | ✓ |

**15/15 variants handled as expected.**

Variant details:

* `net.gsantner.markor` official_copy: Byte-identical copy of the F-Droid download
* `net.gsantner.markor` payload_resigned: Extra file added (harmless marker), re-signed with an attacker key
* `net.gsantner.markor` code_endpoint_swap: One URL in the program code replaced (documentation address), re-signed — classes.dex: 'http://apache.org/xml/features/nonvalidating/load-dtd-grammar' -> 'http://203.0.113.9:8080/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
* `net.gsantner.markor` code_c2_swap: One URL in the program code replaced by a current ThreatFox C2 address, re-signed — classes.dex: 'http://apache.org/xml/features/nonvalidating/load-dtd-grammar' -> 'http://151.243.126.22:9443/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' (ThreatFox #1956999, CraxsRAT)
* `net.gsantner.markor` signature_stripped: All signatures removed (zip rebuilt, not re-signed)
* `org.fossify.notes` official_copy: Byte-identical copy of the F-Droid download
* `org.fossify.notes` payload_resigned: Extra file added (harmless marker), re-signed with an attacker key
* `org.fossify.notes` code_endpoint_swap: One URL in the program code replaced (documentation address), re-signed — classes.dex: 'http://schemas.android.com/apk/res-auto' -> 'http://203.0.113.9:8080/xxxxxxxxxxxxxxx'
* `org.fossify.notes` code_c2_swap: One URL in the program code replaced by a current ThreatFox C2 address, re-signed — classes.dex: 'http://schemas.android.com/apk/res-auto' -> 'http://151.243.126.22:9443/xxxxxxxxxxxx' (ThreatFox #1956999, CraxsRAT)
* `org.fossify.notes` signature_stripped: All signatures removed (zip rebuilt, not re-signed)
* `de.danoeh.antennapod` official_copy: Byte-identical copy of the F-Droid download
* `de.danoeh.antennapod` payload_resigned: Extra file added (harmless marker), re-signed with an attacker key
* `de.danoeh.antennapod` code_endpoint_swap: One URL in the program code replaced (documentation address), re-signed — classes.dex: 'http://ns.adobe.com/xap/1.0/' -> 'http://203.0.113.9:8080/xxxx'
* `de.danoeh.antennapod` code_c2_swap: One URL in the program code replaced by a current ThreatFox C2 address, re-signed — classes.dex: 'http://podlove.org/simple-chapters' -> 'http://151.243.126.22:9443/xxxxxxx' (ThreatFox #1956999, CraxsRAT)
* `de.danoeh.antennapod` signature_stripped: All signatures removed (zip rebuilt, not re-signed)

## Risk scores of the untouched official apps

Integrity answers (is it the original?) were correct for every variant. The *risk* score, however, is
high for genuine apps: `net.gsantner.markor` MEDIUM (37), `org.fossify.notes` MEDIUM (30), `de.danoeh.antennapod` HIGH (55).
These are false positives of the behavioural heuristics, which were designed on small synthetic apps.
On 9 October two rule changes were made using these three apps as the DEVELOPMENT set (call-site
analysis, so APIs called only from well-known libraries count a quarter; widget receivers no longer
count as unprotected exports). Their effect was measured on eight other F-Droid apps never used for
design (results/benign_risk_before.json / _after.json). Before that, two extraction defects were fixed,
because they were objectively wrong rather than a matter of judgement: ASN.1 object identifiers (e.g. 1.3.6.1.5.5.7.3.1)
reported as IP addresses, and the XMP namespace http://ns.adobe.com/xap/1.0/ reported as a web address.
A standalone four-part OID such as 2.5.29.37 still looks like an IP and is still reported.
The first run, before those fixes and before a bug in this script was corrected, is kept in
realworld_initial.md: the script removed a library file (META-INF/versions/9/OSGI-INF/MANIFEST.MF)
together with the signature files, and MerkleTrust correctly reported it as deleted.

Scan times include ssdeep over DEX files of up to 16 MB (pure Python, about
0.7 s per MB); with the default 4 MB limit the largest DEX files are skipped and scans are faster.

Limitations: three apps and synthetic attacks on them (not malware found in the wild); the C2 address
is inserted by us to show that a feed match is reported, not discovered in a real sample.
