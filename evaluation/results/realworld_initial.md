# MerkleTrust — Real-world apps (F-Droid)

Generated 2026-10-09T01:32:14+00:00 by `python -m scripts.run_realworld_evaluation` (Python 3.14.7).
Three open-source apps were downloaded from f-droid.org and verified against the SHA-256 pinned from F-Droid's
repository index. Each official app was enrolled as the trusted baseline; attack variants were built with zip
operations and apksigner only (no app was installed or run). Ground truth is fixed in the script before scanning.
DEX files up to 16 MB were fuzzy-hashed for this run (the default limit is 4 MB).

| App | Official signer matches F-Droid | Enrol time |
|---|---|---|
| `net.gsantner.markor` | yes | 9959 ms |
| `org.fossify.notes` | yes | 3107 ms |
| `de.danoeh.antennapod` | yes | 9810 ms |

C2 address used in `code_c2_swap`: `151.243.126.22:9443` — CraxsRAT, ThreatFox record #1956999, first seen 2026-10-08 06:26:07 (feed updated 2026-10-08 07:40:22 UTC).

| App | Variant | Integrity | Signed by someone else? | Changed files | Code similarity (ssdeep) | Threat feed | Risk | Time | As expected |
|---|---|---|---|---|---|---|---|---|---|
| `net.gsantner.markor` | official_copy | CLEAN | no (verified) | none | — | — | CRITICAL (96) | 14002 ms | ✓ |
| `net.gsantner.markor` | payload_resigned | CERTIFICATE_CHANGED | yes (verified) | added: assets/merkletrust_eval_payload.bin | — | — | CRITICAL (100) | 9078 ms | ✓ |
| `net.gsantner.markor` | code_endpoint_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex | classes.dex 96% (NEAR_DUPLICATE) | — | CRITICAL (100) | 7261 ms | ✓ |
| `net.gsantner.markor` | code_c2_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex | classes.dex 96% (NEAR_DUPLICATE) | 151.243.126.22:9443 (#1956999 CraxsRAT); 151.243.126.22 (#1956999 CraxsRAT) | CRITICAL (100) | 7038 ms | ✓ |
| `net.gsantner.markor` | signature_stripped | CERTIFICATE_CHANGED | yes (unsigned) | none | — | — | CRITICAL (100) | 7054 ms | ✓ |
| `org.fossify.notes` | official_copy | CLEAN | no (verified) | none | — | — | MEDIUM (34) | 3463 ms | ✓ |
| `org.fossify.notes` | payload_resigned | CERTIFICATE_CHANGED | yes (verified) | added: assets/merkletrust_eval_payload.bin; deleted: META-INF/versions/9/OSGI-INF/MANIFEST.MF | — | — | CRITICAL (84) | 3365 ms | ✗ files_exact |
| `org.fossify.notes` | code_endpoint_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex; deleted: META-INF/versions/9/OSGI-INF/MANIFEST.MF | classes.dex 97% (NEAR_DUPLICATE) | — | CRITICAL (100) | 3393 ms | ✗ files_exact |
| `org.fossify.notes` | code_c2_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex; deleted: META-INF/versions/9/OSGI-INF/MANIFEST.MF | classes.dex 97% (NEAR_DUPLICATE) | 151.243.126.22:9443 (#1956999 CraxsRAT); 151.243.126.22 (#1956999 CraxsRAT) | CRITICAL (100) | 3538 ms | ✗ files_exact |
| `org.fossify.notes` | signature_stripped | CERTIFICATE_CHANGED | yes (unsigned) | deleted: META-INF/versions/9/OSGI-INF/MANIFEST.MF | — | — | CRITICAL (84) | 3353 ms | ✗ files_exact |
| `de.danoeh.antennapod` | official_copy | CLEAN | no (verified) | none | — | — | HIGH (61) | 9896 ms | ✓ |
| `de.danoeh.antennapod` | payload_resigned | CERTIFICATE_CHANGED | yes (verified) | added: assets/merkletrust_eval_payload.bin; deleted: META-INF/versions/9/OSGI-INF/MANIFEST.MF | — | — | CRITICAL (100) | 9767 ms | ✗ files_exact |
| `de.danoeh.antennapod` | code_endpoint_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex; deleted: META-INF/versions/9/OSGI-INF/MANIFEST.MF | classes.dex 96% (NEAR_DUPLICATE) | — | CRITICAL (100) | 9802 ms | ✗ files_exact |
| `de.danoeh.antennapod` | code_c2_swap | CERTIFICATE_CHANGED | yes (verified) | modified: classes.dex; deleted: META-INF/versions/9/OSGI-INF/MANIFEST.MF | classes.dex 96% (NEAR_DUPLICATE) | 151.243.126.22:9443 (#1956999 CraxsRAT); 151.243.126.22 (#1956999 CraxsRAT) | CRITICAL (100) | 9825 ms | ✗ files_exact |
| `de.danoeh.antennapod` | signature_stripped | CERTIFICATE_CHANGED | yes (unsigned) | deleted: META-INF/versions/9/OSGI-INF/MANIFEST.MF | — | — | CRITICAL (100) | 9761 ms | ✗ files_exact |

**7/15 variants handled as expected.**

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

Limitations: three apps and synthetic attacks on them (not malware found in the wild); the C2 address
is inserted by us to show that a feed match is reported, not discovered in a real sample.
