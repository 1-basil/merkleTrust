"""scripts/create_test_apks.py — Week 4 Multi-APK Evaluation Dataset Generator.

Generates the 3 test APKs required by Section 7 of MerkleTrust_Work_Split.md:
  1. apks/clean_baseline.apk       — Untampered baseline build
  2. apks/tampered_repackaged.apk   — Repackaged APK with modified classes.dex and new certificate
  3. apks/malicious_sample.apk      — APK with dangerous permissions, DCL, and C2 IOCs
"""

import os
import zipfile
import shutil
import hashlib

APKS_DIR = os.path.join(os.getcwd(), "apks")
os.makedirs(APKS_DIR, exist_ok=True)
# A real signed APK (v1 + v2 signatures): only signed builds can become baselines.
SAMPLE_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "tests", "fixtures", "apks", "signed_v1v2_ec.apk")


def create_clean_baseline(src: str = SAMPLE_SRC):
    """Create clean baseline APK."""
    target = os.path.join(APKS_DIR, "clean_baseline.apk")
    if os.path.exists(src):
        shutil.copyfile(src, target)
        print(f"[+] Created clean baseline: {target}")
    return target


def create_tampered_repackaged(src: str = SAMPLE_SRC):
    """Create repackaged/tampered APK with modified classes.dex and altered signature."""
    target = os.path.join(APKS_DIR, "tampered_repackaged.apk")
    if not os.path.exists(src):
        print(f"[-] Base APK {src} not found.")
        return target

    with zipfile.ZipFile(src, "r") as src_zip:
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as dst_zip:
            for item in src_zip.infolist():
                content = src_zip.read(item.filename)
                
                # Tamper with classes.dex by injecting backdoor bytecode / signature
                if item.filename == "classes.dex":
                    # Inject a simulated payload class marker
                    injected_payload = b"\x00Lcom/evil/Payload;\x00executeBackdoor\x00http://c2.evil-botnet.org\x00"
                    content = content + injected_payload
                
                # Simulate re-signing by altering certificate signature in META-INF
                elif "META-INF" in item.filename or item.filename.endswith(".RSA") or item.filename.endswith(".DSA"):
                    # Flip bytes to simulate a self-signed attacker certificate
                    content = hashlib.sha256(content + b"ATTACKER_SIGNATURE_KEY").digest() * 3

                dst_zip.writestr(item, content)

    print(f"[+] Created tampered repackaged APK: {target}")
    return target


def create_malicious_sample():
    """Create high-risk APK with dynamic class loading, SMS, and C2 indicators."""
    target = os.path.join(APKS_DIR, "malicious_sample.apk")
    if not os.path.exists(SAMPLE_SRC):
        return target

    with zipfile.ZipFile(SAMPLE_SRC, "r") as src_zip:
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as dst_zip:
            for item in src_zip.infolist():
                content = src_zip.read(item.filename)
                
                if item.filename == "classes.dex":
                    malicious_strings = (
                        b"\x00DexClassLoader\x00Runtime\x00exec\x00"
                        b"SmsManager\x00sendTextMessage\x00http://198.51.100.4:443/beacon\x00"
                        b"Lcom/trojan/StealerService;\x00"
                    )
                    content = content + malicious_strings

                dst_zip.writestr(item, content)

    print(f"[+] Created malicious sample APK: {target}")
    return target


def main():
    print("Generating MerkleTrust Week 4 Evaluation APK Dataset...\n")
    create_clean_baseline()
    create_tampered_repackaged()
    create_malicious_sample()
    print("\nDataset ready in ./apks/ directory.")


if __name__ == "__main__":
    main()
