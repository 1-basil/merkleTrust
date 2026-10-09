"""scripts/update_threat_feed.py — Download the latest abuse.ch ThreatFox indicators.

    python -m scripts.update_threat_feed            # into <data_dir>/threat_feeds/threatfox_recent.csv
    python -m scripts.update_threat_feed --out F    # somewhere else (set MERKLETRUST_THREAT_FEED_PATH=F)

ThreatFox's "recent" export lists indicators (C2 servers, malware hosts, malware file hashes)
reported in the last days. The running server picks up a new file automatically; schedule this
script (e.g. hourly) to keep it current. ThreatFox data is free under abuse.ch's fair-use terms;
commercial use may require their commercial API: https://threatfox.abuse.ch/faq/
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import urllib.request
from pathlib import Path

from core.threat_intel import load_threatfox_csv
from core.threat_intel import feed_path

URL = "https://threatfox.abuse.ch/export/csv/recent/"
HEADER = '"first_seen_utc","ioc_id","ioc_value","ioc_type"'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=None, help="output file (default: the configured feed path)")
    parser.add_argument("--url", default=URL, help="export URL (default: ThreatFox recent CSV)")
    args = parser.parse_args(argv)
    out = args.out or feed_path()
    out.parent.mkdir(parents=True, exist_ok=True)

    req = urllib.request.Request(args.url, headers={"User-Agent": "MerkleTrust threat-feed updater"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URL by default
        body = resp.read()
    text = body.decode("utf-8", errors="replace")
    if HEADER not in text:
        print("error: the download does not look like a ThreatFox CSV export; nothing was changed", file=sys.stderr)
        return 1

    # Write next to the target and rename, so the server never reads a half-written file.
    with tempfile.NamedTemporaryFile("wb", dir=out.parent, delete=False, suffix=".part") as tmp:
        tmp.write(body)
    Path(tmp.name).replace(out)

    indicators, meta = load_threatfox_csv(out)
    kinds: dict[str, int] = {}
    for ind in indicators:
        kinds[ind.kind] = kinds.get(ind.kind, 0) + 1
    android = sum(1 for ind in indicators if ind.malware_id.startswith("apk."))
    print(f"saved {out}")
    print(f"{meta['source']}, last updated {meta['updated']}: {meta['indicators']} usable indicators "
          f"({', '.join(f'{v} {k}' for k, v in sorted(kinds.items()))}); {android} for Android malware")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
