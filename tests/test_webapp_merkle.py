"""The web app's in-browser Merkle code (webapp/src/lib/merkle.js) must give the server's exact roots.

Runs the JavaScript under Node (skipped when Node is not installed), once with WebCrypto and once
with its pure-JS SHA-256 fallback, and compares with core/merkle.py, core/file_manifest.py and
core/integrity.py.
"""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from core.file_manifest import file_leaf
from core.integrity import compute_chunks
from core.merkle import build_tree, proof, root

ROOT = Path(__file__).resolve().parent.parent
LIB = (ROOT / "webapp" / "src" / "lib" / "merkle.js").as_uri()
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")

SCRIPT = """
if (process.argv[2] === 'nocrypto') Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
const m = await import(%(lib)s + '?' + process.argv[2]);
const words = ['a', 'bb', 'ccc', 'dddd', 'e'].map(m.utf8);
const levels = await m.buildTree(words);
const { steps } = m.proofFor(levels, 3);
const trail = await m.foldProof(levels[0][3], steps);
const big = new Uint8Array(200000).map((_, i) => (i * 7) %% 251);
const chunks = await m.chunkHashes(big);
const croot = m.rootOf(await m.buildTree(chunks.map(m.fromHex)));
const froot = m.rootOf(await m.buildTree([m.fileLeaf('classes.dex', 'ab'.repeat(32)), m.fileLeaf('res/a.png', 'cd'.repeat(32))]));
const shas = []; for (let n = 0; n < 130; n++) shas.push(await m.sha256(new Uint8Array(n).map((_, i) => (i * 13 + n) %% 256)));
console.log(JSON.stringify({ root: m.rootOf(levels), steps: steps.map(({ sibling, position }) => ({ sibling, position })),
  folded: trail[trail.length - 1], croot, froot, shas }));
"""


@pytest.fixture(scope="module")
def expected():
    leaves = [b"a", b"bb", b"ccc", b"dddd", b"e"]
    tree = build_tree(leaves)
    big = bytes((i * 7) % 251 for i in range(200000))
    return {
        "root": root(tree),
        "steps": proof(tree, 3),
        "croot": root(build_tree([c["hash"] for c in compute_chunks(big)])),
        "froot": root(build_tree([file_leaf("classes.dex", "ab" * 32), file_leaf("res/a.png", "cd" * 32)])),
        "shas": [hashlib.sha256(bytes((i * 13 + n) % 256 for i in range(n))).hexdigest() for n in range(130)],
    }


@pytest.mark.parametrize("mode", ["webcrypto", "nocrypto"])
def test_browser_merkle_matches_server(tmp_path, expected, mode):
    script = tmp_path / "check.mjs"
    script.write_text(SCRIPT % {"lib": json.dumps(LIB)}, encoding="utf-8")
    out = subprocess.run([NODE, str(script), mode], capture_output=True, text=True, timeout=60, check=True).stdout
    got = json.loads(out)
    assert got["root"] == expected["root"] and got["folded"] == expected["root"]
    assert got["steps"] == expected["steps"]
    assert got["croot"] == expected["croot"]
    assert got["froot"] == expected["froot"]
    assert got["shas"] == expected["shas"]
