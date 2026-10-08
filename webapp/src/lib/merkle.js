// Browser twin of core/merkle.py (RFC 6962 hashing), so trees and proofs can be
// rebuilt and checked on the viewer's own machine — no need to trust the server.
//
//   leaf hash = SHA-256(0x00 || leaf_data)
//   node hash = SHA-256(0x01 || left || right)
//   a lone node at the end of a level is promoted unchanged (no duplication)

const enc = new TextEncoder();

export const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
export const fromHex = (hex) => Uint8Array.from(hex.match(/../g) || [], (x) => parseInt(x, 16));
export const utf8 = (s) => enc.encode(s);

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// --- SHA-256 -----------------------------------------------------------------
// WebCrypto only exists in secure contexts (https or localhost). A demo opened
// over a LAN address is plain http, so a small pure-JS fallback keeps it working.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256js(data) {
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(data);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(len / 0x20000000));
  view.setUint32(padded.length - 4, (len << 3) >>> 0);
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i += 1) W[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i += 1) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  H.forEach((v, i) => ov.setUint32(i * 4, v));
  return out;
}

const subtle = globalThis.crypto?.subtle;

/** Hex SHA-256 of a Uint8Array. */
export async function sha256(bytes) {
  if (subtle) return toHex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
  return toHex(sha256js(bytes));
}

// --- RFC 6962 tree --------------------------------------------------------------

const LEAF = new Uint8Array([0]);
const NODE = new Uint8Array([1]);

export const leafHash = (data) => sha256(concat(LEAF, data));
export const nodeHash = (left, right) => sha256(concat(NODE, fromHex(left), fromHex(right)));

/** All levels: levels[0] are leaf hashes, levels[levels.length - 1] is [root]. */
export async function buildTree(leaves) {
  if (!leaves.length) return [[await sha256(new Uint8Array())]];
  let level = await Promise.all(leaves.map(leafHash));
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(await nodeHash(level[i], level[i + 1]));
    if (level.length % 2) next.push(level[level.length - 1]);
    level = next;
    levels.push(level);
  }
  return levels;
}

export const rootOf = (levels) => levels[levels.length - 1][0];

/**
 * Inclusion proof for leaf `index`, in the server's format ({sibling, position})
 * plus the tree coordinates of every node involved, for highlighting.
 */
export function proofFor(levels, index) {
  const steps = [];
  const path = [];
  let idx = index;
  levels.slice(0, -1).forEach((level, depth) => {
    path.push(`${depth}:${idx}`);
    const sib = idx ^ 1;
    if (sib < level.length) {
      steps.push({ sibling: level[sib], position: idx % 2 ? 'left' : 'right', node: `${depth}:${sib}` });
    }
    idx >>= 1;
  });
  path.push(`${levels.length - 1}:0`);
  return { steps, path };
}

/** Fold a proof from a leaf hash; returns every intermediate hash (last one is the computed root). */
export async function foldProof(leafHex, steps) {
  const trail = [leafHex];
  let cur = leafHex;
  for (const s of steps) {
    cur = s.position === 'left' ? await nodeHash(s.sibling, cur) : await nodeHash(cur, s.sibling);
    trail.push(cur);
  }
  return trail;
}

// --- MerkleTrust leaf formats -------------------------------------------------------

/** Leaf data of one file inside an APK (core/file_manifest.py: file_leaf). */
export const fileLeaf = (path, sha256hex) =>
  concat(utf8('merkletrust.file.v1'), LEAF, utf8(path), LEAF, fromHex(sha256hex));

export const CHUNK_SIZE = 64 * 1024; // core/integrity.py DEFAULT_CHUNK_SIZE

/** SHA-256 of every chunk of `bytes` (leaf data for the chunk tree is the raw digest). */
export async function chunkHashes(bytes, size = CHUNK_SIZE) {
  const out = [];
  for (let off = 0; off < bytes.length; off += size) out.push(await sha256(bytes.subarray(off, off + size)));
  return out;
}

/** A stable colour for a hash, so matching hashes are recognisable at a glance. */
export function hashHue(hex) {
  if (!hex) return 0;
  return Math.round((parseInt(hex.slice(0, 6), 16) / 0xffffff) * 360);
}
