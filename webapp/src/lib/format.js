// Presentation helpers: file types, trust score, verdict wording, severities, formatting.
import { FileArchive, FileAudio, FileImage, FileQuestion, FileText, FileVideo, Globe, Smartphone } from 'lucide-react';

// ------------------------------------------------------------ file types --

export const FILE_TYPES = {
  apk: { label: 'Android App', icon: Smartphone, tint: 'text-emerald-300 bg-emerald-500/10 ring-emerald-500/30' },
  image: { label: 'Image', icon: FileImage, tint: 'text-sky-300 bg-sky-500/10 ring-sky-500/30' },
  video: { label: 'Video', icon: FileVideo, tint: 'text-violet-300 bg-violet-500/10 ring-violet-500/30' },
  audio: { label: 'Audio', icon: FileAudio, tint: 'text-pink-300 bg-pink-500/10 ring-pink-500/30' },
  web: { label: 'Web Page', icon: Globe, tint: 'text-amber-300 bg-amber-500/10 ring-amber-500/30' },
  doc: { label: 'Document', icon: FileText, tint: 'text-orange-300 bg-orange-500/10 ring-orange-500/30' },
  archive: { label: 'Archive', icon: FileArchive, tint: 'text-zinc-300 bg-zinc-500/10 ring-zinc-500/30' },
  unknown: { label: 'Unknown', icon: FileQuestion, tint: 'text-zinc-400 bg-zinc-500/10 ring-zinc-500/30' },
};

// Extensions the backend accepts for scans (mirrors api/uploads.py).
export const EXTENSIONS = {
  '.apk': 'apk',
  '.png': 'image', '.jpg': 'image', '.jpeg': 'image', '.gif': 'image', '.webp': 'image',
  '.mp4': 'video', '.mkv': 'video', '.webm': 'video',
  '.m4a': 'audio', '.mp3': 'audio', '.wav': 'audio',
  '.html': 'web', '.htm': 'web', '.js': 'web',
  '.pdf': 'doc',
};
export const ACCEPT = Object.keys(EXTENSIONS).join(',');

export function extOf(name = '') {
  const i = name.lastIndexOf('.');
  return i >= 0 ? name.slice(i).toLowerCase() : '';
}

export function categoryFromName(name) {
  return EXTENSIONS[extOf(name)] || 'unknown';
}

// Magic-byte sniffing (the same signatures the backend's core/detector.py trusts).
export function sniffBytes(b) {
  const at = (off, ...bytes) => bytes.every((x, i) => b[off + i] === x);
  const ascii = (off, s) => [...s].every((c, i) => b[off + i] === c.charCodeAt(0));
  if (at(0, 0x89, 0x50, 0x4e, 0x47)) return { category: 'image', format: 'PNG' };
  if (at(0, 0xff, 0xd8, 0xff)) return { category: 'image', format: 'JPEG' };
  if (ascii(0, 'GIF8')) return { category: 'image', format: 'GIF' };
  if (ascii(0, 'RIFF') && ascii(8, 'WEBP')) return { category: 'image', format: 'WebP' };
  if (ascii(0, 'RIFF') && ascii(8, 'WAVE')) return { category: 'audio', format: 'WAV' };
  if (ascii(4, 'ftyp')) return ascii(8, 'M4A ') ? { category: 'audio', format: 'M4A' } : { category: 'video', format: 'MP4' };
  if (at(0, 0x1a, 0x45, 0xdf, 0xa3)) return { category: 'video', format: 'Matroska' };
  if (ascii(0, 'ID3') || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0)) return { category: 'audio', format: 'MP3' };
  if (ascii(0, '%PDF-')) return { category: 'doc', format: 'PDF' };
  if (at(0, 0x50, 0x4b, 0x03, 0x04)) return { category: 'apk', format: 'ZIP / APK' };
  const head = new TextDecoder('utf-8', { fatal: false }).decode(b).trimStart().toLowerCase();
  if (head.startsWith('<!doctype html') || head.startsWith('<html')) return { category: 'web', format: 'HTML' };
  return null;
}

export async function detectFile(file) {
  const fromName = categoryFromName(file.name);
  let sniffed = null;
  try {
    sniffed = sniffBytes(new Uint8Array(await file.slice(0, 64).arrayBuffer()));
  } catch { /* unreadable: fall back to the extension */ }
  const supported = fromName !== 'unknown';
  // The server refuses files whose contents contradict their extension.
  const mismatch = Boolean(sniffed && supported && sniffed.category !== fromName
    && !(fromName === 'video' && sniffed.category === 'audio'));
  return {
    category: sniffed?.category || fromName,
    format: sniffed?.format || extOf(file.name).slice(1).toUpperCase() || 'Unknown',
    supported,
    mismatch,
  };
}

// --------------------------------------------------------- trust & verdict --

// The backend reports a 0–100 *risk* score (higher = more concerns).
// The trust score shown here is its complement: 100 − risk.
export function trustScore(riskScore) {
  return typeof riskScore === 'number' ? Math.max(0, Math.min(100, 100 - riskScore)) : null;
}

const VERDICT_TONE = {
  CLEAN: 'good', REVIEW: 'warn', NO_BASELINE: 'warn',
  HIGH_RISK: 'bad', CHANGES_DETECTED: 'bad', ANALYSIS_FAILED: 'bad',
};

export function scoreTone(trust) {
  if (trust === null || trust === undefined) return 'neutral';
  if (trust >= 80) return 'good';
  if (trust >= 50) return 'warn';
  return 'bad';
}

const RANK = { neutral: 0, good: 1, warn: 2, bad: 3 };

// The colour is the worse of what the score and the verdict say, so a "tampered"
// verdict is never shown in green just because few risk points were counted.
export function overallTone(trust, verdict) {
  const a = scoreTone(trust);
  const b = VERDICT_TONE[verdict] || 'neutral';
  return RANK[a] >= RANK[b] ? a : b;
}

export function trustLabel(trust) {
  if (trust === null || trust === undefined) return 'Not scored';
  if (trust >= 80) return 'High Trust';
  if (trust >= 50) return 'Moderate Trust';
  return 'Low Trust';
}

export function verdictLabel(verdict, integrityStatus) {
  switch (verdict) {
    case 'CLEAN': return integrityStatus === 'CLEAN' ? 'Verified Original' : 'No Issues Found';
    case 'CHANGES_DETECTED': return 'Tampering Detected';
    case 'HIGH_RISK': return 'Security Risks Found';
    case 'REVIEW': return 'Review Recommended';
    case 'NO_BASELINE': return 'Not Verified';
    case 'ANALYSIS_FAILED': return 'Could Not Analyse';
    default: return verdict || 'Pending';
  }
}

export const TONES = {
  good: { text: 'text-emerald-300', ring: 'ring-emerald-500/30', bg: 'bg-emerald-500/10', stroke: '#34d399', glow: 'shadow-emerald-500/10' },
  warn: { text: 'text-amber-300', ring: 'ring-amber-500/30', bg: 'bg-amber-500/10', stroke: '#fbbf24', glow: 'shadow-amber-500/10' },
  bad: { text: 'text-red-300', ring: 'ring-red-500/30', bg: 'bg-red-500/10', stroke: '#f87171', glow: 'shadow-red-500/10' },
  neutral: { text: 'text-zinc-300', ring: 'ring-zinc-500/30', bg: 'bg-zinc-500/10', stroke: '#71717a', glow: 'shadow-black/0' },
};

// --------------------------------------------------------------- severity --

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_STYLE = {
  critical: 'text-red-200 bg-red-500/15 ring-red-500/40',
  high: 'text-orange-200 bg-orange-500/15 ring-orange-500/40',
  medium: 'text-amber-200 bg-amber-500/15 ring-amber-500/40',
  low: 'text-sky-200 bg-sky-500/15 ring-sky-500/40',
  info: 'text-zinc-300 bg-zinc-500/15 ring-zinc-500/40',
};

// ------------------------------------------------------------- formatting --

export function bytes(n) {
  if (typeof n !== 'number') return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function dateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function shortHash(h, n = 10) {
  if (!h) return '—';
  return h.length > n * 2 ? `${h.slice(0, n)}…${h.slice(-6)}` : h;
}
