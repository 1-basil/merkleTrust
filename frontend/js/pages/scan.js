import { get, upload } from '../api.js';
import { navigate } from '../app.js';
import { ENGINE_LABELS, bytes, errorBox, h, icon, mount } from '../dom.js';

const ORDER = ['integrity', 'static', 'tamper', 'dynamic', 'content', 'score', 'repository'];
const ACCEPT = ['.apk', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.m4a', '.mkv', '.webm', '.mp3', '.wav',
  '.html', '.htm', '.js', '.pdf'];

export async function renderScan(main, { isCurrent }) {
  const input = h('input', { type: 'file', accept: ACCEPT.join(','), id: 'apk-input', class: 'sr-only' });
  const status = h('div', { class: 'scan-status', 'aria-live': 'polite' });
  const zone = h('label', { for: 'apk-input', class: 'dropzone', tabindex: '0' },
    icon('upload', 'icon icon-xl'),
    h('strong', {}, 'Drop a file here or click to choose one'),
    h('span', { class: 'muted small' }, 'Android apps (.apk), images, audio/video, web pages and PDFs. The file is checked before analysis.'));

  const start = async (file) => {
    if (!file) return;
    if (!ACCEPT.some((ext) => file.name.toLowerCase().endsWith(ext))) {
      mount(status, errorBox(new Error('Unsupported file type. Choose an .apk, image, audio/video, web page or PDF.')));
      return;
    }
    zone.classList.add('busy');
    const bar = h('div', { class: 'progress' }, h('span', { style: 'width:0%' }));
    mount(status, h('p', {}, `Uploading ${file.name} (${bytes(file.size)})…`), bar);
    try {
      const scan = await upload('/scans', file, (f) => { bar.firstChild.style.width = `${Math.round(f * 100)}%`; });
      await follow(scan.id);
    } catch (err) {
      zone.classList.remove('busy');
      mount(status, errorBox(err));
    }
  };

  const follow = async (id) => {
    const steps = ORDER.map((e) => h('li', { class: 'step', dataset: { engine: e } },
      h('span', { class: 'step-dot', 'aria-hidden': 'true' }), ENGINE_LABELS[e]));
    mount(status, h('h2', { class: 'card-title' }, 'Analysing the file'), h('ol', { class: 'steps' }, steps));
    for (let i = 0; i < 600 && isCurrent(); i += 1) {
      const scan = await get(`/scans/${id}`);
      const isContent = Object.values(scan.engines).some((e) => e.status === 'skipped') || 'content' in scan.engines;
      steps.forEach((li) => {
        const st = scan.engines[li.dataset.engine]?.status || 'pending';
        // APK pipeline: no content stage. Other content: the APK-only stages are skipped.
        li.hidden = isContent ? st === 'skipped' : li.dataset.engine === 'content';
        li.className = `step step-${st}`;
      });
      if (scan.status === 'done' || scan.status === 'failed') {
        navigate(`/scans/${id}`);
        return;
      }
      await new Promise((r) => setTimeout(r, 800));
    }
  };

  input.addEventListener('change', () => start(input.files[0]));
  zone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('over'); start(e.dataTransfer.files[0]); });

  mount(main,
    h('div', { class: 'page-head' }, h('div', {},
      h('h1', {}, 'Scan a file'),
      h('p', { class: 'lead' }, 'Upload an APK to check whether it has been changed or contains security concerns, or an image, audio/video file, web page or PDF to fingerprint it and look for hidden data and unsafe content.'))),
    h('section', { class: 'card' }, input, zone, status),
    h('section', { class: 'card explain' },
      h('h2', { class: 'card-title' }, 'What happens to the file'),
      h('ol', { class: 'plain-steps' },
        h('li', {}, h('strong', {}, 'Fingerprinting. '), 'Every file inside the app gets a SHA-256 fingerprint; together they form one Merkle root.'),
        h('li', {}, h('strong', {}, 'Comparison. '), 'The fingerprints and developer signature are compared with the approved trusted version of the same app.'),
        h('li', {}, h('strong', {}, 'Security check. '), 'Permissions, settings and program code are inspected for risky behaviour.'),
        h('li', {}, h('strong', {}, 'Other content. '), 'Images, media, web pages and PDFs are fingerprinted in 64 KB chunks under one Merkle root and checked for appended payloads, unsafe scripts, privacy-leaking metadata and malformed structure.'),
        h('li', {}, h('strong', {}, 'Proof. '), 'The result is signed and recorded in a tamper-evident audit log.'))));
}
