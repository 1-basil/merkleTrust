// MerkleTrust Client-Side Dashboard Controller

let selectedFile = null;
let currentJobId = null;
let pollInterval = null;
let currentReportData = null;

// DOM Elements
const dropZone = document.getElementById('apk-drop-zone');
const fileInput = document.getElementById('apk-file-input');
const browseBtn = document.getElementById('browse-btn');
const btnUpload = document.getElementById('btn-upload');
const btnSampleApk = document.getElementById('btn-sample-apk');
const selectedBadge = document.getElementById('selected-file-badge');
const selectedFileName = document.getElementById('selected-file-name');
const selectedFileSize = document.getElementById('selected-file-size');
const clearFileBtn = document.getElementById('clear-file-btn');
const uploadStatus = document.getElementById('upload-status-text');

const pipelineSection = document.getElementById('pipeline-section');
const resultsSection = document.getElementById('results-section');
const currentJobIdElem = document.getElementById('current-job-id');

const btnRefreshLedger = document.getElementById('btn-refresh-ledger');
const ledgerTbody = document.getElementById('ledger-tbody');

const btnTamperCorrupt = document.getElementById('btn-tamper-corrupt');
const btnTamperVerify = document.getElementById('btn-tamper-verify');
const tamperResultBox = document.getElementById('tamper-result-box');

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  setupFileUpload();
  setupLedger();
  setupTamperLab();
  refreshLedger();
});

// File Selection & Drag-and-Drop
function setupFileUpload() {
  browseBtn.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('click', (e) => {
    if (e.target !== clearFileBtn && !clearFileBtn.contains(e.target)) {
      fileInput.click();
    }
  });

  ['dragenter', 'dragover'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  });

  clearFileBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    selectedFile = null;
    fileInput.value = '';
    selectedBadge.classList.add('hidden');
    btnUpload.disabled = true;
    uploadStatus.textContent = '';
  });

  btnSampleApk.addEventListener('click', async () => {
    btnUpload.disabled = true;
    uploadStatus.textContent = 'Loading test_sample.apk from repository...';
    pipelineSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');

    ['integrity', 'static', 'tamper', 'dynamic', 'score', 'repository'].forEach(stage => {
      updateStageBadge(stage, 'pending');
      document.getElementById(`timer-${stage}`).textContent = '0ms';
    });

    try {
      const res = await fetch('/api/upload-sample', { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Sample load failed');
      }
      const data = await res.json();
      currentJobId = data.job_id;
      currentJobIdElem.textContent = `Job ID: ${currentJobId}`;
      uploadStatus.textContent = `Sample APK quarantined. Running 6-stage pipeline...`;
      startPollingJob(currentJobId);
    } catch (err) {
      uploadStatus.textContent = `Error: ${err.message}`;
    }
  });

  btnUpload.addEventListener('click', () => {
    if (selectedFile) {
      submitApkUpload(selectedFile);
    }
  });
}

function handleFileSelected(file) {
  if (!file.name.endsWith('.apk') && !file.name.endsWith('.zip')) {
    alert('Please select an Android .apk or .zip file');
    return;
  }
  selectedFile = file;
  selectedFileName.textContent = file.name;
  selectedFileSize.textContent = formatBytes(file.size);
  selectedBadge.classList.remove('hidden');
  btnUpload.disabled = false;
  uploadStatus.textContent = 'File ready for cryptographic pipeline.';
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function uploadSampleDirectly() {
  // Use a simulated sample upload by creating a small APK-format blob or fetching from backend
  const dummyData = new Uint8Array([80, 75, 3, 4, 20, 0, 0, 0]); // PK header
  const sampleFile = new File([dummyData], "test_sample.apk", { type: "application/vnd.android.package-archive" });
  handleFileSelected(sampleFile);
  submitApkUpload(sampleFile);
}

// Upload & Pipeline Execution
async function submitApkUpload(file) {
  const formData = new FormData();
  formData.append('file', file);

  btnUpload.disabled = true;
  uploadStatus.textContent = 'Uploading and quarantining APK...';
  pipelineSection.classList.remove('hidden');
  resultsSection.classList.add('hidden');

  // Reset stage badges
  ['integrity', 'static', 'tamper', 'dynamic', 'score', 'repository'].forEach(stage => {
    updateStageBadge(stage, 'pending');
    document.getElementById(`timer-${stage}`).textContent = '0ms';
  });

  try {
    const res = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Upload failed');
    }

    const data = await res.json();
    currentJobId = data.job_id;
    currentJobIdElem.textContent = `Job ID: ${currentJobId}`;
    uploadStatus.textContent = `Quarantined as ${data.sha256.substring(0, 16)}... Processing pipeline.`;

    startPollingJob(currentJobId);
  } catch (err) {
    uploadStatus.textContent = `Error: ${err.message}`;
    btnUpload.disabled = false;
  }
}

function startPollingJob(jobId) {
  if (pollInterval) clearInterval(pollInterval);

  pollInterval = setInterval(async () => {
    try {
      const res = await fetch(`/api/jobs/${jobId}`);
      if (!res.ok) return;

      const data = await res.json();
      const statuses = data.engine_status || {};
      const durations = data.durations_ms || {};

      Object.entries(statuses).forEach(([engine, status]) => {
        updateStageBadge(engine, status);
        if (durations[engine]) {
          document.getElementById(`timer-${engine}`).textContent = `${durations[engine]}ms`;
        }
      });

      if (data.status === 'done' || data.status === 'failed') {
        clearInterval(pollInterval);
        loadJobReport(jobId);
        refreshLedger();
      }
    } catch (e) {
      console.error('Polling error', e);
    }
  }, 500);
}

function updateStageBadge(stage, status) {
  const badge = document.getElementById(`badge-${stage}`);
  const card = document.getElementById(`stage-${stage}`);
  if (!badge || !card) return;

  badge.className = `badge badge-${status}`;
  badge.textContent = status.charAt(0).toUpperCase() + status.slice(1);

  card.className = `stage-item stage-${status}`;
}

// Load Completed Report
async function loadJobReport(jobId) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/report`);
    if (!res.ok) return;

    const data = await res.json();
    currentReportData = data;
    renderResults(data);
    resultsSection.classList.remove('hidden');
  } catch (err) {
    console.error('Report error', err);
  }
}

// Render Results Dashboard
function renderResults(data) {
  const reports = data.reports || {};
  const scoreRep = reports.score || {};
  const repoRep = reports.repository || {};
  const integRep = reports.integrity || {};
  const tamperRep = reports.tamper || {};
  const staticRep = reports.static || {};
  const dynamicRep = reports.dynamic || {};

  // 1. Trust Score
  const score = scoreRep.score !== undefined ? scoreRep.score : '--';
  const verdict = scoreRep.verdict || 'unknown';

  document.getElementById('score-value').textContent = score;
  const circle = document.getElementById('score-circle');
  circle.className = `score-circle ${verdict}`;

  const verdictPill = document.getElementById('verdict-pill');
  verdictPill.className = `verdict-pill ${verdict}`;
  verdictPill.textContent = verdict.toUpperCase();

  const rulesList = document.getElementById('rules-fired-list');
  rulesList.innerHTML = '';
  const rules = scoreRep.rules_fired || [];
  if (rules.length === 0) {
    rulesList.innerHTML = '<div class="rule-item"><span>No security penalties applied. Clean baseline state.</span><span class="rule-weight">0</span></div>';
  } else {
    rules.forEach(r => {
      const item = document.createElement('div');
      item.className = 'rule-item';
      item.innerHTML = `<span><strong>${r.rule_id}:</strong> ${r.reason} (${r.source})</span><span class="rule-weight">${r.weight}</span>`;
      rulesList.appendChild(item);
    });
  }

  // 2. Cryptographic Provenance
  document.getElementById('meta-apk-sha').textContent = data.sha256 || integRep.sha256 || '--';
  document.getElementById('meta-merkle-root').textContent = integRep.merkle_root || '--';
  document.getElementById('meta-pubkey-id').textContent = repoRep.pubkey_id || 'mt-signer-1';
  document.getElementById('meta-entry-hash').textContent = repoRep.entry_hash || '--';
  document.getElementById('meta-block-info').textContent = repoRep.sim_block ? `Block #${repoRep.sim_block.height} (${repoRep.sim_block.tx_id.substring(0, 10)}...)` : 'Block #0';
  document.getElementById('meta-proof-steps').textContent = `${(repoRep.inclusion_proof || []).length} Audit Steps`;

  // 3. Merkle Chunk Grid
  renderChunkGrid(integRep.chunks || [], tamperRep.changed_chunks || []);

  // 4. File Map Table
  renderFileMap(integRep.file_map || [], tamperRep.changed_files || []);

  // 5. Findings
  renderFindings(reports);

  // Setup Re-Verify button
  document.getElementById('btn-verify-job').onclick = () => verifyCurrentJob(data.job_id);
}

function renderChunkGrid(chunks, changedChunks) {
  const matrix = document.getElementById('chunk-matrix');
  matrix.innerHTML = '';
  const changedIndices = new Set(changedChunks.map(c => c.index));

  if (chunks.length === 0) {
    matrix.innerHTML = '<p class="drop-hint">No chunks available</p>';
    return;
  }

  chunks.forEach((c, i) => {
    const block = document.createElement('div');
    const isModified = changedIndices.has(c.index);
    block.className = `chunk-block ${isModified ? 'modified' : 'intact'}`;
    block.textContent = c.index;
    block.title = `Chunk #${c.index}\nOffset: ${c.offset}\nLength: ${c.length}\nHash: ${c.hash}\nStatus: ${isModified ? 'TAMPERED' : 'INTACT'}`;
    matrix.appendChild(block);
  });
}

function renderFileMap(fileMap, changedFiles) {
  const tbody = document.getElementById('file-map-tbody');
  tbody.innerHTML = '';

  const changedMap = new Map();
  changedFiles.forEach(f => changedMap.set(f.path, f.change_type));

  if (fileMap.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">No file entries in central directory</td></tr>';
    return;
  }

  fileMap.forEach(f => {
    const isChanged = changedMap.has(f.path);
    const changeType = changedMap.get(f.path) || 'Unmodified';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${f.path}</strong></td>
      <td><code>${f.offset}</code></td>
      <td><code>${f.length} B</code></td>
      <td><code title="${f.sha256}">${f.sha256 ? f.sha256.substring(0, 16) + '...' : 'n/a'}</code></td>
      <td><span class="badge ${isChanged ? 'badge-danger' : 'badge-success'}">${changeType}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderFindings(reports) {
  const list = document.getElementById('findings-list');
  list.innerHTML = '';

  let allFindings = [];
  Object.entries(reports).forEach(([eng, rep]) => {
    const fList = rep.findings || [];
    fList.forEach(f => allFindings.push({ ...f, engine: eng }));
  });

  if (allFindings.length === 0) {
    list.innerHTML = '<p class="drop-hint">No security findings recorded.</p>';
    return;
  }

  allFindings.forEach(f => {
    const card = document.createElement('div');
    card.className = 'finding-card';
    card.dataset.severity = f.severity || 'info';
    card.innerHTML = `
      <div class="finding-severity ${f.severity || 'info'}">${f.severity || 'info'}</div>
      <div class="finding-body">
        <h5>${f.title} <span class="version-tag">${f.id} • ${f.engine}</span></h5>
        <div class="finding-evidence">${f.evidence}</div>
      </div>
    `;
    list.appendChild(card);
  });

  // Filter Buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.dataset.filter;
      document.querySelectorAll('.finding-card').forEach(c => {
        if (filter === 'all' || c.dataset.severity === filter) {
          c.classList.remove('hidden');
        } else {
          c.classList.add('hidden');
        }
      });
    };
  });
}

async function verifyCurrentJob(jobId) {
  const statusElem = document.getElementById('verification-status');
  statusElem.textContent = 'Verifying cryptographic inclusion proof and ECDSA signature...';
  try {
    const res = await fetch(`/api/jobs/${jobId}/verify`);
    const data = await res.json();
    if (data.is_valid) {
      statusElem.innerHTML = `<span style="color: var(--accent-emerald);">✓ Valid: ECDSA signature verified, Merkle proof confirmed against root!</span>`;
    } else {
      statusElem.innerHTML = `<span style="color: var(--accent-rose);">✗ Verification Failed: Signature or proof mismatch detected!</span>`;
    }
  } catch (err) {
    statusElem.textContent = `Error: ${err.message}`;
  }
}

// Ledger Explorer
function setupLedger() {
  btnRefreshLedger.addEventListener('click', refreshLedger);
}

async function refreshLedger() {
  try {
    const res = await fetch('/api/repository?limit=15');
    if (!res.ok) return;

    const data = await res.json();
    const entries = data.entries || [];

    document.getElementById('chain-ledger-count').textContent = `${data.total_entries} Ledger Entries`;
    if (entries.length > 0 && entries[entries.length - 1].sim_block) {
      document.getElementById('chain-block-height').textContent = `Simulated Chain: Block #${entries[entries.length - 1].sim_block.height}`;
    }

    ledgerTbody.innerHTML = '';
    if (entries.length === 0) {
      ledgerTbody.innerHTML = '<tr><td colspan="7" class="empty-cell">Ledger is currently empty. Run an APK analysis to add entries.</td></tr>';
      return;
    }

    entries.slice().reverse().forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>#${e.entry_index}</strong></td>
        <td>${new Date(e.timestamp).toLocaleTimeString()}</td>
        <td><code title="${e.entry_hash}">${e.entry_hash.substring(0, 14)}...</code></td>
        <td><code title="${e.prev_entry_hash}">${e.prev_entry_hash.substring(0, 10)}...</code></td>
        <td><code title="${e.canonical_report_sha256}">${e.canonical_report_sha256.substring(0, 14)}...</code></td>
        <td><span class="code-tag">#${e.sim_block ? e.sim_block.height : 0}</span></td>
        <td>
          <button class="btn-outline" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="inspectProof(${e.entry_index})">Verify Proof</button>
        </td>
      `;
      ledgerTbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Ledger refresh error', e);
  }
}

window.inspectProof = async function(index) {
  try {
    const res = await fetch(`/api/repository/${index}/proof`);
    const data = await res.json();
    alert(`Inclusion Proof for Entry #${index}:\nRoot: ${data.repo_merkle_root}\nSteps: ${data.inclusion_proof.length}\nProof Status: ${data.verified ? 'VALID' : 'INVALID'}`);
  } catch (err) {
    alert(`Proof check failed: ${err.message}`);
  }
};

// Tamper Demonstration Lab
function setupTamperLab() {
  btnTamperCorrupt.addEventListener('click', () => runTamperDemo(true));
  btnTamperVerify.addEventListener('click', () => runTamperDemo(false));
}

async function runTamperDemo(corrupt) {
  tamperResultBox.classList.remove('hidden');
  const titleElem = document.getElementById('tamper-verdict-title');
  const badgeElem = document.getElementById('tamper-verdict-badge');
  const descElem = document.getElementById('tamper-verdict-desc');
  const targetElem = document.getElementById('tamper-target-entry');
  const breakElem = document.getElementById('tamper-break-loc');
  const reasonElem = document.getElementById('tamper-reason');

  titleElem.textContent = corrupt ? 'Simulating Byte Flip Attack...' : 'Verifying Ledger State...';

  try {
    const res = await fetch(`/api/tamper-demo?corrupt_byte=${corrupt}`, { method: 'POST' });
    const data = await res.json();

    if (data.chain_intact) {
      tamperResultBox.className = 'tamper-result-box intact';
      titleElem.textContent = 'Cryptographic Ledger Intact';
      badgeElem.className = 'badge badge-success';
      badgeElem.textContent = 'PASSED';
      descElem.textContent = 'All mathematical hash chains, Merkle inclusion proofs, and ECDSA digital signatures validated without discrepancy.';
      targetElem.textContent = `Entry #${data.target_entry_index}`;
      breakElem.textContent = 'None (0 breaks detected)';
      reasonElem.textContent = data.reason;
    } else {
      tamperResultBox.className = 'tamper-result-box broken';
      titleElem.textContent = 'Tamper Detected by Cryptographic Chain!';
      badgeElem.className = 'badge badge-danger';
      badgeElem.textContent = 'TAMPER DETECTED';
      descElem.textContent = data.explanation;
      targetElem.textContent = `Entry #${data.target_entry_index}`;
      breakElem.textContent = `Entry #${data.break_detected_at_index} (Chain Severed)`;
      reasonElem.textContent = data.reason;
    }
  } catch (err) {
    titleElem.textContent = 'Tamper Test Error';
    descElem.textContent = err.message;
  }
}
