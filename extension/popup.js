// --- Config ---
let SERVER_URL = 'http://localhost:5050';

document.addEventListener('DOMContentLoaded', async () => {
  // Load saved config
  const saved = await chrome.storage.local.get(['serverUrl', 'outputDir']);
  if (saved.serverUrl) {
    SERVER_URL = saved.serverUrl;
    document.getElementById('serverUrl').value = SERVER_URL;
  }
  if (saved.outputDir) {
    document.getElementById('outputDir').value = saved.outputDir;
  }
  checkServer();
});

async function saveConfig() {
  SERVER_URL = document.getElementById('serverUrl').value.replace(/\/$/, '');
  await chrome.storage.local.set({ serverUrl: SERVER_URL });
  log('Config saved', 'info');
  checkServer();
}

async function saveOutputDir() {
  const dir = document.getElementById('outputDir').value;
  await chrome.storage.local.set({ outputDir: dir });
  log('Output directory saved', 'success');
}

// --- Server Status ---
async function checkServer() {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  try {
    const res = await fetch(`${SERVER_URL}/health`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      dot.className = 'dot connected';
      text.textContent = 'Server connected';
      return true;
    }
  } catch (e) {}
  dot.className = 'dot error';
  text.textContent = 'Server offline — run server.py';
  return false;
}

// --- UI Helpers ---
function toggleSection(id) {
  const el = document.getElementById(id);
  const arrow = document.getElementById(id + 'Arrow');
  el.classList.toggle('hidden');
  if (arrow) arrow.textContent = el.classList.contains('hidden') ? '▸' : '▾';
}

function setButtonsState(disabled) {
  ['btnMerge', 'btnAnalyze', 'btnFilter', 'btnRunAll'].forEach(id => {
    document.getElementById(id).disabled = disabled;
  });
}

function showProgress(show, pct) {
  const bar = document.getElementById('progressBar');
  const fill = document.getElementById('progressFill');
  bar.classList.toggle('hidden', !show);
  if (pct !== undefined) fill.style.width = pct + '%';
}

function log(msg, type = '') {
  const el = document.getElementById('log');
  const line = document.createElement('div');
  line.className = type;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  line.textContent = `[${ts}] ${msg}`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function setResult(id, value) {
  document.getElementById(id).textContent = value;
}

function showFiles(files) {
  const section = document.getElementById('filesSection');
  const list = document.getElementById('filesList');
  list.innerHTML = '';

  if (!files || files.length === 0) {
    section.classList.add('hidden');
    return;
  }

  section.classList.remove('hidden');
  files.forEach(f => {
    const item = document.createElement('div');
    item.className = 'file-item';
    item.innerHTML = `
      <span class="name">${f.name}</span>
      <span class="size">${formatSize(f.size)}</span>
      <button class="download-btn" onclick="downloadFile('${f.name}')">⬇ Download</button>
    `;
    list.appendChild(item);
  });
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// --- API Calls ---
async function uploadFiles() {
  const fullPcap = document.getElementById('fullPcap').files[0];
  const sipPcap = document.getElementById('sipPcap').files[0];

  if (!fullPcap || !sipPcap) {
    log('Please select both PCAP files', 'error');
    return null;
  }

  const formData = new FormData();
  formData.append('full_pcap', fullPcap);
  formData.append('sip_pcap', sipPcap);

  const outputDir = document.getElementById('outputDir').value;
  if (outputDir) {
    formData.append('output_dir', outputDir);
  }

  return formData;
}

async function runStep(step) {
  if (!await checkServer()) {
    log('Server is not running. Start it with: python3 server.py', 'error');
    return;
  }

  const formData = await uploadFiles();
  if (!formData) return;

  formData.append('step', step);

  setButtonsState(true);
  showProgress(true, 30);
  log(`Running step: ${step}...`, 'info');

  try {
    const res = await fetch(`${SERVER_URL}/process`, {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    showProgress(true, 100);

    if (data.success) {
      handleResult(data, step);
    } else {
      log(`Error: ${data.error}`, 'error');
    }
  } catch (e) {
    log(`Request failed: ${e.message}`, 'error');
  } finally {
    setButtonsState(false);
    setTimeout(() => showProgress(false), 500);
  }
}

async function runAll() {
  if (!await checkServer()) {
    log('Server is not running. Start it with: python3 server.py', 'error');
    return;
  }

  const formData = await uploadFiles();
  if (!formData) return;

  formData.append('step', 'all');

  setButtonsState(true);
  showProgress(true, 10);
  log('═══ Running all steps... ═══', 'info');

  try {
    const res = await fetch(`${SERVER_URL}/process`, {
      method: 'POST',
      body: formData
    });

    showProgress(true, 90);
    const data = await res.json();
    showProgress(true, 100);

    if (data.success) {
      handleResult(data, 'all');
    } else {
      log(`Error: ${data.error}`, 'error');
    }
  } catch (e) {
    log(`Request failed: ${e.message}`, 'error');
  } finally {
    setButtonsState(false);
    setTimeout(() => showProgress(false), 500);
  }
}

function handleResult(data, step) {
  // Log messages
  if (data.logs) {
    data.logs.forEach(l => {
      const type = l.includes('✅') ? 'success' :
                   l.includes('ERROR') ? 'error' :
                   l.includes('⚠️') ? 'warn' : '';
      log(l, type);
    });
  }

  // Signaling IPs
  if (data.signaling_ips) {
    setResult('signalingIps', data.signaling_ips.join(', ') || '—');
  }

  // SDP Media IPs
  if (data.sdp_media_ips) {
    setResult('sdpIps', data.sdp_media_ips.join(', ') || '—');
  }

  // Files
  if (data.files) {
    setResult('exportedFiles', `${data.files.length} file(s)`);
    showFiles(data.files);
    log(`🎉 Done! ${data.files.length} file(s) exported`, 'success');
  }

  if (step === 'merge') {
    log('Merge complete', 'success');
  }
}

async function downloadFile(filename) {
  try {
    const res = await fetch(`${SERVER_URL}/download/${encodeURIComponent(filename)}`);
    if (!res.ok) {
      log(`Download failed: ${res.statusText}`, 'error');
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    log(`Downloaded: ${filename}`, 'success');
  } catch (e) {
    log(`Download failed: ${e.message}`, 'error');
  }
}
