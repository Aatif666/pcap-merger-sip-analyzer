// --- Config ---
let SERVER_URL = 'http://localhost:5050';

// --- Init ---
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

  // Bind all event listeners
  document.getElementById('configToggle').addEventListener('click', () => toggleSection('configBody'));
  document.getElementById('logToggle').addEventListener('click', () => toggleSection('logBody'));
  document.getElementById('btnSaveConfig').addEventListener('click', saveConfig);
  document.getElementById('btnSaveDir').addEventListener('click', saveOutputDir);
  document.getElementById('btnRunAll').addEventListener('click', runAll);
  document.getElementById('btnDownload').addEventListener('click', function() {
    downloadFile('filtered_signaling_and_media.pcap');
  });

  checkServer();
});

async function saveConfig() {
  SERVER_URL = document.getElementById('serverUrl').value.replace(/\/$/, '');
  await chrome.storage.local.set({ serverUrl: SERVER_URL });
  log('Config saved', 'info');
  checkServer();
}

async function saveOutputDir() {
  const dir = document.getElementById('outputDir').value.trim();
  if (!dir) {
    log('Please enter a directory path', 'error');
    return;
  }
  await chrome.storage.local.set({ outputDir: dir });
  document.getElementById('dirStatus').textContent = '✅ Saved: ' + dir;
  log('Output directory saved: ' + dir, 'success');
}

// --- Server Status ---
async function checkServer() {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  try {
    const res = await fetch(SERVER_URL + '/health', { signal: AbortSignal.timeout(3000) });
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
  document.getElementById('btnRunAll').disabled = disabled;
}

function showProgress(show, pct) {
  const bar = document.getElementById('progressBar');
  const fill = document.getElementById('progressFill');
  if (show) {
    bar.classList.remove('hidden');
  } else {
    bar.classList.add('hidden');
  }
  if (pct !== undefined) fill.style.width = pct + '%';
}

function log(msg, type) {
  type = type || '';
  const el = document.getElementById('log');
  const line = document.createElement('div');
  line.className = type;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  line.textContent = '[' + ts + '] ' + msg;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function setResult(id, value) {
  document.getElementById(id).textContent = value;
}

function showFiles(files) {
  var section = document.getElementById('downloadSection');
  if (!files || files.length === 0) {
    section.classList.add('hidden');
    return;
  }
  // Check if the combined file exists in the results
  var hasFiltered = files.some(function(f) {
    return f.name === 'filtered_signaling_and_media.pcap';
  });
  if (hasFiltered) {
    section.classList.remove('hidden');
  } else {
    section.classList.add('hidden');
  }
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// --- API Calls ---
function getFormData() {
  var fullPcap = document.getElementById('fullPcap').files[0];
  var sipPcap = document.getElementById('sipPcap').files[0];

  if (!fullPcap || !sipPcap) {
    log('Please select both PCAP files', 'error');
    return null;
  }

  var formData = new FormData();
  formData.append('full_pcap', fullPcap);
  formData.append('sip_pcap', sipPcap);

  var outputDir = document.getElementById('outputDir').value.trim();
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

  var formData = getFormData();
  if (!formData) return;

  formData.append('step', step);

  setButtonsState(true);
  showProgress(true, 30);
  log('Running step: ' + step + '...', 'info');

  try {
    var res = await fetch(SERVER_URL + '/process', {
      method: 'POST',
      body: formData
    });

    var data = await res.json();
    showProgress(true, 100);

    if (data.success) {
      handleResult(data, step);
    } else {
      log('Error: ' + data.error, 'error');
    }
  } catch (e) {
    log('Request failed: ' + e.message, 'error');
  } finally {
    setButtonsState(false);
    setTimeout(function() { showProgress(false); }, 500);
  }
}

async function runAll() {
  if (!await checkServer()) {
    log('Server is not running. Start it with: python3 server.py', 'error');
    return;
  }

  var formData = getFormData();
  if (!formData) return;

  formData.append('step', 'all');

  setButtonsState(true);
  showProgress(true, 10);
  log('═══ Running all steps... ═══', 'info');

  try {
    var res = await fetch(SERVER_URL + '/process', {
      method: 'POST',
      body: formData
    });

    showProgress(true, 90);
    var data = await res.json();
    showProgress(true, 100);

    if (data.success) {
      handleResult(data, 'all');
    } else {
      log('Error: ' + data.error, 'error');
    }
  } catch (e) {
    log('Request failed: ' + e.message, 'error');
  } finally {
    setButtonsState(false);
    setTimeout(function() { showProgress(false); }, 500);
  }
}

function handleResult(data, step) {
  if (data.logs) {
    data.logs.forEach(function(l) {
      var type = '';
      if (l.indexOf('✅') >= 0) type = 'success';
      else if (l.indexOf('ERROR') >= 0) type = 'error';
      else if (l.indexOf('⚠️') >= 0) type = 'warn';
      log(l, type);
    });
  }

  if (data.signaling_ips) {
    setResult('signalingIps', data.signaling_ips.join(', ') || '—');
  }

  if (data.sdp_media_ips) {
    setResult('sdpIps', data.sdp_media_ips.join(', ') || '—');
  }

  if (data.files) {
    setResult('exportedFiles', data.files.length + ' file(s)');
    showFiles(data.files);
    log('🎉 Done! ' + data.files.length + ' file(s) exported', 'success');
  }

  if (step === 'merge') {
    log('Merge complete', 'success');
  }
}

async function downloadFile(filename) {
  try {
    var res = await fetch(SERVER_URL + '/download/' + encodeURIComponent(filename));
    if (!res.ok) {
      log('Download failed: ' + res.statusText, 'error');
      return;
    }
    var blob = await res.blob();
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    // Refresh the session after download
    setTimeout(function() {
      window.location.reload();
    }, 1000);
  } catch (e) {
    log('Download failed: ' + e.message, 'error');
  }
}
