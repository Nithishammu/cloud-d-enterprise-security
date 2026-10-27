(() => {
  'use strict';

  // A browser cannot launch the Python process from file://. The installed
  // macOS login service starts it in the background; send file-opened users to
  // the same-origin dashboard served by that local service.
  if (location.protocol === 'file:') {
    location.replace('http://127.0.0.1:8765/');
    return;
  }

  const $ = id => document.getElementById(id) || document.createElement("div");
  const fmt = value => new Intl.NumberFormat('en-US').format(value || 0);
  const isHostedDeployment = Boolean(location.hostname) && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  const vectors = [
    { id: 'auth', attacker: 'Credential-Bot', defender: 'AuthSentinel', domain: 'Credential attacks', icon: '⌑', target: 'Auth Server', color: 'var(--cyan)' },
    { id: 'flow', attacker: 'FloodSwarm', defender: 'FlowGuardian', domain: 'DDoS / traffic floods', icon: '≋', target: 'API Gateway', color: 'var(--blue)' },
    { id: 'query', attacker: 'Injector-X', defender: 'QueryShield', domain: 'SQL injection', icon: '⌘', target: 'Primary DB', color: 'var(--purple)' },
    { id: 'behavior', attacker: 'GhostUser', defender: 'BehaviorWatch', domain: 'Insider / anomalous behavior', icon: '◌', target: 'Customer DB', color: 'var(--amber)' }
  ];
  let sim = null;
  let running = false;
  let uploading = false;
  let cloudFileCache = [];
  let cloudActivity = [];
  let lastCloudFileIds = new Set();
  let progressHideTimer = null;
  let currentUser = null;
  let authMode = 'login';
  let accountType = 'customer';
  let currentFolders = [];
  let selectedFolderFilter = 'all';
  let uploadTriggeredFromNew = false;

  function updateDeploymentCopy() {
    const hosted = isHostedDeployment;
    $('storage-mode-pill').textContent = hosted ? 'HOSTED · PERSISTENT DISK' : 'LOCAL · PERSISTENT';
    $('cloud-storage-note').textContent = hosted
      ? 'AES-256-GCM file copies · Render persistent disk'
      : 'Automatic SQLite recovery copy';
    $('upload-storage-note').textContent = hosted
      ? 'Uploads are encrypted with AES-256-GCM before storage. The cloud service uses a persistent disk so data survives instance restarts.'
      : 'File contents are encrypted before storage and persist safely across app restarts.';
    $('stored-files-description').textContent = 'Folders and files are scoped to your account. Each saved revision is mirrored to the encrypted recovery database.';
    $('storage-footer-note').textContent = hosted
      ? 'Cloud-D Drive · AES-256-GCM encrypted and stored on a Render persistent disk (/var/cloud-d-data).'
      : 'Cloud-D Drive · AES-256-GCM encrypted and persistent in local databases.';
  }
  updateDeploymentCopy();

  async function authorizedFetch(path, { method = 'GET', body, headers } = {}) {
    try {
      const requestHeaders = new Headers(headers || {});
      return await fetch(path, { method, body, headers: requestHeaders, credentials: 'same-origin' });
    } catch (_error) {
      const message = isHostedDeployment
          ? 'Could not reach the hosted cloud service. It may be starting or waking; retry in a moment.'
          : 'Could not reach the Cloud-D service. The background service may still be starting; try again in a moment.';
      $('upload-status').textContent = message;
      throw new Error(message);
    }
  }

  async function request(path, options = {}) {
    const response = await authorizedFetch(path, options);
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401 && currentUser) {
      showAuthScreen('Your session expired. Please sign in again.');
    }
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status}).`);
    return payload;
  }

  function showAuthScreen(message = '') {
    currentUser = null;
    sim = null;
    lastCloudFileIds = new Set();
    cloudFileCache = [];
    cloudActivity = [];
    $('app-shell').hidden = true;
    $('auth-screen').hidden = false;
    setAuthMode('login', false);
    $('auth-message').textContent = message;
    $('auth-message').classList.toggle('error', Boolean(message));
    $('auth-message').classList.remove('error');
    $('auth-password').value = '';
  }

  async function enterWorkspace(user) {
    currentUser = user;
    $('auth-screen').hidden = true;
    $('app-shell').hidden = false;
    $('current-user-name').textContent = user.username;
    $('current-user-role').textContent = user.role === 'staff' ? 'Staff operator' : 'Customer';
    $('current-user-avatar').textContent = user.username.slice(0, 2).toUpperCase();
    document.querySelectorAll('.page').forEach(item => item.classList.toggle('active', item.id === 'page-cloud'));
    document.querySelectorAll('.nav button').forEach(item => item.classList.toggle('active', item.dataset.page === 'cloud'));
    $('crumb-current').textContent = 'Cloud Storage';
    document.querySelectorAll('.staff-only').forEach(item => { item.hidden = user.role !== 'staff'; });
    document.querySelectorAll('.cust-only').forEach(item => { item.hidden = user.role === 'staff'; });
    $('cloud-nodes-online').textContent = user.role === 'staff' ? 'Primary DB' : 'Customer DB';
    $('cloud-status-pill').textContent = user.role === 'staff' ? 'STAFF AREA' : 'CUSTOMER AREA';
    $('cloud-area-eyebrow').textContent = user.role === 'staff' ? 'Staff workspace · Primary DB' : 'Customer workspace · Customer DB';
    $('cloud-area-description').textContent = user.role === 'staff'
      ? 'Manage files in shared staff folders. Cloud-D routes them to the Primary DB and keeps encrypted recovery copies.'
      : 'Your files stay in your private Customer DB folders. Cloud-D assigns this storage area automatically.';
    try {
      await refreshFolders();
      setSimulation(await request('/api/state'));
      setCloudConnection('connected');
      $('upload-status').textContent = 'Signed in · files are encrypted and backed up automatically.';
    } catch (error) {
      $('upload-status').textContent = error.message;
      setCloudConnection('offline');
    }
  }

  let lastSelectedFolder = '';

  async function refreshFolders(selectedId = '') {
    const result = await request('/api/folders');
    const folders = result.folders || [];
    currentFolders = folders;
    const uploadSelect = $('upload-folder');
    const filterSelect = $('cloud-folder-filter');
    const previousUpload = selectedId || uploadSelect.value;
    const previousFilter = filterSelect.value;

    const folderBtn = $('create-folder-button');
    if (folderBtn) {
      folderBtn.hidden = false;
      folderBtn.style.display = '';
    }

    let uploadOptions = folders.map(folder => `<option value="${escapeHtml(folder.id)}">${escapeHtml(folder.name)}</option>`).join('');
    uploadOptions += '<option value="__new_folder__">＋ New folder…</option>';

    uploadSelect.innerHTML = uploadOptions;
    filterSelect.innerHTML = '<option value="all">All folders</option>' + folders.map(folder => `<option value="${escapeHtml(folder.id)}">${escapeHtml(folder.name)}</option>`).join('');

    if (folders.some(folder => folder.id === previousUpload)) {
      uploadSelect.value = previousUpload;
      lastSelectedFolder = previousUpload;
    } else if (folders.length > 0) {
      uploadSelect.value = folders[0].id;
      lastSelectedFolder = folders[0].id;
    }
    if (folders.some(folder => folder.id === previousFilter)) {
      filterSelect.value = previousFilter;
    } else if (selectedFolderFilter !== 'all' && !folders.some(folder => folder.id === selectedFolderFilter)) {
      selectedFolderFilter = 'all';
      filterSelect.value = 'all';
    }
    renderFoldersGrid();
    renderFilteredCloudFiles();
  }

  function renderFoldersGrid() {
    const container = $('cloud-folders-grid');
    if (!container) return;
    const totalFiles = cloudFileCache.length;

    // Count files per folder
    const fileCounts = {};
    for (const file of cloudFileCache) {
      fileCounts[file.folder_id] = (fileCounts[file.folder_id] || 0) + 1;
    }

    let html = `
      <div class="folder-tile ${selectedFolderFilter === 'all' ? 'active' : ''}" data-folder-id="all">
        <div class="folder-tile-icon">📂</div>
        <div class="folder-tile-content">
          <div class="folder-tile-name">All Folders</div>
          <div class="folder-tile-meta">${totalFiles} file${totalFiles === 1 ? '' : 's'} total</div>
        </div>
      </div>
    `;

    for (const folder of currentFolders) {
      const count = fileCounts[folder.id] || 0;
      const isActive = selectedFolderFilter === folder.id;
      html += `
        <div class="folder-tile ${isActive ? 'active' : ''}" data-folder-id="${escapeHtml(folder.id)}">
          <div class="folder-tile-icon">📁</div>
          <div class="folder-tile-content">
            <div class="folder-tile-name">${escapeHtml(folder.name)}</div>
            <div class="folder-tile-meta">${count} file${count === 1 ? '' : 's'}</div>
          </div>
        </div>
      `;
    }

    html += `
      <div class="folder-tile add-folder-tile" id="add-folder-tile" role="button" tabindex="0">
        <div class="folder-tile-icon">＋</div>
        <div class="folder-tile-content">
          <div class="folder-tile-name">New folder</div>
          <div class="folder-tile-meta">Create folder</div>
        </div>
      </div>
    `;

    container.innerHTML = html;
    if ($('folders-count-pill')) {
      $('folders-count-pill').textContent = `${currentFolders.length} FOLDER${currentFolders.length === 1 ? '' : 'S'}`;
    }

    if ($('folders-view-desc')) {
      if (selectedFolderFilter === 'all') {
        $('folders-view-desc').textContent = 'Showing all folders and files across your cloud workspace.';
      } else {
        const curF = currentFolders.find(f => f.id === selectedFolderFilter);
        $('folders-view-desc').textContent = curF
          ? `Filtered to folder “${curF.name}”. New uploads default to this folder.`
          : 'Select a folder to view its contents.';
      }
    }
  }

  function selectFolder(folderId) {
    selectedFolderFilter = folderId;
    if ($('cloud-folder-filter')) $('cloud-folder-filter').value = folderId;
    if (folderId !== 'all') {
      $('upload-folder').value = folderId;
      lastSelectedFolder = folderId;
    }
    renderFoldersGrid();
    renderFilteredCloudFiles();
  }

  async function submitAuth(event) {
    event.preventDefault();
    const message = $('auth-message');
    message.textContent = 'Verifying account…';
    message.classList.remove('error');
    const payload = {
      username: $('auth-username').value.trim(),
      password: $('auth-password').value
    };
    const path = authMode === 'login' ? '/api/auth/login' : '/api/auth/signup';
    if (authMode === 'signup') {
      payload.role = accountType;
      payload.email = $('auth-email').value.trim();
      payload.staff_registration_code = $('staff-registration-code').value.trim();
    }
    try {
      const response = await authorizedFetch(path, {
        method: 'POST', body: JSON.stringify(payload), headers: { 'Content-Type': 'application/json' }
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || 'Account verification failed.');
      $('auth-form').reset();
      setPasswordVisibility(false);
      await enterWorkspace(result.user);
    } catch (error) {
      message.textContent = error.message;
      message.classList.add('error');
    }
  }

  function setPasswordVisibility(visible) {
    const password = $('auth-password');
    const toggle = $('password-toggle');
    password.type = visible ? 'text' : 'password';
    toggle.checked = visible;
  }

  function setAuthMode(mode, clearMessage = true) {
    authMode = mode;
    const signup = mode === 'signup';
    setPasswordVisibility(false);
    $('auth-title').textContent = signup ? 'Create your Cloud-D account' : 'Sign in to your cloud';
    $('auth-copy').textContent = signup
      ? 'Enter your email address and choose a username. Choose Customer or Staff to set your cloud access.'
      : 'Sign in using your username and password. Cloud-D finds your account type automatically.';
    $('auth-email-field').hidden = !signup;
    $('auth-email').required = signup;
    $('auth-username').required = true;
    $('auth-username-label-text').textContent = signup ? 'Username' : 'Username or Email';
    if (signup) {
      $('auth-username').setAttribute('pattern', '[A-Za-z0-9][A-Za-z0-9._-]{2,29}');
      $('auth-username').setAttribute('maxlength', '30');
      $('auth-username').setAttribute('autocomplete', 'username');
    } else {
      $('auth-username').removeAttribute('pattern');
      $('auth-username').setAttribute('maxlength', '254');
      $('auth-username').setAttribute('autocomplete', 'username email');
    }
    $('auth-username-help').hidden = false;
    $('auth-username-help').textContent = signup
      ? 'Choose a username (3–30 letters, numbers, dots, underscores, or hyphens).'
      : 'Sign in with your username or registered email address.';
    $('auth-role-switch').hidden = !signup;
    $('auth-password').autocomplete = signup ? 'new-password' : 'current-password';
    $('auth-submit').textContent = signup ? 'Create account' : 'Sign in';
    $('staff-code-field').hidden = !signup || accountType !== 'staff';
    $('staff-registration-code').required = signup && accountType === 'staff';
    $('auth-mode-link').textContent = signup ? 'Sign in' : 'Create an account';
    $('auth-mode-link').href = signup ? '#login' : '#signup';
    $('auth-link-row').firstChild.textContent = signup ? 'Already have an account?' : 'New to Cloud-D?';
    if (clearMessage) {
      $('auth-message').textContent = '';
      $('auth-message').classList.remove('error');
    }
  }

  async function signOut() {
    try { await authorizedFetch('/api/auth/logout', { method: 'POST' }); } catch (_error) { /* clear the local view even offline */ }
    lastCloudFileIds = new Set();
    cloudFileCache = [];
    cloudActivity = [];
    showAuthScreen('You have signed out.');
  }

  async function createFolder(event) {
    event.preventDefault();
    const button = $('folder-form').querySelector('[type="submit"]');
    button.disabled = true;
    try {
      const result = await request('/api/folders', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: $('folder-name-input').value })
      });
      $('folder-dialog').close();
      $('folder-form').reset();
      await refreshFolders(result.folder.id);
      selectFolder(result.folder.id);
      showToast(`Folder “${result.folder.name}” created.`);
    } catch (error) {
      showToast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  function config() {
    return {
      threshold: Number($('threshold').value),
      intensity: $('intensity-select').value,
      active_vectors: [...document.querySelectorAll('.vector-toggle:checked')].map(input => input.value)
    };
  }

  function setSimulation(value) {
    const previousIds = lastCloudFileIds;
    const currentFiles = value.files || [];
    const newFiles = currentFiles.filter(file => !previousIds.has(file.id));
    const firstConnection = sim === null;
    sim = value;
    lastCloudFileIds = new Set(currentFiles.map(file => file.id));
    if (firstConnection) {
      addCloudActivity('Cloud workspace connected', `${fmt(currentFiles.length)} current files · ${fmt(value.storage?.backup_file_count || 0)} encrypted backup copies`, 'success');
    } else if (newFiles.length) {
      const versioned = newFiles.filter(file => Number(file.version) > 1);
      if (versioned.length === 1 && newFiles.length === 1) {
        addCloudActivity('New file version saved', `${versioned[0].filename} · version ${versioned[0].version}`, 'upload');
      } else {
        const locations = [...new Set(newFiles.map(file => file.folder_name).filter(Boolean))].join(', ');
        addCloudActivity(`${newFiles.length} file${newFiles.length === 1 ? '' : 's'} synced`, locations ? `Added or updated in ${locations}` : 'Added or updated in your assigned storage area', 'upload');
      }
    }
    if (value.threshold !== undefined) {
      $('threshold').value = $('threshold-lab').value = value.threshold;
      $('threshold-label').textContent = $('threshold-lab-label').textContent = Number(value.threshold).toFixed(2);
      $('engine-threshold').textContent = Number(value.threshold).toFixed(2);
    }
    if (value.intensity) $('intensity-select').value = value.intensity;
    if (value.active_vectors) {
      document.querySelectorAll('.vector-toggle').forEach(input => { input.checked = value.active_vectors.includes(input.value); });
    }
    renderCustomerSecurity();
    renderAll();
  }

  function addCloudActivity(title, detail, style = 'success') {
    cloudActivity.unshift({ title, detail, style, time: new Date() });
    cloudActivity = cloudActivity.slice(0, 8);
    renderCloudActivity();
  }

  function renderCloudActivity() {
    $('cloud-activity-list').innerHTML = cloudActivity.length ? cloudActivity.map(item => {
      const icon = item.style === 'upload' ? '⇧' : item.style === 'download' ? '⇩' : item.style === 'secure' ? '✓' : '◉';
      const when = item.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      return `<div class="activity-row"><span class="activity-icon ${item.style}">${icon}</span><div class="activity-copy"><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.detail)}</span></div><time class="activity-time">${when}</time></div>`;
    }).join('') : '<div class="empty">Cloud activity will appear here.</div>';
  }

  function setCloudConnection(state) {
    const badge = $('cloud-connection-badge');
    badge.className = `cloud-live ${state === 'connected' ? '' : state}`;
    $('cloud-connection-label').textContent = state === 'connected' ? 'CONNECTED' : state === 'syncing' ? 'SYNCING' : 'OFFLINE';
    if (state === 'connected') {
      $('cloud-last-sync').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
  }

  function showToast(message, error = false) {
    const toast = $('toast');
    toast.textContent = message;
    toast.style.background = error ? '#47252b' : '';
    toast.style.borderColor = error ? '#a44958' : '';
    toast.classList.add('show');
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => toast.classList.remove('show'), 3200);
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, character => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[character]);
  }

  function nav(page) {
    if (page !== 'cloud' && currentUser?.role !== 'staff') {
      showToast('Administrative simulation and architecture views are restricted to staff accounts.', true);
      return;
    }
    document.querySelectorAll('.page').forEach(item => item.classList.toggle('active', item.id === `page-${page}`));
    document.querySelectorAll('.nav button').forEach(button => button.classList.toggle('active', button.dataset.page === page));
    document.querySelectorAll('.mobile-tab-btn[data-page]').forEach(button => button.classList.toggle('active', button.dataset.page === page));
    $('crumb-current').textContent = ({
      cloud: 'Cloud Storage',
      threats: 'Threat Simulation',
      simulation: 'Agent Background',
      overview: 'Cloud Architecture',
      report: 'Security Report'
    })[page] || 'Cloud Storage';
    window.scrollTo(0, 0);
    if (page === 'cloud') syncCloudWorkspace();
  }

  async function syncCloudWorkspace() {
    if (!currentUser || document.visibilityState !== 'visible' || running || uploading) return;
    setCloudConnection('syncing');
    try {
      setSimulation(await request('/api/state'));
      await refreshFolders();
      setCloudConnection('connected');
    } catch (_error) {
      setCloudConnection('offline');
    }
  }

  function renderOverview() {
    const metrics = sim?.metrics;
    const counts = sim?.counts || {};
    const totalAttacks = metrics?.total_attacks || 0;
    const blocked = metrics?.blocked || 0;
    $('kpi-block').textContent = totalAttacks ? `${metrics.block_rate.toFixed(1)}%` : '—';
    $('kpi-block-note').innerHTML = totalAttacks ? `<strong>${blocked} blocked</strong> of ${totalAttacks} threat events` : 'Run threat analysis to evaluate defense';
    $('kpi-data').textContent = metrics ? `${metrics.protection_rate.toFixed(3)}%` : '—';
    $('kpi-data-note').textContent = metrics ? `${fmt(metrics.protected)} / ${fmt(metrics.total_records)} actual records protected` : 'Records protected / stored';
    $('kpi-response').textContent = sim?.has_run ? `${sim.latency_ms} ms` : '—';
    $('kpi-contained').innerHTML = `${blocked} <small style="font-size:12px;color:#8190a8;font-weight:600">/ ${totalAttacks}</small>`;
    $('kpi-contained-note').textContent = sim?.round ? `${sim.round} of ${sim.max_rounds} rounds processed` : 'No attack rounds processed';
    $('round-pill').textContent = `${running ? 'RUNNING' : sim?.game_over ? 'COMPLETE' : sim?.round ? 'IN PROGRESS' : 'READY'} · ${sim?.round || 0} ROUNDS`;
    for (const vector of vectors) $(`node-${vector.id}`).textContent = counts[vector.id]?.actions || 0;
    for (let i = 1; i <= 4; i++) $(`link-${i}`).classList.toggle('active', running);
    renderAgentSummary();
    renderAttackSummary();
    renderFeed();
    renderNodes();
  }

  function renderAgentSummary() {
    const counts = sim?.counts || {};
    $('agent-summary').innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0 };
      const rate = count.scored ? count.blocked / count.scored * 100 : 0;
      return `<div class="agent-row"><div class="agent-id"><span class="agent-icon" style="--agent-color:${vector.color}">${vector.icon}</span>${vector.defender}</div><div class="bar-wrap"><div class="bar" style="--agent-color:${vector.color};width:${rate}%"></div></div><div class="agent-score">${count.scored ? `${rate.toFixed(0)}%` : '—'}</div></div>`;
    }).join('');
  }

  function renderAttackSummary() {
    const counts = sim?.counts || {};
    $('attack-summary').innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0 };
      const passed = count.scored - count.blocked;
      return `<div class="agent-row"><div class="agent-id"><span class="agent-icon" style="--agent-color:${vector.color}">${vector.icon}</span>${vector.attacker}</div><div style="color:#8796ad;font-size:9px">${count.scored} attempts · ${passed} passed</div><div class="agent-score"><span class="pill ${passed ? 'red' : count.scored ? 'green' : 'blue'}">${passed ? 'ACTIVE' : count.scored ? 'CLEAR' : 'IDLE'}</span></div></div>`;
    }).join('');
    $('attack-count-label').textContent = `${sim?.metrics?.total_attacks || 0} events`;
  }

  function renderFeed() {
    const events = [...(sim?.attack_log || [])].reverse().slice(0, 7);
    $('event-feed').innerHTML = events.length ? events.map(event => {
      const result = event.blocked ? 'Threat contained' : event.damage ? 'Threat impacted node' : 'Attempt caused no damage';
      const status = event.blocked ? '' : event.damage ? 'missed' : '';
      return `<div class="feed-item"><i class="feed-dot ${status}"></i><div><div class="feed-title">${result} · ${event.attacker}</div><div class="feed-detail">${event.action || 'No qualifying defense'} · Utility ${Number(event.utility).toFixed(2)} · ${event.target}${event.damage ? ` · ${event.damage} damage` : ''}</div></div><span class="feed-time">R${event.round}</span></div>`;
    }).join('') : '<div class="empty">Run threat analysis to see agent decisions and attack outcomes.</div>';
  }

  function renderNodes() {
    const nodes = sim?.nodes || [];
    renderStorage();
    renderCloudFiles(sim?.files || []);
    $('cloud-nodes-online').textContent = currentUser?.role === 'staff' ? 'Primary DB' : currentUser ? 'Customer DB' : '—';
    $('cloud-status-pill').textContent = currentUser?.role === 'staff' ? 'STAFF AREA' : currentUser ? 'CUSTOMER AREA' : 'YOUR AREA';
    $('cloud-record-count').textContent = fmt((sim?.files || []).reduce((total, file) => total + Number(file.record_count || 0), 0));
    $('cloud-storage-size').textContent = fmt(sim?.storage?.backup_file_count || 0);
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${(bytes / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
  }

  function renderStorage() {
    const storage = sim?.storage || {};
    const persistent = storage.persistent === undefined ? !isHostedDeployment : Boolean(storage.persistent);
    $('database-engine').textContent = storage.engine || 'SQLite';
    $('database-encryption').textContent = storage.encryption || 'AES-256-GCM';
    $('database-files').textContent = fmt(storage.backup_file_count || 0);
    $('database-size').textContent = storage.backup_ready ? 'Ready' : 'Unavailable';
    $('database-heading').textContent = persistent ? 'Primary and recovery storage are ready' : 'Hosted primary and recovery storage are temporary';
    $('database-note').textContent = storage.storage_note || (isHostedDeployment
      ? 'The hosted service uses temporary storage. Encrypted file contents may be lost when the instance is replaced.'
      : 'Encrypted file contents and the separate SQLite recovery copy stay in this device’s Cloud-D data folder. Account and folder metadata are not encrypted as a whole database.');
    $('database-status-pill').textContent = persistent ? 'FILE COPIES READY' : 'TEMPORARY HOSTED';
    $('database-status-pill').className = `pill ${persistent && storage.backup_ready ? 'green' : 'amber'}`;
  }

  function renderCloudFiles(files) {
    cloudFileCache = files || [];
    const storageBytes = cloudFileCache.reduce((total, file) => total + Number(file.size_bytes || 0), 0);
    $('cloud-file-count').textContent = fmt(cloudFileCache.length);
    $('cloud-storage-size').textContent = formatBytes(storageBytes);
    renderFoldersGrid();
    renderFilteredCloudFiles();
  }

  function renderFilteredCloudFiles() {
    const query = ($('cloud-file-search').value || '').trim().toLowerCase();
    const selectedFolder = selectedFolderFilter;
    const selectedType = $('cloud-type-filter').value;
    if ($('cloud-folder-filter') && $('cloud-folder-filter').value !== selectedFolder) {
      $('cloud-folder-filter').value = selectedFolder;
    }
    const files = cloudFileCache.filter(file => {
      const matchesText = !query || `${file.filename} ${file.folder_name}`.toLowerCase().includes(query);
      const matchesFolder = selectedFolder === 'all' || file.folder_id === selectedFolder;
      const matchesType = selectedType === 'all' || (selectedType === 'data' ? file.kind === 'data' : file.kind !== 'data');
      return matchesText && matchesFolder && matchesType;
    });
    if ($('stored-files-description')) {
      if (selectedFolder === 'all') {
        $('stored-files-description').textContent = 'Files are scoped to your account and assigned folders.';
      } else {
        const curF = currentFolders.find(f => f.id === selectedFolder);
        $('stored-files-description').textContent = curF
          ? `Viewing files in folder “${curF.name}”.`
          : 'Files in selected folder.';
      }
    }
    $('stored-files-pill').textContent = files.length === cloudFileCache.length
      ? `${files.length} FILE${files.length === 1 ? '' : 'S'}`
      : `${files.length} OF ${cloudFileCache.length} FILES`;
    $('cloud-files-body').innerHTML = files.length ? files.map(file => {
      const name = escapeHtml(file.filename);
      const kind = file.kind === 'data' ? 'Structured data' : 'Document';
      const icon = file.kind === 'data' ? '▦' : '▤';
      const version = Number(file.version || 1);
      const versions = Number(file.version_count || 1);
      const savedAt = file.created_at ? new Date(file.created_at).toLocaleString() : 'Saved';
      const backupStatus = file.backup_available ? '<span class="pill green">BACKED UP</span>' : '<span class="pill amber">NO COPY</span>';
      const restoreButton = !file.primary_available ? `<button class="btn primary" type="button" data-restore-file="${escapeHtml(file.id)}">Restore</button>` : '';
      const nodeShard = `<span class="pill blue" style="font-size:10px;padding:2px 7px;" title="Encrypted shard on Node ${file.node_id || 2}">Node ${file.node_id || 2} · 🛡</span>`;
      return `<tr><td><div class="file-entry"><span class="file-icon ${file.kind === 'data' ? 'structured' : ''}">${icon}</span><span class="file-entry-text"><strong>${name}</strong><small>Version ${version} · ${nodeShard} · ${escapeHtml(savedAt)}</small></span></div></td><td>${escapeHtml(file.folder_name)}</td><td>${formatBytes(Number(file.size_bytes || 0))}</td><td>${kind}</td><td>${fmt(file.record_count)}</td><td>${backupStatus}</td><td><div class="file-actions">${restoreButton}<button class="btn" type="button" data-preview-file="${escapeHtml(file.id)}" data-filename="${name}" title="Preview decrypted contents">👁 Preview</button><button class="btn" type="button" data-download-file="${escapeHtml(file.id)}" data-filename="${name}">Download</button><button class="btn" type="button" data-view-versions="${escapeHtml(file.logical_id)}" data-filename="${name}" data-folder-id="${escapeHtml(file.folder_id)}">◷ Versions · ${versions}</button><button class="btn" type="button" data-add-version="${escapeHtml(file.logical_id)}" data-filename="${name}" data-folder-id="${escapeHtml(file.folder_id)}" title="Upload next version of this file">⬆ New Version</button><button class="btn" type="button" data-replace-file="${escapeHtml(file.logical_id)}" data-filename="${name}" data-folder-id="${escapeHtml(file.folder_id)}" title="Replace/overwrite this file">⇄ Replace</button><button class="btn" type="button" data-verify-file="${escapeHtml(file.id)}" data-filename="${name}" title="Verify AES-256-GCM integrity proof">🔐 Verify</button><button class="btn danger" type="button" data-delete-file="${escapeHtml(file.id)}" data-filename="${name}">Delete</button></div></td></tr>`;
    }).join('') : `<tr><td colspan="7" class="empty">${cloudFileCache.length ? 'No matching files. Change the search or filters.' : 'Your cloud is ready. Upload a file to see it here.'}</td></tr>`;
  }

  function renderAttackCards() {
    const el = $('attack-cards');
    if (!el) return;
    const counts = sim?.counts || {};
    const active = sim?.active_vectors || vectors.map(item => item.id);
    el.innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0 };
      const enabled = active.includes(vector.id);
      const algorithm = vector.id === 'auth' ? 'Minimax attacker' : vector.id === 'query' ? 'Expectimax defense' : vector.id === 'flow' ? 'Traffic growth model' : 'Stochastic success model';
      return `<article class="card attack-card" style="--attack-color:${vector.color};opacity:${enabled ? 1 : .45}"><div class="top"><span class="attack-symbol">${vector.icon}</span><span class="pill ${count.scored ? (count.scored === count.blocked ? 'green' : 'amber') : 'blue'}">${count.scored ? `${count.blocked}/${count.scored} BLOCKED` : enabled ? 'READY' : 'DISABLED'}</span></div><div class="attack-name">${vector.attacker}</div><div class="attack-type">${vector.domain} · ${algorithm}</div><div class="attack-stats"><span>Target node</span><strong>${vector.target}</strong></div></article>`;
    }).join('');
  }

  function renderAttackTable() {
    const rows = [...(sim?.attack_log || [])].reverse().slice(0, 16);
    $('attack-table').innerHTML = rows.length ? rows.map(event => `<tr><td>${String(event.round).padStart(2, '0')}</td><td><strong>${event.attacker}</strong><div class="node-meta">${event.tactic || event.attack_type}</div></td><td>${event.target}</td><td>${Number(event.utility).toFixed(2)}</td><td>${event.action || 'No action'}</td><td><span class="pill ${event.blocked ? 'green' : event.damage ? 'red' : 'amber'}">${event.blocked ? 'BLOCKED' : event.damage ? 'IMPACT' : 'NO DAMAGE'}</span></td></tr>`).join('') : '<tr><td colspan="6" class="empty">No events yet. Start threat analysis to populate defense decisions.</td></tr>';
  }

  function renderAgentCards() {
    const el = $('agent-cards');
    if (!el) return;
    const blurbs = {
      auth: 'Scores credential attack signals and proposes IP blocking or account locks. Cross-round signature counts are shared through the cloud state. Credential-Bot searches two moves ahead with Minimax.',
      flow: 'Monitors simulated request rates and proposes rate limiting when a flood exceeds the node’s traffic tolerance.',
      query: 'Uses Expectimax chance nodes to compare query sanitization, rejection, and monitoring against uncertain parser outcomes.',
      behavior: 'Flags anomalous workforce access and estimates session-revocation utility from simulated credential-harvest evidence.'
    };
    const counts = sim?.counts || {};
    const defenders = sim?.defenders || [];
    el.innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0, actions: 0, last: 0 };
      const defender = defenders.find(item => item.vector_id === vector.id) || {};
      const searchValue = defender.search_nodes ? defender.search_nodes : vector.id === 'auth' ? (sim?.attackers?.find(item => item.vector_id === 'auth')?.search_nodes || 0) : 0;
      const method = vector.id === 'query' ? 'Expectimax' : 'Utility heuristic';
      const rate = count.scored ? `${(count.blocked / count.scored * 100).toFixed(1)}%` : '—';
      return `<article class="card agent-card"><div class="agent-card-head"><div class="agent-card-name"><span class="agent-icon" style="--agent-color:${vector.color}">${vector.icon}</span><div><h3>${vector.defender}</h3><div class="node-meta">${vector.domain}</div></div></div><span class="pill ${defender.active ? 'green' : 'blue'}">${defender.active ? 'ACTIVE' : 'READY'}</span></div><p>${blurbs[vector.id]}</p><div class="metric-pairs"><div><span>Events scored</span><strong>${count.scored}</strong></div><div><span>Actions proposed</span><strong>${count.actions}</strong></div><div><span>Decision method</span><strong>${method}</strong></div></div><div class="metric-pairs" style="border:0;padding-top:8px"><div><span>Containment</span><strong>${rate}</strong></div><div><span>Search nodes</span><strong>${searchValue || '—'}</strong></div><div><span>Last utility</span><strong>${count.scored ? Number(count.last).toFixed(2) : '—'}</strong></div></div></article>`;
    }).join('');
    $('agents-state').textContent = sim?.has_run ? `${sim.round} rounds · ${sim.metrics.blocked} blocks` : 'Awaiting threat evaluation';
  }

  function renderReport() {
    const metrics = sim?.metrics;
    const counts = sim?.counts || {};
    $('report-block').textContent = metrics?.total_attacks ? `${metrics.block_rate.toFixed(1)}%` : '—';
    $('report-block-note').textContent = metrics?.total_attacks ? `${metrics.blocked} / ${metrics.total_attacks} attack events blocked` : 'No events yet';
    $('report-data').textContent = metrics ? `${metrics.protection_rate.toFixed(3)}%` : '—';
    $('report-data-note').textContent = metrics ? `${fmt(metrics.protected)} / ${fmt(metrics.total_records)} records protected` : 'No records assessed';
    $('report-response').textContent = sim?.has_run ? `${sim.latency_ms} ms` : '—';
    $('report-exposed').textContent = metrics ? fmt(metrics.compromised) : '—';
    $('report-damage').textContent = metrics ? `${metrics.damage_taken} HP` : '—';
    $('report-rounds').textContent = sim?.round || 0;
    $('report-date').textContent = sim?.last_run_at ? new Date(sim.last_run_at).toLocaleString() : 'Not run';
    $('report-summary').textContent = metrics
      ? `The ${metrics.rounds}-round Cloud-D threat evaluation processed ${metrics.total_attacks} threat events across ${(sim.active_vectors || []).length} enabled vectors. Defender agents blocked ${metrics.blocked} events (${metrics.block_rate.toFixed(1)}%). The cloud contains ${fmt(metrics.total_records)} individual records; ${fmt(metrics.compromised)} were compromised (${metrics.protection_rate.toFixed(3)}% protected). Total node damage sustained: ${metrics.damage_taken}. Uploaded file contents are not included in this report.`
      : 'No threat evaluation has been run yet. Start an evaluation to populate this report.';
    $('report-agent-table').innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0, actions: 0, last: 0 };
      const rate = count.scored ? `${(count.blocked / count.scored * 100).toFixed(1)}%` : '—';
      return `<tr><td><strong>${vector.defender}</strong></td><td>${vector.domain}</td><td>${count.scored}</td><td>${count.actions}</td><td>${rate}</td><td>${count.scored ? Number(count.last).toFixed(2) : '—'}</td></tr>`;
    }).join('');
    const nodes = sim?.nodes || [];
    $('node-table').innerHTML = nodes.length ? nodes.map(node => {
      const statusClass = node.status === 'HEALTHY' ? 'green' : node.status === 'DAMAGED' ? 'amber' : node.status === 'COMPROMISED' ? 'red' : 'amber';
      const observed = (sim.attack_log || []).filter(event => event.target === node.name).length;
      const defended = (sim.attack_log || []).filter(event => event.target === node.name && event.blocked).length;
      return `<tr><td><strong>${node.name}</strong><div class="node-meta">${node.role} · ${node.uploaded_records} uploaded</div></td><td><span class="pill ${statusClass}">${node.status}</span></td><td>${observed}</td><td>${defended}</td><td>${node.compromised_records} records exposed · ${node.health} HP</td></tr>`;
    }).join('') : '<tr><td colspan="5" class="empty">Cloud nodes initialize when the defense network starts.</td></tr>';
  }

  function renderAll() {
    renderOverview();
    renderAttackCards();
    renderAttackTable();
    renderAgentCards();
    renderReport();
  }

  async function runSimulation({ oneRound = false } = {}) {
    if (running) return;
    const selected = config();
    if (!selected.active_vectors.length) { showToast('Select at least one attack vector.', true); nav('threats'); return; }
    running = true;
    renderOverview();
    try {
      const rounds = oneRound ? 1 : Number($('round-select').value);
      if (!oneRound || !sim || sim.game_over) sim = await request('/api/restart', { method: 'POST', body: JSON.stringify(selected), headers: { 'Content-Type': 'application/json' } });
      for (let index = 0; index < rounds; index++) {
        if (sim.game_over || sim.round >= sim.max_rounds) break;
        sim = await request('/api/round', { method: 'POST', body: JSON.stringify(selected), headers: { 'Content-Type': 'application/json' } });
        renderAll();
        if (!oneRound) await new Promise(resolve => setTimeout(resolve, 110));
      }
      renderAll();
      showToast(`Round ${sim.round} · ${sim.metrics.blocked} of ${sim.metrics.total_attacks} attacks blocked.`);
    } catch (error) {
      showToast(error.message, true);
    } finally {
      running = false;
      renderOverview();
    }
  }

  async function uploadDataset(event) {
    event.preventDefault();
    const files = [...$('upload-file').files];
    if (!files.length) { showToast('Choose at least one document or data file first.', true); return; }
    const totalBytes = files.reduce((total, file) => total + file.size, 0);
    if (totalBytes > 10 * 1024 * 1024) { showToast('Selected files must total 10 MB or less.', true); return; }
    const selectedFolder = $('upload-folder').value;
    if (!selectedFolder || selectedFolder === '__new_folder__') {
      showToast('Please select or create a destination folder first.', true);
      return;
    }
    const button = $('upload-button');
    button.disabled = true;
    uploading = true;
    $('upload-progress-panel').classList.add('active');
    clearTimeout(progressHideTimer);
    button.textContent = 'Uploading…';
    $('upload-status').textContent = `Connecting ${files.length} file${files.length === 1 ? '' : 's'} to ${$('upload-folder').selectedOptions[0]?.textContent || 'your folder'}…`;
    updateUploadProgress(0, 'Preparing encrypted upload…');
    try {
      const formData = new FormData($('upload-form'));
      const progress = percent => {
        const stage = percent >= 100 ? 'Transfer complete · encrypting and saving in SQLite…' : `Transferring ${formatBytes(totalBytes * percent / 100)}`;
        updateUploadProgress(percent, stage);
        $('upload-status').textContent = stage;
      };
      let result;
      try {
        result = await uploadWithProgress(formData, progress);
      } catch (error) {
        if (error.status !== 409 || !error.payload?.duplicates?.length) throw error;
        const duplicateMode = await chooseDuplicateMode(error.payload.duplicates);
        if (!duplicateMode) throw new Error('Upload cancelled. No files were changed.');
        formData.set('duplicate_mode', duplicateMode);
        $('upload-status').textContent = duplicateMode === 'replace'
          ? 'Replacing existing file and overwriting version history…'
          : 'Saving as new version on Cloud Drive…';
        result = await uploadWithProgress(formData, progress);
      }
      updateUploadProgress(100, 'Encrypted and saved to the cloud node.');
      setSimulation(result.state);
      const updateSummary = (result.file_updates || []).map(file => `${file.filename} · v${file.version}`).join(', ');
      $('upload-status').textContent = `${fmt(result.loaded)} records saved to ${result.folder}${updateSummary ? ` · ${updateSummary}` : ''}. Encrypted backup created.`;
      $('upload-form').reset();
      $('upload-folder').value = selectedFolder;
      $('upload-selection').textContent = 'No files selected';
      showToast(`${fmt(result.loaded)} records saved to ${result.folder}.`);
    } catch (error) {
      if (error.status === 401) showAuthScreen('Your session expired. Please sign in again.');
      $('upload-status').textContent = error.message;
      updateUploadProgress(0, `Upload failed · ${error.message}`);
      showToast(error.message, true);
    } finally {
      uploading = false;
      button.disabled = false;
      button.textContent = 'Upload encrypted';
      progressHideTimer = setTimeout(() => $('upload-progress-panel').classList.remove('active'), 2800);
    }
  }

  function updateUploadProgress(percent, stage) {
    const clamped = Math.max(0, Math.min(100, percent));
    $('upload-progress-fill').style.width = `${clamped}%`;
    $('upload-progress-percent').textContent = `${Math.round(clamped)}%`;
    $('upload-progress-stage').textContent = stage;
  }

  function uploadWithProgress(formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/upload');
      xhr.timeout = 120000;
      xhr.withCredentials = true;
      xhr.upload.addEventListener('progress', event => {
        if (event.lengthComputable) onProgress(Math.round(event.loaded / event.total * 100));
      });
      xhr.addEventListener('load', () => {
        let payload = {};
        try { payload = JSON.parse(xhr.responseText || '{}'); } catch (_error) { /* report status below */ }
        if (xhr.status < 200 || xhr.status >= 300) {
          const error = new Error(payload.error || `Upload failed (${xhr.status}).`);
          error.status = xhr.status;
          error.payload = payload;
          reject(error);
          return;
        }
        resolve(payload);
      });
      xhr.addEventListener('error', () => reject(new Error('The cloud connection ended during upload. Check the connection and retry.')));
      xhr.addEventListener('timeout', () => reject(new Error('Upload timed out. Try a smaller batch of files.')));
      xhr.addEventListener('abort', () => reject(new Error('Upload was cancelled.')));
      xhr.send(formData);
    });
  }

  function chooseDuplicateMode(duplicates) {
    const dialog = $('duplicate-dialog');
    $('duplicate-file-list').innerHTML = duplicates.map(item =>
      `<li><strong>${escapeHtml(item.filename)}</strong><span>Current version ${Number(item.version) || 1} · ${Number(item.version_count) || 1} saved</span></li>`
    ).join('');
    return new Promise(resolve => {
      dialog.returnValue = '';
      const onClose = () => resolve(dialog.returnValue === 'new_version' || dialog.returnValue === 'replace' ? dialog.returnValue : null);
      dialog.addEventListener('close', onClose, { once: true });
      dialog.showModal();
    });
  }

  async function openVersionHistory(logicalId, filename) {
    const dialog = $('version-dialog');
    $('version-dialog-title').textContent = `Version history · ${filename}`;
    $('version-list').innerHTML = '<div class="empty">Loading versions…</div>';
    dialog.showModal();
    try {
      const result = await request(`/api/file-groups/${encodeURIComponent(logicalId)}/versions`);
      const activeVersion = (result.versions || []).find(v => v.current);
      $('version-list').innerHTML = result.versions.map(version => {
        const savedAt = new Date(version.created_at).toLocaleString();
        const status = version.current ? '<span class="pill green">CURRENT</span>' : '<span class="pill blue">HISTORY</span>';
        const promoteBtn = !version.current ? `<button class="btn primary" type="button" data-promote-file="${escapeHtml(version.id)}" data-logical-id="${escapeHtml(logicalId)}" data-filename="${escapeHtml(filename)}" data-version="${Number(version.version)}">↺ Restore Active</button>` : '';
        const diffBtn = (!version.current && activeVersion) ? `<button class="btn" type="button" data-diff-version="${escapeHtml(version.id)}" data-active-id="${escapeHtml(activeVersion.id)}" data-filename="${escapeHtml(filename)}" data-version="${Number(version.version)}" data-active-version="${Number(activeVersion.version)}" title="Compare this version with active version">⇄ Diff</button>` : '';
        return `<div class="version-row"><div class="version-main"><div><strong>Version ${Number(version.version)}</strong> ${status} <span class="pill blue" style="font-size:9.5px;padding:2px 6px;">Node ${version.node_id || 2} · 🛡</span></div><small>${escapeHtml(savedAt)} · ${formatBytes(Number(version.size_bytes || 0))} · ${fmt(version.record_count)} record${Number(version.record_count) === 1 ? '' : 's'}</small></div><div class="file-actions">${promoteBtn}<button class="btn" type="button" data-preview-file="${escapeHtml(version.id)}" data-filename="${escapeHtml(filename)}">👁 Preview</button>${diffBtn}<button class="btn" type="button" data-verify-file="${escapeHtml(version.id)}" data-filename="${escapeHtml(filename)}">🔐 Verify</button><button class="btn" type="button" data-download-file="${escapeHtml(version.id)}" data-filename="${escapeHtml(filename)}">Download</button><button class="btn danger" type="button" data-delete-file="${escapeHtml(version.id)}" data-filename="${escapeHtml(filename)}" data-version-num="${Number(version.version)}" data-logical-id="${escapeHtml(logicalId)}">Delete</button></div></div>`;
      }).join('') || '<div class="empty">No saved versions were found.</div>';
    } catch (error) {
      $('version-list').innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }

  let activeVersionTarget = null;

  function handleCloudFileAction(event) {
    const restoreButton = event.target.closest('[data-restore-file]');
    if (restoreButton) {
      restoreBackedUpFile(restoreButton.dataset.restoreFile, restoreButton);
      return;
    }
    const versionButton = event.target.closest('[data-view-versions]');
    if (versionButton) {
      activeVersionTarget = { logicalId: versionButton.dataset.viewVersions, filename: versionButton.dataset.filename, folderId: versionButton.dataset.folderId };
      openVersionHistory(versionButton.dataset.viewVersions, versionButton.dataset.filename);
      return;
    }
    const addVersionButton = event.target.closest('[data-add-version]');
    if (addVersionButton) {
      activeVersionTarget = { logicalId: addVersionButton.dataset.addVersion, filename: addVersionButton.dataset.filename, folderId: addVersionButton.dataset.folderId, mode: 'new_version' };
      $('version-file-picker').click();
      return;
    }
    const replaceButton = event.target.closest('[data-replace-file]');
    if (replaceButton) {
      activeVersionTarget = { logicalId: replaceButton.dataset.replaceFile, filename: replaceButton.dataset.filename, folderId: replaceButton.dataset.folderId, mode: 'replace' };
      $('replace-file-picker').click();
      return;
    }
    const previewButton = event.target.closest('[data-preview-file]');
    if (previewButton) {
      previewCloudFile(previewButton.dataset.previewFile, previewButton.dataset.filename);
      return;
    }
    const diffButton = event.target.closest('[data-diff-version]');
    if (diffButton) {
      diffCloudVersions(
        diffButton.dataset.diffVersion,
        diffButton.dataset.activeId,
        diffButton.dataset.version,
        diffButton.dataset.activeVersion,
        diffButton.dataset.filename
      );
      return;
    }
    const promoteButton = event.target.closest('[data-promote-file]');
    if (promoteButton) {
      promoteFileVersion(promoteButton.dataset.promoteFile, promoteButton.dataset.logicalId, promoteButton.dataset.filename, promoteButton.dataset.version);
      return;
    }
    const verifyButton = event.target.closest('[data-verify-file]');
    if (verifyButton) {
      verifyFileIntegrity(verifyButton.dataset.verifyFile, verifyButton.dataset.filename);
      return;
    }
    const downloadButton = event.target.closest('[data-download-file]');
    if (downloadButton) {
      downloadCloudFile(downloadButton.dataset.downloadFile, downloadButton.dataset.filename)
        .catch(error => showToast(error.message, true));
      return;
    }
    const deleteButton = event.target.closest('[data-delete-file]');
    if (deleteButton) {
      deleteCloudFile(deleteButton.dataset.deleteFile, deleteButton.dataset.filename, deleteButton);
      return;
    }
  }

  async function deleteCloudFile(fileId, filename, button) {
    const versionNum = button.dataset.versionNum;
    const logicalId = button.dataset.logicalId;
    const isSingleVersion = Boolean(versionNum);
    const confirmMessage = isSingleVersion
      ? `Delete version ${versionNum} of "${filename}"?`
      : `Are you sure you want to delete "${filename}"?\n\nThis will permanently remove the file and all its versions from the cloud.`;

    if (!confirm(confirmMessage)) {
      return;
    }
    button.disabled = true;
    const oldText = button.textContent;
    button.textContent = 'Deleting…';
    try {
      const deleteUrl = isSingleVersion
        ? `/api/files/${encodeURIComponent(fileId)}?all=false`
        : `/api/files/${encodeURIComponent(fileId)}?all=true`;
      const result = await request(deleteUrl, { method: 'DELETE' });
      setSimulation(result.state);
      showToast(isSingleVersion ? `Version ${versionNum} of ${filename} deleted.` : `${filename} deleted successfully.`);
      addCloudActivity('File deleted', isSingleVersion ? `${filename} (v${versionNum})` : filename, 'alert');
      if (isSingleVersion && $('version-dialog').open && logicalId) {
        const remaining = (result.state?.files || []).find(f => f.logical_id === logicalId);
        if (remaining) {
          await openVersionHistory(logicalId, filename);
        } else {
          $('version-dialog').close();
        }
      } else if ($('version-dialog').open) {
        $('version-dialog').close();
      }
    } catch (error) {
      showToast(error.message, true);
      button.disabled = false;
      button.textContent = oldText;
    }
  }

  async function restoreBackedUpFile(fileId, button) {
    button.disabled = true;
    const oldText = button.textContent;
    button.textContent = 'Restoring…';
    try {
      const result = await request(`/api/files/${encodeURIComponent(fileId)}/restore`, { method: 'POST' });
      setSimulation(result.state);
      showToast(`${result.filename} restored from the encrypted backup.`);
      addCloudActivity('File restored from backup', result.filename, 'secure');
    } catch (error) {
      showToast(error.message, true);
    } finally {
      button.disabled = false;
      button.textContent = oldText;
    }
  }

  function exportJson() {
    if (!sim) { showToast('Connect to the Cloud-D service before exporting.', true); return; }
    const report = {
      project: 'Cloud-D — A Multi-Agent Decision System for Enterprise Cloud Security',
      author: 'Nithish M · 24X064', simulation_only: true,
      generated_at: sim.last_run_at,
      configuration: { round: sim.round, threshold: sim.threshold, intensity: sim.intensity, active_vectors: sim.active_vectors },
      algorithms: { credential_bot: 'Minimax depth 2', query_shield: 'Expectimax with chance nodes', others: 'Rule and utility heuristics' },
      metrics: sim.metrics,
      counts: sim.counts,
      nodes: sim.nodes,
      attack_log: sim.attack_log,
      events: sim.events
    };
    downloadFile('cloud-d-defense-report.json', JSON.stringify(report, null, 2), 'application/json');
  }

  function exportCsv() {
    if (!sim) { showToast('Connect to the Cloud-D service before exporting.', true); return; }
    const rows = [['round','attacker','attack_type','target_node','utility','defender','action','outcome','damage','record_id','payload']];
    for (const event of sim.attack_log) rows.push([event.round,event.attacker,event.attack_type,event.target,event.utility,event.defender,event.action,event.blocked ? 'blocked' : event.damage ? 'impact' : 'no_damage',event.damage,event.record_id,event.payload]);
    const csv = rows.map(row => row.map(value => `"${String(value ?? '').replaceAll('"','""')}"`).join(',')).join('\n');
    downloadFile('cloud-d-events.csv', csv, 'text/csv');
  }

  function downloadFile(name, content, type) {
    saveBlob(name, new Blob([content], { type }));
  }

  function saveBlob(name, blob) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 500);
    showToast(`${name} downloaded.`);
  }

  async function downloadCloudFile(fileId, filename) {
    const response = await authorizedFetch(`/api/files/${encodeURIComponent(fileId)}/download`);
    if (response.status === 401) showAuthScreen('Your session expired. Please sign in again.');
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || `Download failed (${response.status}).`);
    }
    saveBlob(filename, await response.blob());
    addCloudActivity('File decrypted and downloaded', filename, 'download');
  }

  async function runNodeCryptoAction(nodeId, action, button) {
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = action === 'verify' ? 'Checking…' : 'Updating…';
    try {
      const result = await request('/api/node-crypto', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_id: Number(nodeId), action })
      });
      if (action === 'verify') {
        showToast(`${result.node}: ${fmt(result.verified)} encrypted file${result.verified === 1 ? '' : 's'} decrypted and verified. Plaintext stayed on the server.`);
        addCloudActivity('Decryption verified', `${result.node} · ${fmt(result.verified)} encrypted files authenticated`, 'secure');
      } else {
        showToast(`${result.node}: re-encrypted ${fmt(result.reencrypted)} file${result.reencrypted === 1 ? '' : 's'}.`);
        addCloudActivity('Node data re-encrypted', `${result.node} · ${fmt(result.reencrypted)} encrypted files updated`, 'secure');
      }
    } catch (error) {
      showToast(error.message, true);
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  }

  document.querySelectorAll('.nav button').forEach(button => button.addEventListener('click', () => nav(button.dataset.page)));
  $('threshold').addEventListener('input', event => {
    $('threshold-lab').value = event.target.value;
    $('threshold-label').textContent = $('threshold-lab-label').textContent = Number(event.target.value).toFixed(2);
    $('engine-threshold').textContent = Number(event.target.value).toFixed(2);
  });
  $('threshold-lab').addEventListener('input', event => {
    $('threshold').value = event.target.value;
    $('threshold-label').textContent = $('threshold-lab-label').textContent = Number(event.target.value).toFixed(2);
    $('engine-threshold').textContent = Number(event.target.value).toFixed(2);
  });
  $('run-btn').addEventListener('click', () => runSimulation());
  $('step-btn').addEventListener('click', () => runSimulation({ oneRound: true }));
  $('threat-run').addEventListener('click', () => runSimulation());
  $('threat-step').addEventListener('click', () => runSimulation({ oneRound: true }));
  $('agents-run').addEventListener('click', () => { nav('simulation'); runSimulation(); });
  $('simulation-step').addEventListener('click', () => runSimulation({ oneRound: true }));
  $('print-report').addEventListener('click', () => window.print());
  $('download-report').addEventListener('click', exportJson);
  $('download-csv').addEventListener('click', exportCsv);
  $('upload-form').addEventListener('submit', uploadDataset);
  $('cloud-upload-shortcut')?.addEventListener('click', () => {
    $('upload-panel').scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => $('upload-file').click(), 220);
  });
  $('cloud-file-search').addEventListener('input', renderFilteredCloudFiles);
  $('cloud-folder-filter').addEventListener('change', renderFilteredCloudFiles);
  $('cloud-type-filter').addEventListener('change', renderFilteredCloudFiles);
  $('cloud-files-body').addEventListener('click', handleCloudFileAction);
  $('version-list').addEventListener('click', handleCloudFileAction);
  $('close-version-dialog').addEventListener('click', () => $('version-dialog').close());
  $('upload-file').addEventListener('change', () => {
    const files = [...$('upload-file').files];
    $('upload-selection').textContent = files.length
      ? `${files.length} selected · ${files.map(file => file.name).join(', ')}`
      : 'No files selected';
    if (files.length) $('upload-progress-panel').classList.remove('active');
    if (uploadTriggeredFromNew && files.length > 0) {
      uploadTriggeredFromNew = false;
      const prog = $('upload-progress-panel'); if (prog) { prog.classList.add('active'); prog.style.display = 'block'; }
      $('upload-button').click();
    }
  });
  $('auth-form').addEventListener('submit', submitAuth);
  $('password-toggle').addEventListener('change', event => {
    setPasswordVisibility(event.target.checked);
  });
  $('auth-mode-link').addEventListener('click', event => {
    event.preventDefault();
    setAuthMode(authMode === 'login' ? 'signup' : 'login');
  });
  $('auth-role-switch').addEventListener('click', event => {
    const button = event.target.closest('[data-auth-role]');
    if (!button) return;
    accountType = button.dataset.authRole;
    $('auth-screen').querySelectorAll('[data-auth-role]').forEach(item => item.classList.toggle('active', item === button));
    $('staff-code-field').hidden = authMode !== 'signup' || accountType !== 'staff';
    $('staff-registration-code').required = authMode === 'signup' && accountType === 'staff';
    $('auth-message').textContent = '';
    $('auth-message').classList.remove('error');
  });
  $('verify-encryption-button').addEventListener('click', event => runNodeCryptoAction(2, 'verify', event.currentTarget));
  $('reencrypt-button').addEventListener('click', event => runNodeCryptoAction(2, 'reencrypt', event.currentTarget));
  $('logout-button').addEventListener('click', signOut);
  $('create-folder-button').addEventListener('click', () => {
    $('folder-dialog').showModal();
    $('folder-name-input').focus();
  });
  $('upload-folder').addEventListener('change', event => {
    if (event.target.value === '__new_folder__') {
      $('folder-dialog').showModal();
      $('folder-name-input').focus();
    } else {
      lastSelectedFolder = event.target.value;
    }
  });
  $('folder-dialog').addEventListener('close', () => {
    if ($('upload-folder').value === '__new_folder__') {
      $('upload-folder').value = lastSelectedFolder;
    }
  });
  $('folder-form').addEventListener('submit', createFolder);
  $('close-folder-dialog').addEventListener('click', () => $('folder-dialog').close());
  $('cancel-folder-dialog').addEventListener('click', () => $('folder-dialog').close());
  const dropArea = $('upload-drop');
  dropArea.addEventListener('dragover', event => { event.preventDefault(); dropArea.classList.add('drag-over'); });
  dropArea.addEventListener('dragleave', () => dropArea.classList.remove('drag-over'));
  dropArea.addEventListener('drop', event => {
    event.preventDefault();
    dropArea.classList.remove('drag-over');
    $('upload-file').files = event.dataTransfer.files;
    $('upload-file').dispatchEvent(new Event('change', { bubbles: true }));
  });
  $('round-select').addEventListener('change', event => {
    $('run-btn').textContent = Number(event.target.value) === 20 ? 'Run 20-round evaluation' : `Run ${event.target.value}-round evaluation`;
    $('agents-run').textContent = Number(event.target.value) === 20 ? 'Run 20-round evaluation' : `Run ${event.target.value}-round evaluation`;
  });

  async function bootstrapSession() {
    try {
      const response = await authorizedFetch('/api/auth/me');
      const result = await response.json().catch(() => ({}));
      if (result.user) await enterWorkspace(result.user);
      else showAuthScreen();
    } catch (_error) {
      showAuthScreen('Start the Cloud-D Python service, then refresh this page.');
    }
  }

  // Google Drive style "+ New" dropdown & folder interactions
  const driveNewBtn = $('drive-new-btn');
  const driveNewMenu = $('drive-new-menu');
  if (driveNewBtn && driveNewMenu) {
    driveNewBtn.addEventListener('click', event => {
      event.stopPropagation();
      driveNewMenu.hidden = !driveNewMenu.hidden;
    });
    document.addEventListener('click', event => {
      if (!event.target.closest('.drive-new-dropdown')) {
        driveNewMenu.hidden = true;
      }
    });
  }

  const driveMenuUpload = $('drive-menu-upload');
  if (driveMenuUpload) {
    driveMenuUpload.addEventListener('click', () => {
      if (driveNewMenu) driveNewMenu.hidden = true;
      if (selectedFolderFilter !== 'all') {
        $('upload-folder').value = selectedFolderFilter;
        lastSelectedFolder = selectedFolderFilter;
      }
      uploadTriggeredFromNew = true;
      $('upload-file').click();
    });
  }

  const driveMenuFolder = $('drive-menu-folder');
  if (driveMenuFolder) {
    driveMenuFolder.addEventListener('click', () => {
      if (driveNewMenu) driveNewMenu.hidden = true;
      $('folder-dialog').showModal();
      $('folder-name-input').focus();
    });
  }

  const createFolderGridBtn = $('create-folder-grid-btn');
  if (createFolderGridBtn) {
    createFolderGridBtn.addEventListener('click', () => {
      $('folder-dialog').showModal();
      $('folder-name-input').focus();
    });
  }

  const foldersGrid = $('cloud-folders-grid');
  if (foldersGrid) {
    foldersGrid.addEventListener('click', event => {
      const addTile = event.target.closest('#add-folder-tile');
      if (addTile) {
        $('folder-dialog').showModal();
        $('folder-name-input').focus();
        return;
      }
      const tile = event.target.closest('.folder-tile');
      if (!tile) return;
      const folderId = tile.dataset.folderId;
      if (folderId) selectFolder(folderId);
    });
  }


  // Manually Induced Simulation Engine
  const targetNodeMap = {
    auth: 'Auth Server (Node 0 · cloud_users & session tokens)',
    flow: 'API Gateway (Node 1 · Ingress & /api/upload pipeline)',
    query: 'Primary DB (Node 2 · Staff Storage & SQLite tables)',
    behavior: 'Customer DB (Node 3 · Customer Private Drives & folders)'
  };

  const manualVectorSelect = $('manual-vector-select');
  if (manualVectorSelect) {
    manualVectorSelect.addEventListener('change', () => {
      const selected = manualVectorSelect.value;
      const targetLabel = $('manual-target-name');
      if (targetLabel) targetLabel.textContent = targetNodeMap[selected] || 'Cloud Node';
    });
  }

  async function runManualAttack() {
    const vector = $('manual-vector-select') ? $('manual-vector-select').value : 'auth';
    const intensity = $('manual-intensity-select') ? $('manual-intensity-select').value : 'normal';
    const button = $('manual-attack-btn');
    if (button) {
      button.disabled = true;
      button.textContent = 'Inducing Attack…';
    }

    const resultBox = $('manual-result-box');
    if (resultBox) {
      resultBox.hidden = false;
      resultBox.innerHTML = '<div style="padding:10px 0;color:var(--muted);font-size:10px;">Evaluating game-theoretic decision tree and defender response…</div>';
    }

    try {
      const payload = {
        active_vectors: [vector],
        intensity: intensity
      };
      const responseState = await request('/api/round', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      setSimulation(responseState);

      const log = responseState.attack_log || [];
      const lastAttack = log[log.length - 1];
      if (!lastAttack || !resultBox) return;

      const isBlocked = Boolean(lastAttack.blocked);
      const outcomeBadge = isBlocked
        ? '<span class="pill green">BLOCKED · CONTAINED</span>'
        : (lastAttack.damage ? '<span class="pill red">IMPACT SUSTAINED</span>' : '<span class="pill amber">NO DAMAGE</span>');

      const vectorMeta = vectors.find(v => v.id === vector) || {};

      let algoExplanation = '';
      if (vector === 'auth') {
        algoExplanation = '<strong>Minimax Game-Tree Search (Depth 2):</strong> Credential-Bot calculated expected adversarial payoff across possible defender replies. AuthSentinel detected velocity anomalies and initiated progressive lockout.';
      } else if (vector === 'query') {
        algoExplanation = '<strong>Expectimax Chance-Node Evaluation:</strong> QueryShield averaged outcomes across uncertain AST parser states, verifying that SQL sanitization/rejection maximized records protection.';
      } else if (vector === 'flow') {
        algoExplanation = '<strong>Adaptive Token-Bucket Rate Limiting:</strong> FloodSwarm generated burst concurrency against the API Gateway. FlowGuardian executed traffic shedding and HTTP 429 limiting to preserve cloud availability.';
      } else if (vector === 'behavior') {
        algoExplanation = '<strong>Behavioral Baseline Scoring:</strong> GhostUser simulated unauthorized folder traversal. BehaviorWatch detected deviations from baseline access entropy and triggered session revocation.';
      }

      resultBox.innerHTML = `
        <div class="manual-result-card ${isBlocked ? 'success' : 'impact'}">
          <div class="manual-result-header">
            <div class="manual-result-title">
              <span style="font-size:16px;">${vectorMeta.icon || '⚔'}</span>
              <div>
                <strong>${escapeHtml(lastAttack.attacker)} ➔ ${escapeHtml(lastAttack.target)}</strong>
                <small>${escapeHtml(lastAttack.tactic || lastAttack.attack_type)} · Round ${lastAttack.round}</small>
              </div>
            </div>
            ${outcomeBadge}
          </div>
          <div class="manual-steps-grid">
            <div class="manual-step-item">
              <span class="step-label">Adversarial Vector</span>
              <strong>${escapeHtml(vectorMeta.domain || lastAttack.attack_type)}</strong>
            </div>
            <div class="manual-step-item">
              <span class="step-label">Defender Specialist</span>
              <strong>${escapeHtml(lastAttack.defender || vectorMeta.defender)}</strong>
            </div>
            <div class="manual-step-item">
              <span class="step-label">Defense Action</span>
              <strong>${escapeHtml(lastAttack.action || 'No action needed')}</strong>
            </div>
            <div class="manual-step-item">
              <span class="step-label">Utility Score</span>
              <strong style="color:var(--cyan)">${Number(lastAttack.utility || 0).toFixed(2)} <small style="color:var(--muted)">(Threshold: ${Number(responseState.threshold).toFixed(2)})</small></strong>
            </div>
          </div>
          <div class="manual-algo-note">
            ${algoExplanation}
          </div>
          <div class="manual-cloud-impact">
            <span>🛡</span>
            <span><strong>Cloud Protection Status:</strong> Target node <em>${escapeHtml(lastAttack.target)}</em> protected. Persistent SQLite databases, user folders, and AES-256-GCM encrypted files remain secure.</span>
          </div>
        </div>
      `;
      showToast(`Manual attack evaluated: ${lastAttack.attacker} ➔ ${lastAttack.target} (${isBlocked ? 'Blocked' : 'Impact'})`);
    } catch (error) {
      if (resultBox) {
        resultBox.innerHTML = `<div style="color:var(--red);font-size:10px;">Failed to induce attack: ${escapeHtml(error.message)}</div>`;
      }
      showToast(error.message, true);
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = '⚡ Launch Manual Attack';
      }
    }
  }

  const manualAttackBtn = $('manual-attack-btn');
  if (manualAttackBtn) {
    manualAttackBtn.addEventListener('click', runManualAttack);
  }

  bootstrapSession();
  setInterval(syncCloudWorkspace, 4000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') syncCloudWorkspace();
  });

  let lastSeenAttackTime = '';

  function renderCustomerSecurity() {
    const banner = $('customer-protection-banner');
    if (!banner) return;
    if (currentUser?.role !== 'customer') {
      banner.hidden = true;
      return;
    }

    banner.hidden = false;
    const sec = sim?.customer_security;
    const titleEl = $('cust-banner-title');
    const subEl = $('cust-banner-sub');
    const iconEl = $('cust-shield-icon');

    if (sec && (sec.ongoing_threat || sec.has_records)) {
      banner.classList.add('threat-alert');
      iconEl.textContent = '⚡';
      titleEl.innerHTML = `<strong>Autonomous Defense Active:</strong> ${escapeHtml(sec.attack_type)} Intercepted`;
      subEl.textContent = `${escapeHtml(sec.attacker)} was contained by ${escapeHtml(sec.defender)}. Customer Vault (Node 3) remains 100% encrypted and intact.`;

      if (sec.timestamp && sec.timestamp !== lastSeenAttackTime) {
        lastSeenAttackTime = sec.timestamp;
        showToast(`🛡 Sentinel: ${sec.attack_type} neutralized by ${sec.defender}`);
      }
    } else {
      banner.classList.remove('threat-alert');
      iconEl.textContent = '🛡';
      titleEl.innerHTML = '<strong>Sentinel Protection Active:</strong> Monitoring Customer DB (Node 3)';
      subEl.textContent = 'Autonomous AI agent sentinels are safeguarding your personal documents. Zero active threats detected.';
    }
  }

  function openCustomerProtectionModal() {
    const dialog = $('customer-protection-dialog');
    if (!dialog) return;
    const sec = sim?.customer_security;

    if (sec && sec.has_records) {
      $('cust-attacker-name').textContent = sec.attacker || 'Adversarial Probe';
      $('cust-attack-type').textContent = sec.attack_type || 'External Intrusion Attempt';
      $('cust-defender-name').textContent = sec.defender || 'Cloud-D Autonomous Sentinels';
      $('cust-defense-action').textContent = sec.defense_action || 'Autonomous Shielding & Lockout';
      $('cust-status-badge').textContent = sec.status || 'PROTECTION ENGAGED · VAULT SECURE';
      $('cust-status-badge').className = `pill ${sec.status && sec.status.includes('BLOCKED') ? 'green' : 'amber'}`;
      $('cust-protection-summary').textContent = sec.summary || 'Threat intercepted. Your customer documents remain safe.';
      if (sec.timestamp) {
        try {
          $('cust-status-time').textContent = new Date(sec.timestamp).toLocaleTimeString();
        } catch (_) {
          $('cust-status-time').textContent = 'Recently';
        }
      }
    } else {
      $('cust-attacker-name').textContent = 'Zero Active Threats';
      $('cust-attack-type').textContent = 'No unauthorized access detected';
      $('cust-defender-name').textContent = 'Cloud-D Sentinel Fleet';
      $('cust-defense-action').textContent = 'Continuous AES-256-GCM Monitoring';
      $('cust-status-badge').textContent = 'ALL SYSTEMS NORMAL · FULLY SECURED';
      $('cust-status-badge').className = 'pill green';
      $('cust-protection-summary').textContent = 'All customer storage nodes are healthy and protected with military-grade encryption. No adversarial events recorded.';
      $('cust-status-time').textContent = 'Active now';
    }

    if (typeof dialog.showModal === 'function') {
      dialog.showModal();
    } else {
      dialog.setAttribute('open', '');
    }
  }

  $('btn-open-cust-report')?.addEventListener('click', openCustomerProtectionModal);
  $('close-cust-dialog')?.addEventListener('click', () => {
    const dialog = $('customer-protection-dialog');
    if (typeof dialog?.close === 'function') dialog.close();
    else dialog?.removeAttribute('open');
  });
  $('btn-ack-cust-dialog')?.addEventListener('click', () => {
    const dialog = $('customer-protection-dialog');
    if (typeof dialog?.close === 'function') dialog.close();
    else dialog?.removeAttribute('open');
  });


  async function promoteFileVersion(fileId, logicalId, filename, versionNum) {
    showToast(`Restoring version ${versionNum} as active file…`);
    try {
      const result = await request(`/api/files/${encodeURIComponent(fileId)}/promote`, { method: 'POST' });
      setSimulation(result.state);
      showToast(`Version ${versionNum} of ${filename} restored as active!`);
      addCloudActivity('Version promoted to active', `${filename} (v${versionNum})`, 'secure');
      if ($('version-dialog').open) {
        await openVersionHistory(logicalId, filename);
      }
    } catch (err) {
      showToast(err.message, true);
    }
  }

  async function verifyFileIntegrity(fileId, filename) {
    showToast('Authenticating AES-256-GCM ciphertext…');
    try {
      const res = await request(`/api/files/${encodeURIComponent(fileId)}/verify`);
      $('int-filename').textContent = `${res.filename || filename} (v${res.version || 1})`;
      $('int-cipher').textContent = res.algorithm || 'AES-256-GCM';
      $('int-version').textContent = `v${res.version || 1}`;
      $('int-size').textContent = formatBytes(res.size_bytes || 0);
      $('int-nonce').textContent = res.nonce_hex || '—';
      $('int-sha256').textContent = res.sha256 || '—';
      $('int-guardian').textContent = res.shield_guardian || 'QueryShield';
      $('int-badge').textContent = res.tamper_status || 'AUTHENTICATED · INTACT';
      $('int-badge').className = 'pill green';

      const dialog = $('integrity-dialog');
      if (typeof dialog?.showModal === 'function') {
        dialog.showModal();
      } else {
        dialog?.setAttribute('open', '');
      }
    } catch (err) {
      showToast('Integrity verification failed: ' + err.message, true);
    }
  }

  async function uploadDirectVersion(file, target) {
    if (!target || !file) return;
    const formData = new FormData();
    formData.append('folder_id', target.folderId || currentFolders[0]?.id || '');
    formData.append('target_logical_id', target.logicalId);
    formData.append('duplicate_mode', target.mode || 'new_version');
    formData.append('file', file, file.name);

    showToast(`Uploading ${file.name} as ${target.mode === 'replace' ? 'replacement' : 'new version'}…`);
    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Upload failed');
      }
      setSimulation(data.state);
      const isReplace = target.mode === 'replace';
      showToast(isReplace ? `${target.filename} replaced successfully!` : `New version added to ${target.filename}!`);
      addCloudActivity(isReplace ? 'File replaced' : 'New version saved', target.filename, 'upload');
      if ($('version-dialog').open) {
        await openVersionHistory(target.logicalId, target.filename);
      }
    } catch (err) {
      showToast(err.message, true);
    }
  }

  $('version-file-picker')?.addEventListener('change', () => {
    const file = $('version-file-picker').files[0];
    if (file && activeVersionTarget) {
      uploadDirectVersion(file, { ...activeVersionTarget, mode: 'new_version' });
    }
    $('version-file-picker').value = '';
  });

  $('replace-file-picker')?.addEventListener('change', () => {
    const file = $('replace-file-picker').files[0];
    if (file && activeVersionTarget) {
      uploadDirectVersion(file, { ...activeVersionTarget, mode: 'replace' });
    }
    $('replace-file-picker').value = '';
  });

  $('btn-version-upload-new')?.addEventListener('click', () => {
    if (activeVersionTarget) {
      activeVersionTarget.mode = 'new_version';
      $('version-file-picker').click();
    }
  });

  $('close-integrity-dialog')?.addEventListener('click', () => $('integrity-dialog')?.close());
  $('btn-ack-integrity')?.addEventListener('click', () => $('integrity-dialog')?.close());

  let activePreviewTarget = null;

  async function previewCloudFile(fileId, filename) {
    showToast('Decrypting file preview…');
    try {
      const res = await request(`/api/files/${encodeURIComponent(fileId)}/preview`);
      activePreviewTarget = { fileId, filename: res.filename || filename, previewText: res.preview_text };
      $('preview-dialog-title').textContent = `${res.filename || filename}`;
      $('preview-pill-ver').textContent = `Version ${res.version || 1}`;
      $('preview-pill-node').textContent = `Node ${res.node_id || 2} Shard · 🛡 Guarded`;
      $('preview-pill-size').textContent = formatBytes(res.size_bytes || 0);
      $('preview-content-box').textContent = res.preview_text || (res.is_text ? '(Empty file)' : '[Encrypted binary document - preview unavailable. Download to inspect.]');
      const dialog = $('file-preview-dialog');
      if (typeof dialog?.showModal === 'function') {
        dialog.showModal();
      } else {
        dialog?.setAttribute('open', '');
      }
    } catch (err) {
      showToast('Preview error: ' + err.message, true);
    }
  }

  async function diffCloudVersions(baseId, targetId, baseVer, targetVer, filename) {
    showToast('Comparing versions…');
    try {
      const res = await request(`/api/files/diff?base=${encodeURIComponent(baseId)}&target=${encodeURIComponent(targetId)}`);
      $('diff-dialog-title').textContent = `Version Diff · ${res.filename || filename}`;
      $('diff-base-badge').textContent = `v${res.base_version}`;
      $('diff-target-badge').textContent = `v${res.target_version} (Active)`;
      $('diff-add-count').textContent = `+${res.additions} additions`;
      $('diff-del-count').textContent = `-${res.deletions} deletions`;

      const contentBox = $('diff-content-box');
      if (res.lines && res.lines.length) {
        contentBox.innerHTML = res.lines.map(line => {
          const typeClass = line.type === 'add' ? 'diff-add' : line.type === 'del' ? 'diff-del' : line.type === 'chunk' ? 'diff-chunk' : line.type === 'info' ? 'diff-info' : 'diff-same';
          const prefix = line.type === 'add' ? '+ ' : line.type === 'del' ? '- ' : line.type === 'chunk' ? '@ ' : '  ';
          return `<div class="diff-line ${typeClass}"><code>${prefix}${escapeHtml(line.text || '')}</code></div>`;
        }).join('');
      } else {
        contentBox.innerHTML = '<div class="empty" style="padding:12px;">No textual differences found between these versions.</div>';
      }

      const restoreBtn = $('diff-restore-btn');
      if (restoreBtn) {
        restoreBtn.textContent = `↺ Restore Version ${res.base_version}`;
        restoreBtn.onclick = async () => {
          $('version-diff-dialog')?.close();
          await promoteFileVersion(baseId, null, filename, res.base_version);
        };
      }

      const dialog = $('version-diff-dialog');
      if (typeof dialog?.showModal === 'function') {
        dialog.showModal();
      } else {
        dialog?.setAttribute('open', '');
      }
    } catch (err) {
      showToast('Version diff error: ' + err.message, true);
    }
  }

  $('close-preview-dialog-btn')?.addEventListener('click', () => $('file-preview-dialog')?.close());
  $('btn-ack-preview')?.addEventListener('click', () => $('file-preview-dialog')?.close());
  $('preview-copy-btn')?.addEventListener('click', () => {
    if (activePreviewTarget?.previewText) {
      navigator.clipboard.writeText(activePreviewTarget.previewText).then(() => {
        showToast('Preview text copied to clipboard!');
      }).catch(() => {
        showToast('Could not copy to clipboard', true);
      });
    }
  });
  $('preview-download-btn')?.addEventListener('click', () => {
    if (activePreviewTarget?.fileId) {
      downloadCloudFile(activePreviewTarget.fileId, activePreviewTarget.filename);
    }
  });

  $('close-diff-dialog-btn')?.addEventListener('click', () => $('version-diff-dialog')?.close());
  $('btn-ack-diff')?.addEventListener('click', () => $('version-diff-dialog')?.close());

  // --- Mobile App Compatibility & PWA Services ---
  let deferredInstallPrompt = null;
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').then(reg => {
        console.log('Cloud-D PWA ServiceWorker active:', reg.scope);
      }).catch(err => {
        console.warn('Cloud-D ServiceWorker registration failed:', err);
      });
    });
  }

  window.addEventListener('beforeinstallprompt', event => {
    event.preventDefault();
    deferredInstallPrompt = event;
    const installBtn = $('maccount-install-pwa');
    if (installBtn) {
      installBtn.style.display = 'block';
      installBtn.onclick = async () => {
        if (!deferredInstallPrompt) return;
        deferredInstallPrompt.prompt();
        const { outcome } = await deferredInstallPrompt.userChoice;
        if (outcome === 'accepted') {
          showToast('Cloud-D installed to home screen!');
          installBtn.style.display = 'none';
        }
        deferredInstallPrompt = null;
      };
    }
  });

  // Mobile Bottom Bar Navigation
  document.querySelectorAll('.mobile-tab-btn[data-page]').forEach(btn => {
    btn.addEventListener('click', () => {
      nav(btn.dataset.page);
    });
  });

  $('mobile-btn-security')?.addEventListener('click', () => {
    openCustomerProtectionModal();
  });

  $('mobile-btn-account')?.addEventListener('click', () => {
    const dialog = $('mobile-account-sheet');
    if (!dialog) return;
    if (currentUser) {
      $('maccount-username').textContent = currentUser.username;
      $('maccount-avatar').textContent = currentUser.username.slice(0, 2).toUpperCase();
      $('maccount-role').textContent = currentUser.role === 'staff' ? 'Staff Operator' : 'Customer Account';
    }
    if (typeof dialog.showModal === 'function') {
      dialog.showModal();
    } else {
      dialog.setAttribute('open', '');
    }
  });

  $('close-mobile-account-btn')?.addEventListener('click', () => $('mobile-account-sheet')?.close());
  $('maccount-logout-btn')?.addEventListener('click', () => {
    $('mobile-account-sheet')?.close();
    signOut();
  });

  // Mobile Floating Action Button (FAB)
  $('mobile-fab')?.addEventListener('click', () => {
    if (selectedFolderFilter !== 'all') {
      $('upload-folder').value = selectedFolderFilter;
      lastSelectedFolder = selectedFolderFilter;
    }
    uploadTriggeredFromNew = true;
    $('upload-file')?.click();
  });

  // Mobile File Bottom Sheet Handlers
  let activeMobileFile = null;

  function openMobileFileSheet(file) {
    activeMobileFile = file;
    const dialog = $('mobile-file-sheet');
    if (!dialog) return;
    $('mobile-sheet-filename').textContent = file.filename;
    $('mobile-sheet-meta').textContent = `Version ${file.version || 1} · ${formatBytes(file.size_bytes || 0)} · Node ${file.node_id || 2} Shard`;
    $('mobile-sheet-icon').textContent = file.kind === 'data' ? '▦' : '▤';
    if (typeof dialog.showModal === 'function') {
      dialog.showModal();
    } else {
      dialog.setAttribute('open', '');
    }
  }

  $('close-mobile-sheet')?.addEventListener('click', () => $('mobile-file-sheet')?.close());

  $('msheet-preview')?.addEventListener('click', () => {
    $('mobile-file-sheet')?.close();
    if (activeMobileFile) previewCloudFile(activeMobileFile.id, activeMobileFile.filename);
  });
  $('msheet-versions')?.addEventListener('click', () => {
    $('mobile-file-sheet')?.close();
    if (activeMobileFile) openVersionHistory(activeMobileFile.logical_id, activeMobileFile.filename);
  });
  $('msheet-new-version')?.addEventListener('click', () => {
    $('mobile-file-sheet')?.close();
    if (activeMobileFile) {
      activeVersionTarget = { logicalId: activeMobileFile.logical_id, filename: activeMobileFile.filename, folderId: activeMobileFile.folder_id, mode: 'new_version' };
      $('version-file-picker')?.click();
    }
  });
  $('msheet-replace')?.addEventListener('click', () => {
    $('mobile-file-sheet')?.close();
    if (activeMobileFile) {
      activeVersionTarget = { logicalId: activeMobileFile.logical_id, filename: activeMobileFile.filename, folderId: activeMobileFile.folder_id, mode: 'replace' };
      $('replace-file-picker')?.click();
    }
  });
  $('msheet-verify')?.addEventListener('click', () => {
    $('mobile-file-sheet')?.close();
    if (activeMobileFile) verifyFileIntegrity(activeMobileFile.id, activeMobileFile.filename);
  });
  $('msheet-download')?.addEventListener('click', () => {
    $('mobile-file-sheet')?.close();
    if (activeMobileFile) downloadCloudFile(activeMobileFile.id, activeMobileFile.filename);
  });
  $('msheet-delete')?.addEventListener('click', () => {
    $('mobile-file-sheet')?.close();
    if (activeMobileFile) {
      const mockButton = { dataset: { versionNum: '', logicalId: activeMobileFile.logical_id } };
      deleteCloudFile(activeMobileFile.id, activeMobileFile.filename, mockButton);
    }
  });


  // QR Code Instant Mobile Modal Handlers
  const openQrDialog = () => {
    const dialog = $('qr-code-dialog');
    if (!dialog) return;
    if (typeof dialog.showModal === 'function') dialog.showModal();
    else dialog.setAttribute('open', '');
  };

  $('topbar-mobile-qr')?.addEventListener('click', openQrDialog);
  $('auth-mobile-qr-btn')?.addEventListener('click', openQrDialog);
  $('close-qr-dialog')?.addEventListener('click', () => $('qr-code-dialog')?.close());
  $('btn-ack-qr')?.addEventListener('click', () => $('qr-code-dialog')?.close());
  $('btn-copy-mobile-link')?.addEventListener('click', () => {
    navigator.clipboard.writeText('https://cloud-d.onrender.com/').then(() => {
      showToast('Mobile link copied! Send it to your phone via WhatsApp or Email.');
    }).catch(() => {
      showToast('https://cloud-d.onrender.com/');
    });
  });

  // Enable row tap on mobile to open file sheet
  $('cloud-files-body')?.addEventListener('click', event => {
    if (window.innerWidth <= 768) {
      if (event.target.closest('button')) return; // let specific button click handle it
      const row = event.target.closest('tr');
      if (!row) return;
      const downloadBtn = row.querySelector('[data-download-file]');
      if (!downloadBtn) return;
      const fileId = downloadBtn.dataset.downloadFile;
      const file = cloudFileCache.find(f => f.id === fileId);
      if (file) openMobileFileSheet(file);
    }
  });


  // Google Drive Filter Chips & View Switcher (Signature Cloud-D Purple Palette)
  const chipType = $('chip-filter-type');
  if (chipType) {
    let typeIdx = 0;
    const types = ['all', 'data', 'document'];
    const typeLabels = ['Type ▾', 'Data (CSV/JSON) ▾', 'Documents ▾'];
    chipType.addEventListener('click', () => {
      typeIdx = (typeIdx + 1) % types.length;
      $('cloud-type-filter').value = types[typeIdx];
      const span = chipType.querySelector('span');
      if (span) span.textContent = typeLabels[typeIdx];
      chipType.classList.toggle('active', typeIdx !== 0);
      renderFilteredCloudFiles();
    });
  }

  const chipPeople = $('chip-filter-people');
  if (chipPeople) {
    chipPeople.addEventListener('click', () => {
      showToast(currentUser ? `Operator: ${currentUser.username} (${currentUser.role}) • AES-256-GCM Shard Node 2` : 'Cloud-D Defense Intelligence');
    });
  }

  const chipModified = $('chip-filter-modified');
  if (chipModified) {
    let sortAsc = false;
    chipModified.addEventListener('click', () => {
      sortAsc = !sortAsc;
      cloudFileCache.sort((a, b) => {
        const da = new Date(a.created_at || 0).getTime();
        const db = new Date(b.created_at || 0).getTime();
        return sortAsc ? da - db : db - da;
      });
      chipModified.classList.toggle('active', sortAsc);
      const span = chipModified.querySelector('span');
      if (span) span.textContent = sortAsc ? 'Oldest first ▾' : 'Modified ▾';
      renderFilteredCloudFiles();
    });
  }

  const chipLoc = $('chip-filter-location');
  if (chipLoc) {
    chipLoc.addEventListener('click', () => {
      const select = $('cloud-folder-filter');
      if (select && currentFolders && currentFolders.length) {
        let nextIdx = (select.selectedIndex + 1) % select.options.length;
        select.selectedIndex = nextIdx;
        selectedFolderFilter = select.value;
        renderFoldersGrid();
        renderFilteredCloudFiles();
      }
    });
  }

  const btnList = $('btn-view-list');
  const btnGrid = $('btn-view-grid');
  const tableCard = document.querySelector('.cloud-files-card');
  if (btnList && btnGrid) {
    btnList.addEventListener('click', () => {
      btnList.classList.add('active');
      btnGrid.classList.remove('active');
      if (tableCard) tableCard.classList.remove('grid-view-active');
    });
    btnGrid.addEventListener('click', () => {
      btnGrid.classList.add('active');
      btnList.classList.remove('active');
      if (tableCard) tableCard.classList.add('grid-view-active');
    });
  }

})();