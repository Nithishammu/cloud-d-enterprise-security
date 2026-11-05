(() => {
  'use strict';

  // A browser cannot launch the Python process from file://. The installed
  // macOS login service starts it in the background; send file-opened users to
  // the same-origin dashboard served by that local service.
  if (location.protocol === 'file:') {
    location.replace('http://127.0.0.1:8765/');
    return;
  }

  // Remove stale offline app shells left by earlier Cloud-D builds. This site
  // uses network responses only; keeping an old worker can show obsolete UI.
  const staleWorkerCleanup = (async () => {
    if (!('serviceWorker' in navigator)) return;
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(registrations.map(registration => registration.unregister()));
    if ('caches' in window) {
      const cacheNames = await caches.keys();
      await Promise.all(cacheNames.map(name => caches.delete(name)));
    }
  })().catch(() => {});

  const $ = id => document.getElementById(id);
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
  let stopRequested = false;
  let uploading = false;
  let cloudFileCache = [];
  let cloudActivity = [];
  let lastCloudFileIds = new Set();
  let activeDriveView = 'my-drive';
  let starredFileIds = new Set();
  let trashedFileIds = new Set();
  let fileViewerObjectUrl = null;
  let fileViewerBlob = null;
  let fileViewerToken = 0;
  let currentUser = null;
  let customerNoticeId = null;
  let customerNoticePrimed = false;
  let simulationSettingsTimer = null;
  let authMode = 'login';
  let accountType = 'customer';
  function updateDeploymentCopy() {
    const hosted = isHostedDeployment;
    const modePill = $('storage-mode-pill');
    const cloudStorageNote = $('cloud-storage-note');
    const uploadStorageNote = $('upload-storage-note');
    if (modePill) modePill.textContent = hosted ? 'HOSTED · TEMPORARY' : 'LOCAL · PERSISTENT';
    if (cloudStorageNote) cloudStorageNote.textContent = hosted
      ? 'AES-256-GCM file copies · host storage is temporary'
      : 'Automatic SQLite recovery copy';
    if (uploadStorageNote) uploadStorageNote.textContent = hosted
      ? 'Uploads are encrypted before SQLite writes them. Render’s filesystem is temporary, so this hosted copy may be lost when its instance is replaced.'
      : 'File contents are encrypted before SQLite writes them and stay on this device across app restarts. Back up both databases and the encryption key together.';
    $('stored-files-description').textContent = 'Folders and files are scoped to your account. Each saved revision is mirrored to the encrypted recovery database.';
    $('storage-footer-note').textContent = hosted
      ? 'Simulation only · file contents use AES-256-GCM, but this Render service has temporary local storage.'
      : 'Simulation only · file contents use AES-256-GCM and persist in local SQLite databases.';
  }
  updateDeploymentCopy();

  async function authorizedFetch(path, { method = 'GET', body, headers } = {}) {
    try {
      const requestHeaders = new Headers(headers || {});
      return await fetch(path, { method, body, headers: requestHeaders, credentials: 'same-origin' });
    } catch (_error) {
      const message = isHostedDeployment
          ? 'Could not reach the hosted simulation. It may be starting or waking; retry in a moment.'
          : 'Could not reach the local simulation. The Cloud-D background service may still be starting; try again in a moment.';
      showToast(message, true);
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
    $('app-shell').style.display = 'none';
    $('app-shell').inert = true;
    $('app-shell').setAttribute('aria-hidden', 'true');
    $('auth-screen').hidden = false;
    $('workspace-sidebar').hidden = true;
    document.body.classList.add('auth-active');
    setAuthMode('login', false);
    $('auth-message').textContent = message;
    $('auth-message').classList.toggle('error', Boolean(message));
    $('auth-message').classList.remove('error');
    $('auth-password').value = '';
  }

  async function enterWorkspace(user) {
    currentUser = user;
    customerNoticeId = null;
    customerNoticePrimed = false;
    starredFileIds = new Set();
    trashedFileIds = new Set();
    $('account-name').textContent = user.name || user.username || 'Cloud-D user';
    $('account-email').textContent = user.email || '';
    const avatar = $('account-menu-button');
    avatar.textContent = (user.name || user.username || 'N').trim().charAt(0).toUpperCase();
    const profileAvatar = $('account-profile-avatar');
    profileAvatar.textContent = (user.name || user.username || 'N').trim().charAt(0).toUpperCase();
    if (user.profile_picture) {
      const image = document.createElement('img');
      image.src = user.profile_picture;
      image.alt = 'Profile picture';
      avatar.replaceChildren(image.cloneNode());
      profileAvatar.replaceChildren(image);
    }
    $('auth-screen').hidden = true;
    document.body.classList.remove('auth-active');
    $('app-shell').hidden = false;
    $('app-shell').style.removeProperty('display');
    $('app-shell').inert = false;
    $('app-shell').removeAttribute('aria-hidden');
    $('workspace-sidebar').hidden = false;
    $('current-user-name').textContent = user.username;
    $('current-user-role').textContent = user.role === 'staff' ? 'Staff operator' : 'Customer';
    switchDriveView('my-drive');
    document.querySelectorAll('.page').forEach(item => item.classList.toggle('active', item.id === 'page-cloud'));
    document.querySelectorAll('.nav button').forEach(item => item.classList.toggle('active', item.dataset.page === 'cloud'));
    $('crumb-current').textContent = 'Cloud';
    document.querySelectorAll('.staff-only').forEach(item => { item.hidden = user.role !== 'staff'; });
    document.querySelectorAll('.customer-only').forEach(item => { item.hidden = user.role !== 'customer'; });
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
    } catch (error) {
      setCloudConnection('offline');
    }
  }

  async function refreshFolders(selectedId = '') {
    const result = await request('/api/folders');
    const folders = result.folders || [];
    const uploadSelect = $('upload-folder');
    const filterSelect = $('cloud-folder-filter');
    const previousUpload = selectedId || uploadSelect.value;
    const previousFilter = filterSelect.value;
    uploadSelect.innerHTML = folders.map(folder => `<option value="${escapeHtml(folder.id)}">${escapeHtml(folder.name)}</option>`).join('');
    filterSelect.innerHTML = '<option value="all">All folders</option>' + folders.map(folder => `<option value="${escapeHtml(folder.id)}">${escapeHtml(folder.name)}</option>`).join('');
    if (folders.some(folder => folder.id === previousUpload)) uploadSelect.value = previousUpload;
    const targetFilter = selectedId || previousFilter;
    if (folders.some(folder => folder.id === targetFilter)) filterSelect.value = targetFilter;
    syncFolderLocationLabel();
    renderFolderCards(folders);
    renderFilteredCloudFiles();
  }

  function syncFolderLocationLabel() {
    const uploadSelect = $('upload-folder');
    const filterSelect = $('cloud-folder-filter');
    const folderId = filterSelect.value !== 'all' ? filterSelect.value : uploadSelect.value;
    const folderName = [...uploadSelect.options].find(option => option.value === folderId)?.textContent || 'My Files';
    const label = $('folder-location-label');
    if (!label) return;
    const folderOpen = filterSelect.value !== 'all';
    const folderButton = $('folder-back-button');
    const folderTitle = $('folder-section-title');
    const folderGrid = $('folder-grid');
    if (folderButton) folderButton.hidden = !folderOpen;
    if (folderGrid) folderGrid.hidden = folderOpen;
    if (folderTitle) folderTitle.textContent = folderOpen ? `Files in ${folderName}` : 'Folders';
    const cardTitle = document.querySelector('.cloud-files-card .card-title');
    if (cardTitle && activeDriveView === 'my-drive') cardTitle.textContent = folderOpen ? folderName : 'Your cloud folders and files';
    label.textContent = folderOpen
      ? `${folderName} is open · new uploads will go here.`
      : `All folders shown · new uploads will go to ${folderName}.`;
  }

  function renderFolderCards(folders) {
    const grid = $('folder-grid');
    const visibleFolders = folders.filter(folder => !['my files', 'recovered files'].includes(String(folder.name).trim().toLowerCase()));
    grid.innerHTML = visibleFolders.length ? visibleFolders.map(folder => {
      const count = cloudFileCache.filter(file => file.folder_id === folder.id && !trashedFileIds.has(String(file.logical_id || file.id))).length;
      const selected = $('cloud-folder-filter').value === folder.id;
      return `<button class="folder-tile${selected ? ' selected' : ''}" type="button" data-open-folder="${escapeHtml(folder.id)}" aria-pressed="${selected}" title="Click to open this folder. New uploads will be saved here."><span class="folder-tile-icon" aria-hidden="true">▱</span><span class="folder-tile-copy"><strong>${escapeHtml(folder.name)}</strong><small>${count} file${count === 1 ? '' : 's'}</small></span></button>`;
    }).join('') : '<div class="folder-empty">No folders yet. Choose <strong>New folder</strong> to create one.</div>';
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
    try {
    if (authMode === 'signup') {
      payload.role = accountType;
      payload.email = $('auth-email').value.trim();
      payload.name = payload.username;
      payload.staff_registration_code = $('staff-registration-code').value.trim();
    }
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
    $('auth-username-help').hidden = false;
    $('auth-username-help').textContent = signup
      ? 'Use 3–30 letters, numbers, dots, underscores, or hyphens. Usernames must start with a letter or number.'
      : 'For older accounts, the username is based on the part of your email before @. Your username appears beside your role after sign-in.';
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

  async function changeAccount(mode) {
    try { await authorizedFetch('/api/auth/logout', { method:'POST' }); } catch (_error) { /* continue to account selection */ }
    lastCloudFileIds = new Set(); cloudFileCache = []; cloudActivity = [];
    showAuthScreen('');
    setAuthMode(mode);
    $('account-popover').hidden = true;
    $('account-menu-button').setAttribute('aria-expanded', 'false');
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
      switchDriveView('my-drive');
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
      intensity: Number($('intensity-select').value),
      active_vectors: [...document.querySelectorAll('.vector-toggle:checked')].map(input => input.value)
    };
  }

  async function saveSimulationSettings() {
    if (currentUser?.role !== 'staff') return;
    try {
      const updated = await request('/api/config', {
        method: 'POST',
        body: JSON.stringify(config()),
        headers: { 'Content-Type': 'application/json' }
      });
      setSimulation(updated);
      $('simulation-visual-status').textContent = 'SETTINGS SAVED';
    } catch (error) {
      $('simulation-visual-status').textContent = 'SETTINGS NOT SAVED';
      showToast(`Could not save simulation settings: ${error.message}`, true);
    }
  }

  function scheduleSimulationSettingsSave() {
    clearTimeout(simulationSettingsTimer);
    simulationSettingsTimer = setTimeout(saveSimulationSettings, 250);
  }

  function setSimulation(value) {
    const previousIds = lastCloudFileIds;
    const currentFiles = value.files || [];
    const newFiles = currentFiles.filter(file => !previousIds.has(file.id));
    const firstConnection = sim === null;
    sim = value;
    if (currentUser?.role === 'customer') {
      const notice = value.security_notice;
      $('customer-security-status').textContent = notice
        ? 'Security event detected · defense response active'
        : 'Your cloud is protected';
      $('customer-security-detail').textContent = notice
        ? `The exercise is processing round ${notice.round} of ${notice.max_rounds}. Defender systems are responding to simulated activity; your files remain in your assigned customer area.`
        : 'When a simulated security event is detected, Cloud-D will show its current status here.';
      if (!customerNoticePrimed) {
        customerNoticeId = notice?.id || null;
        customerNoticePrimed = true;
      } else if (notice?.id && notice.id !== customerNoticeId) {
        customerNoticeId = notice.id;
        $('customer-alert-dialog').showModal();
      }
    }
    starredFileIds = new Set(currentFiles.filter(file => file.starred).map(file => String(file.logical_id || file.id)));
    trashedFileIds = new Set(currentFiles.filter(file => file.trashed_at).map(file => String(file.logical_id || file.id)));
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
    if (value.intensity !== undefined && value.intensity !== null) {
      $('intensity-select').value = value.intensity;
      $('intensity-value').textContent = `${value.intensity} / 10`;
    }
    if (value.active_vectors) {
      document.querySelectorAll('.vector-toggle').forEach(input => { input.checked = value.active_vectors.includes(input.value); });
    }
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
    const permitted = currentUser?.role === 'staff'
      ? ['cloud', 'architecture', 'overview', 'threats', 'live-simulation', 'report']
      : ['cloud', 'architecture', 'report'];
    if (!permitted.includes(page)) return;
    document.querySelectorAll('.page').forEach(item => item.classList.toggle('active', item.id === `page-${page}`));
    document.querySelectorAll('.nav button').forEach(button => button.classList.toggle('active', button.dataset.page === page));
    $('crumb-current').textContent = ({ cloud: 'Cloud', architecture: 'Cloud Architecture', overview: 'Security Overview', threats: 'Attack & Defense Simulation Details', 'live-simulation': 'Live Simulation', report: 'Defense Report' })[page] || 'Cloud';
    window.scrollTo(0, 0);
    if (page === 'live-simulation') requestAnimationFrame(() => requestAnimationFrame(updateNetworkRoutes));
    if (page === 'cloud') syncCloudWorkspace();
  }

  async function syncCloudWorkspace() {
    if (!currentUser || document.visibilityState !== 'visible' || running || uploading) return;
    const onCloudPage = document.getElementById('page-cloud').classList.contains('active');
    if (onCloudPage) setCloudConnection('syncing');
    try {
      setSimulation(await request('/api/state'));
      if (onCloudPage) {
        await refreshFolders();
        setCloudConnection('connected');
      }
    } catch (_error) {
      if (onCloudPage) setCloudConnection('offline');
    }
  }

  function renderOverview() {
    const metrics = sim?.metrics;
    const counts = sim?.counts || {};
    const totalAttacks = metrics?.total_attacks || 0;
    const blocked = metrics?.blocked || 0;
    $('kpi-block').textContent = totalAttacks ? `${metrics.block_rate.toFixed(1)}%` : '—';
    $('kpi-block-note').innerHTML = totalAttacks ? `<strong>${blocked} blocked</strong> of ${totalAttacks} attack events` : 'Run the agents to start the simulation';
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
    const attackLog = sim?.attack_log || [];
    const blockedEvents = attackLog.filter(event => event.blocked).length;
    const impactEvents = attackLog.filter(event => !event.blocked && Number(event.damage || 0) > 0).length;
    const runUtilities = attackLog.map(event => Number(event.utility)).filter(Number.isFinite);
    const runMeanUtility = runUtilities.length ? runUtilities.reduce((sum, utility) => sum + utility, 0) / runUtilities.length : null;
    $('live-run-attempts').textContent = fmt(attackLog.length);
    $('live-run-blocked').textContent = fmt(blockedEvents);
    $('live-run-impacts').textContent = fmt(impactEvents);
    $('live-run-containment').textContent = attackLog.length ? `${(blockedEvents / attackLog.length * 100).toFixed(1)}%` : '—';
    $('live-run-utility').textContent = runMeanUtility === null ? '—' : runMeanUtility.toFixed(2);
    const summaryMarkup = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0 };
      const events = attackLog.filter(event => event.attacker === vector.attacker);
      const attempts = Math.max(Number(count.scored || 0), events.length);
      const blocked = events.length ? events.filter(event => event.blocked).length : Math.min(attempts, Number(count.blocked || 0));
      const impacts = events.filter(event => !event.blocked && Number(event.damage || 0) > 0).length;
      const passedWithoutDamage = Math.max(0, attempts - blocked - impacts);
      const containment = attempts ? blocked / attempts * 100 : 0;
      const utilityScores = events.map(event => Number(event.utility)).filter(Number.isFinite);
      const meanUtility = utilityScores.length ? utilityScores.reduce((sum, utility) => sum + utility, 0) / utilityScores.length : null;
      const utilityRange = utilityScores.length ? `${Math.min(...utilityScores).toFixed(2)}–${Math.max(...utilityScores).toFixed(2)}` : '—';
      const thresholds = [...new Set(events.map(event => Number(event.threshold)).filter(Number.isFinite).map(value => value.toFixed(2)))];
      const threshold = thresholds.length ? thresholds.join(' / ') : Number(sim?.threshold ?? 0.4).toFixed(2);
      const targets = [...new Set(events.map(event => event.target).filter(Boolean))];
      const defenders = [...new Set(events.map(event => event.assigned_defender || event.defender).filter(Boolean))];
      const rateClass = !attempts ? 'blue' : containment >= 75 ? 'green' : containment >= 50 ? 'amber' : 'red';
      const targetText = targets.length ? targets.join(', ') : vector.target;
      const defenderText = defenders.length ? defenders.join(', ') : vector.defender;
      const meanText = meanUtility === null ? '—' : meanUtility.toFixed(2);
      return `<div class="agent-row"><div class="agent-id"><span class="agent-icon" style="--agent-color:${vector.color}">${vector.icon}</span><strong>${escapeHtml(vector.attacker)}</strong><span class="agent-domain">${escapeHtml(vector.domain)}</span></div><div class="live-attack-stats"><div><span>Attempts</span><strong>${attempts}</strong></div><div><span>Blocked</span><strong>${blocked}</strong></div><div><span>Impacts</span><strong>${impacts}</strong></div><div><span>No damage</span><strong>${passedWithoutDamage}</strong></div></div><div class="live-attack-extra"><span><strong>Target:</strong> ${escapeHtml(targetText)} · <strong>Defender:</strong> ${escapeHtml(defenderText)}</span><span><strong>Containment:</strong> ${attempts ? `${containment.toFixed(1)}%` : '—'} · <strong>Mean utility:</strong> ${meanText} <span>(range ${utilityRange})</span> · <strong>Threshold:</strong> ${threshold}</span></div><div class="agent-score live-attack-rate"><span class="pill ${rateClass}">${attempts ? `${containment.toFixed(1)}% contained` : 'NO DATA'}</span></div></div>`;
    }).join('');
    ['attack-summary', 'live-attack-summary'].forEach(id => {
      const container = $(id);
      if (container) container.innerHTML = summaryMarkup;
    });
    const eventCount = Math.max(Number(sim?.metrics?.total_attacks || 0), attackLog.length);
    ['attack-count-label', 'live-attack-count-label', 'live-history-count'].forEach(id => {
      const label = $(id);
      if (label) label.textContent = `${eventCount} events`;
    });
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
    const activeFiles = cloudFileCache.filter(file => !file.trashed_at);
    const storageBytes = activeFiles.reduce((total, file) => total + Number(file.size_bytes || 0), 0);
    $('cloud-file-count').textContent = fmt(activeFiles.length);
    $('cloud-storage-size').textContent = formatBytes(storageBytes);
    document.querySelectorAll('[data-open-folder]').forEach(tile => {
      const count = cloudFileCache.filter(file => file.folder_id === tile.dataset.openFolder && !file.trashed_at).length;
      tile.querySelector('small').textContent = `${count} file${count === 1 ? '' : 's'}`;
    });
    renderFilteredCloudFiles();
  }

  function renderFilteredCloudFiles() {
    const query = ($('cloud-file-search').value || '').trim().toLowerCase();
    const selectedFolder = $('cloud-folder-filter').value;
    const selectedType = $('cloud-type-filter').value;
    const viewFiles = cloudFileCache.filter(file => {
      const fileKey = String(file.logical_id || file.id);
      const isTrashed = trashedFileIds.has(fileKey);
      if (activeDriveView === 'trash' ? !isTrashed : isTrashed) return false;
      if (activeDriveView === 'starred' && !starredFileIds.has(fileKey)) return false;
      return true;
    });
    document.querySelector('.cloud-files-card').classList.toggle('is-empty', viewFiles.length === 0);
    let files = viewFiles.filter(file => {
      const matchesText = !query || `${file.filename} ${file.folder_name}`.toLowerCase().includes(query);
      const matchesFolder = selectedFolder === 'all' || file.folder_id === selectedFolder;
      const matchesType = selectedType === 'all' || (selectedType === 'data' ? file.kind === 'data' : file.kind !== 'data');
      return matchesText && matchesFolder && matchesType;
    });
    if (activeDriveView === 'recent') files.sort((left, right) => new Date(right.created_at || 0) - new Date(left.created_at || 0));
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
      const fileKey = escapeHtml(file.logical_id || file.id);
      const trashAction = activeDriveView === 'trash'
        ? `<button class="btn" type="button" data-restore-trash="${fileKey}">Restore</button>`
        : `<button class="btn" type="button" data-trash-file="${fileKey}">Move to trash</button>`;
      const starAction = activeDriveView === 'trash' ? '' : `<button class="btn" type="button" data-star-file="${fileKey}" aria-label="${starredFileIds.has(file.logical_id || file.id) ? 'Remove from' : 'Add to'} Starred">${starredFileIds.has(file.logical_id || file.id) ? '★' : '☆'}</button>`;
      const fileAttrs = `data-file-id="${escapeHtml(file.id)}" data-filename="${name}" data-folder-name="${escapeHtml(file.folder_name || 'My Drive')}" data-folder-id="${escapeHtml(file.folder_id || '')}"`;
      const fileActions = activeDriveView === 'trash' ? trashAction : `<button class="btn primary" type="button" data-open-file ${fileAttrs}>Open</button>${starAction}${trashAction}${restoreButton}<button class="btn" type="button" data-download-file="${escapeHtml(file.id)}" data-filename="${name}">Download</button><button class="btn" type="button" data-view-versions="${escapeHtml(file.logical_id)}" data-filename="${name}">Versions · ${versions}</button>`;
      const trashInfo = activeDriveView === 'trash' && file.trashed_at
        ? `In Trash · auto-deletes in ${Math.max(0, 90 - Math.floor((Date.now() - new Date(file.trashed_at).getTime()) / 86400000))} days`
        : activeDriveView === 'recent' ? `Uploaded ${escapeHtml(savedAt)} · Version ${version}` : `Version ${version} · Uploaded ${escapeHtml(savedAt)}`;
      return `<tr><td><div class="file-entry"><span class="file-icon ${file.kind === 'data' ? 'structured' : ''}">${icon}</span><span class="file-entry-text"><button class="file-open-link" type="button" data-open-file ${fileAttrs}>${name}</button><small>${trashInfo}</small></span></div></td><td>${escapeHtml(file.folder_name)}</td><td>${formatBytes(Number(file.size_bytes || 0))}</td><td>${kind}</td><td>${fmt(file.record_count)}</td><td>${backupStatus}</td><td><div class="file-actions">${fileActions}</div></td></tr>`;
    }).join('') : `<tr><td colspan="7" class="empty">${activeDriveView === 'starred' ? 'No starred files yet. Use ☆ beside a file to save it here.' : activeDriveView === 'trash' ? 'Trash is empty.' : selectedFolder !== 'all' ? 'This folder is empty. Choose Upload files to add a file here.' : cloudFileCache.length ? 'No matching files. Change the search or filters.' : 'Your cloud is ready. Choose New to upload a file.'}</td></tr>`;
  }

  async function updateDriveEntry(logicalId, action, button) {
    if (button) button.disabled = true;
    try {
      const result = await request('/api/drive-state', { method:'POST', body:JSON.stringify({ logical_id:logicalId, action }), headers:{'Content-Type':'application/json'} });
      if (sim) { sim.files = result.files; renderCloudFiles(sim.files); }
      showToast(action === 'trash' ? 'File moved to Trash. It will be permanently deleted after 90 days.' : action === 'restore' ? 'File restored to My Drive.' : action === 'star' ? 'Added to Starred.' : 'Removed from Starred.');
    } catch (error) { showToast(error.message, true); }
    finally { if (button) button.disabled = false; }
  }

  function switchDriveView(view) {
    if (!$('page-cloud').classList.contains('active')) nav('cloud');
    activeDriveView = view;
    document.querySelectorAll('[data-drive-view]').forEach(button => button.classList.toggle('active', button.dataset.driveView === view));
    const labels = { 'my-drive': 'My Drive', recent: 'Recent', starred: 'Starred', trash: 'Trash' };
    const descriptions = {
      'my-drive': 'Your files and folders',
      recent: 'Most recently uploaded files first · upload date and time shown for every file',
      starred: 'Files you marked with a star',
      trash: 'Restore files within 90 days; older items are permanently deleted'
    };
    $('crumb-current').textContent = labels[view];
    document.querySelector('.cloud-files-card .card-title').textContent = labels[view];
    $('stored-files-description').textContent = descriptions[view];
    renderFilteredCloudFiles();
  }

  function renderAttackTable() {
    const rows = [...(sim?.attack_log || [])].reverse();
    const markup = rows.length ? rows.map(event => {
      const utility = Number(event.utility ?? 0).toFixed(2);
      const proposalUtility = Number(event.proposal_utility ?? event.utility ?? 0).toFixed(2);
      const threshold = Number(event.threshold ?? sim?.threshold ?? 0.4).toFixed(2);
      const utilityApplied = Boolean(event.utility_applied ?? event.blocked);
      const utilitySource = event.utility_source || (utilityApplied ? 'Applied utility' : event.action ? 'Candidate utility' : 'No matching proposal');
      const proposals = (event.matching_proposals || []).map(proposal => `${escapeHtml(proposal.defender || 'Defender')} ${Number(proposal.utility || 0).toFixed(2)}${proposal.executed ? ' · applied' : proposal.above_threshold ? ' · eligible' : ' · below threshold'}`).join(' · ');
      const decision = event.blocked
        ? `Executed: ${event.action || 'Defense action'}`
        : event.action ? `Not executed: ${event.action}` : 'No action selected';
      const outcome = event.blocked ? 'BLOCKED · defense succeeded' : Number(event.damage || 0) > 0 ? 'IMPACT · attack succeeded' : 'PASSED · no damage';
      const outcomeClass = event.blocked ? 'green' : Number(event.damage || 0) > 0 ? 'red' : 'amber';
      const impact = Number(event.damage || 0) > 0
        ? `${Number(event.damage)} damage${event.record_exposed ? ' · record exposed' : ''}`
        : 'No direct impact';
      return `<tr><td>${String(event.round).padStart(2, '0')}</td><td><strong>${escapeHtml(event.attacker)}</strong><small>${escapeHtml(event.tactic || event.attack_type || 'Attack')}</small></td><td>${escapeHtml(event.target)}<small>${escapeHtml(event.target_role || '')}</small></td><td>${escapeHtml(event.assigned_defender || event.defender || 'None assigned')}<small>${event.defender ? 'Action executed' : 'Mapped specialist'}</small></td><td><strong>${utility}</strong><small>${escapeHtml(utilitySource)} · threshold ${threshold}</small>${proposalUtility !== utility ? `<small>Best matching proposal ${proposalUtility}</small>` : ''}</td><td>${escapeHtml(decision)}${proposals ? `<small>${proposals}</small>` : ''}</td><td><span class="pill ${outcomeClass}">${outcome}</span></td><td>${impact}</td><td class="history-rationale">${escapeHtml(event.rationale || 'No rationale recorded.')}</td></tr>`;
    }).join('') : '<tr><td colspan="9" class="empty">No attacks yet. Run the simulation to create decision records.</td></tr>';
    ['attack-table', 'live-attack-table'].forEach(id => {
      const table = $(id);
      if (table) table.innerHTML = markup;
    });
  }

  function renderReport() {
    const metrics = sim?.metrics;
    const counts = sim?.counts || {};
    const reportStatus = $('report-live-status');
    if (running) {
      reportStatus.className = 'pill amber';
      reportStatus.textContent = `UPDATING · ROUND ${sim?.round || 0}/${sim?.max_rounds || 20}`;
    } else if (sim?.has_run) {
      reportStatus.className = 'pill green';
      reportStatus.textContent = sim.game_over
        ? `COMPLETE · ${sim.round} ROUNDS`
        : `CURRENT · ROUND ${sim.round}/${sim.max_rounds}`;
    } else {
      reportStatus.className = 'pill blue';
      reportStatus.textContent = 'AWAITING SIMULATION';
    }
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
      ? `The ${metrics.rounds}-round Cloud-D simulation processed ${metrics.total_attacks} attack events. Defender agents blocked ${metrics.blocked} events (${metrics.block_rate.toFixed(1)}%). The cloud contains ${fmt(metrics.total_records)} individual records; ${fmt(metrics.compromised)} were compromised (${metrics.protection_rate.toFixed(3)}% protected). Simulated node damage totaled ${metrics.damage_taken}. Uploaded file contents are not included in this report.`
      : 'No simulation has been run yet. Start an exercise to populate this report.';
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
    }).join('') : '<tr><td colspan="5" class="empty">Cloud nodes initialize when the Python simulation starts.</td></tr>';
    const savedReports = sim?.saved_reports || [];
    $('saved-report-list').innerHTML = savedReports.length ? savedReports.map(item => {
      const report = item.payload || {};
      const result = report.metrics || {};
      return `<article class="saved-report-row"><div><strong>Run · ${escapeHtml(new Date(item.created_at).toLocaleString())}</strong><small>Updated ${escapeHtml(new Date(item.updated_at).toLocaleString())} · Round ${Number(report.round || 0)}/${Number(report.max_rounds || 20)} · ${Number(result.blocked || 0)} blocked · ${Number(result.protection_rate || 0).toFixed(2)}% protected</small></div><span class="pill green">AES-256-GCM</span></article>`;
    }).join('') : '<div class="card empty">Saved encrypted reports will appear here after a simulation.</div>';
  }

  function renderAll() {
    renderOverview();
    renderAttackTable();
    $('agents-state').textContent = sim?.has_run ? `${sim.round} rounds · ${sim.metrics.blocked} blocks` : 'Awaiting simulation';
    renderReport();
    renderLiveSimulation();
  }

  function renderLiveSimulation() {
    $('live-round-count').textContent = `${sim?.round || 0} / ${sim?.max_rounds || 20}`;
    $('live-block-count').textContent = `${sim?.metrics?.blocked || 0} / ${sim?.metrics?.total_attacks || 0}`;
    $('live-cloud-status').textContent = sim?.game_over ? 'Exercise complete' : sim?.round ? 'Protected' : 'Ready';
    $('live-process-panel').hidden = !(running || sim?.has_run || (sim?.attack_log || []).length);
    renderLiveProcesses();
    renderAttackSummary();
  }

  function renderLiveProcesses() {
    const round = Number(sim?.round || 0);
    const selected = new Set(sim?.active_vectors || [...document.querySelectorAll('.vector-toggle:checked')].map(input => input.value));
    const events = (sim?.attack_log || []).filter(event => Number(event.round) === round);
    const byVector = new Map(events.map(event => {
      const vector = vectors.find(item => item.attacker === event.attacker);
      return vector ? [vector.id, event] : null;
    }).filter(Boolean));
    $('live-process-round').textContent = round ? `ROUND ${round} / ${sim?.max_rounds || 20}` : 'WAITING';
    $('live-agent-processes').innerHTML = vectors.map(vector => {
      const active = selected.has(vector.id);
      const event = byVector.get(vector.id);
      const defenderName = event?.defender || event?.assigned_defender || vector.defender;
      const blocked = Boolean(event?.blocked);
      const impacted = Boolean(event && !blocked && Number(event.damage || 0) > 0);
      const state = !active ? 'NOT SELECTED' : !event ? (round ? 'NO EVENT' : 'READY') : blocked ? 'BLOCKED' : impacted ? 'IMPACTED' : 'INSPECTED';
      const outcomeClass = blocked ? 'blocked' : impacted ? 'impacted' : '';
      const threshold = Number(sim?.threshold ?? 0.4).toFixed(2);
      const utility = event ? Number(event.utility || 0).toFixed(2) : '—';
      const attackResult = !event ? (active ? 'PENDING · run a round' : 'Agent paused') : blocked ? 'ATTACK FAILED · blocked' : impacted ? `ATTACK SUCCEEDED · ${event.damage} damage` : 'ATTACK PASSED · no damage';
      const defenseResult = !event ? (active ? 'PENDING · run a round' : 'Agent paused') : blocked ? 'DEFENSE SUCCEEDED · contained' : 'DEFENSE FAILED · attack passed';
      const attackerProcess = event ? `${event.tactic || event.attack_type} · ${event.target}` : active ? 'Waiting for next round' : 'Agent paused';
      const defenderProcess = event ? (event.action || (blocked ? 'Threat blocked' : 'Inspection complete')) : active ? 'Waiting for assignment' : 'Agent paused';
      const attackerResultClass = blocked ? 'failed' : impacted ? 'succeeded' : '';
      const defenderResultClass = event ? (blocked ? 'succeeded' : 'failed') : '';
      const detail = event
        ? `Attack ${attackResult.toLowerCase()} · Defense ${defenseResult.toLowerCase()} · Utility ${utility} (threshold ${threshold})${event.rationale ? ` · ${event.rationale}` : ''}`
        : active ? 'No simulation data yet. Attack and defense outcomes, utility, and rationale appear after each round.' : 'Enable this attacker in the controls to include its process in the next run.';
      return `<article class="live-process-row${event ? ' has-event' : ''}" data-process-agent="${vector.id}"><div class="live-process-route" aria-label="${escapeHtml(vector.attacker)} to firewall to ${escapeHtml(defenderName)}"><div class="live-process-agent"><strong>${escapeHtml(vector.attacker)}</strong><small>${escapeHtml(attackerProcess)}</small><em class="live-process-result ${attackerResultClass}">${escapeHtml(attackResult)}</em></div><div class="live-process-link attack" aria-label="Attack to firewall"></div><div class="live-process-firewall"><b>⬡</b><small>Firewall</small></div><div class="live-process-link defense" aria-label="Firewall response to defender"></div><div class="live-process-agent"><strong>${escapeHtml(defenderName)}</strong><small>${escapeHtml(defenderProcess)}</small><em class="live-process-result ${defenderResultClass}">${escapeHtml(defenseResult)}</em></div></div><div class="live-process-summary"><span class="live-process-outcome ${outcomeClass}">${state}</span><div class="live-process-utility"><small>UTILITY</small><strong>${utility}</strong><small>${event ? 'Threshold' : 'Computed each round'} ${threshold}</small></div></div><small class="live-process-detail">${escapeHtml(detail)}</small></article>`;
    }).join('');
  }

  function animatePacket(packetId) {
    const packet = $(packetId);
    if (!packet) return Promise.resolve();
    packet.classList.remove('packet-visible');
    packet.classList.add('packet-visible');
    const motion = packet.querySelector('animateMotion');
    const svg = packet.ownerSVGElement;
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', motion?.getAttribute('path') || '');
    try {
      const length = path.getTotalLength();
      if (!length) throw new Error('Packet route is empty');
      const duration = 650;
      const startedAt = performance.now();
      return new Promise(resolve => {
        const step = now => {
          const progress = Math.min(1, (now - startedAt) / duration);
          const point = path.getPointAtLength(length * progress);
          packet.setAttribute('cx', point.x);
          packet.setAttribute('cy', point.y);
          if (progress < 1) requestAnimationFrame(step);
          else resolve();
        };
        requestAnimationFrame(step);
      });
    } catch (_error) {
      try {
        if (svg && typeof packet.getBBox === 'function') void packet.getBBox();
        if (motion?.beginElement) motion.beginElement();
      } catch (_animationError) {
        // Station highlights and the round process log remain visible if SVG motion is unavailable.
      }
      return new Promise(resolve => setTimeout(resolve, 650));
    }
  }

  function updateNetworkRoutes() {
    const lane = $('simulation-lane');
    const svg = lane?.querySelector('.network-wires');
    const firewall = $('firewall-center');
    if (!lane || !svg || !firewall) return;

    const svgRect = svg.getBoundingClientRect();
    if (!svgRect.width || !svgRect.height) return;
    svg.setAttribute('viewBox', `0 0 ${svgRect.width} ${svgRect.height}`);
    svg.setAttribute('preserveAspectRatio', 'none');

    const point = (element, edge) => {
      const rect = element.getBoundingClientRect();
      return {
        x: (edge === 'left' ? rect.left : edge === 'right' ? rect.right : rect.left + rect.width / 2) - svgRect.left,
        y: rect.top + rect.height / 2 - svgRect.top
      };
    };
    const route = (start, end) => {
      const controlX = (start.x + end.x) / 2;
      const controlY = start.y + (end.y - start.y) * 0.16;
      return `M ${start.x} ${start.y} Q ${controlX} ${controlY} ${end.x} ${end.y}`;
    };
    const setRoute = (wire, packetId, path) => {
      if (wire) wire.setAttribute('d', path);
      const motion = $(packetId)?.querySelector('animateMotion');
      if (motion) motion.setAttribute('path', path);
    };
    const firewallLeft = point(firewall, 'left');
    const firewallRight = point(firewall, 'right');
    const attackWires = svg.querySelectorAll('.attack-link');
    const defenseWires = svg.querySelectorAll('.defense-link');

    vectors.forEach((vector, index) => {
      const attacker = document.querySelector(`[data-attacker-station="${vector.id}"]`);
      const defender = document.querySelector(`[data-defender-station="${vector.id}"]`);
      if (attacker) setRoute(attackWires[index], `attack-packet-${vector.id}`, route(point(attacker, 'right'), firewallLeft));
      if (defender) {
        setRoute(defenseWires[index], `defense-in-packet-${vector.id}`, route(point(defender, 'left'), firewallRight));
        setRoute(null, `defense-packet-${vector.id}`, route(firewallRight, point(defender, 'left')));
      }
    });
  }

  let networkRouteFrame = 0;
  function scheduleNetworkRouteUpdate() {
    if (networkRouteFrame) cancelAnimationFrame(networkRouteFrame);
    networkRouteFrame = requestAnimationFrame(() => {
      networkRouteFrame = 0;
      updateNetworkRoutes();
    });
  }
  window.addEventListener('resize', scheduleNetworkRouteUpdate, { passive: true });

  async function animateAttackTraffic(vectorIds, isPending) {
    const activeVectors = vectors.filter(vector => vectorIds.includes(vector.id));
    if (!activeVectors.length) return;
    activeVectors.forEach(vector => {
      document.querySelector(`[data-attacker-station="${vector.id}"]`)?.classList.add('is-active');
      const row = document.querySelector(`[data-process-agent="${vector.id}"]`);
      row?.classList.add('is-moving');
      const process = row?.querySelector('.live-process-agent small');
      if (process) process.textContent = 'Attack packet moving to firewall';
      const outcome = row?.querySelector('.live-process-outcome');
      if (outcome) outcome.textContent = 'IN TRANSIT';
    });
    while (isPending()) {
      await Promise.all(activeVectors.map(vector => animatePacket(`attack-packet-${vector.id}`)));
      if (isPending()) await new Promise(resolve => setTimeout(resolve, 120));
    }
  }

  function animateRoundEvents(events) {
    document.querySelectorAll('.network-station').forEach(station => station.classList.remove('is-active'));
    document.querySelectorAll('.network-packet').forEach(packet => packet.classList.remove('packet-visible'));
    if (!events.length) return new Promise(resolve => setTimeout(resolve, 500));
    let responseCount = 0;
    const responseMotions = [];
    for (const event of events) {
      const attacker = vectors.find(vector => vector.attacker === event.attacker);
      if (!attacker) continue;
      document.querySelector(`[data-attacker-station="${attacker.id}"]`)?.classList.add('is-active');
      const defenderMotions = [];
      const defender = vectors.find(vector => vector.defender === (event.defender || event.assigned_defender));
      if (defender) {
        document.querySelector(`[data-defender-station="${defender.id}"]`)?.classList.add('is-active');
        defenderMotions.push((async () => {
          await new Promise(resolve => setTimeout(resolve, 220));
          await animatePacket(`defense-in-packet-${defender.id}`);
          await animatePacket(`defense-packet-${defender.id}`);
        })());
        responseCount += 1;
      }
      responseMotions.push(...defenderMotions);
    }
    $('simulation-visual-status').textContent = `ROUND ${events[0].round} · ${responseCount} RESPONSE${responseCount === 1 ? '' : 'S'}`;
    return Promise.all(responseMotions).then(() => new Promise(resolve => setTimeout(() => {
      document.querySelectorAll('.network-station').forEach(station => station.classList.remove('is-active'));
      document.querySelectorAll('.network-packet').forEach(packet => packet.classList.remove('packet-visible'));
      resolve();
    }, 100)));
  }

  async function runSimulation() {
    if (currentUser?.role !== 'staff') { showToast('Security simulations are available to staff accounts.', true); return; }
    if (running) return;
    const selected = config();
    if (!selected.active_vectors.length) { showToast('Select at least one attack agent.', true); return; }
    running = true;
    stopRequested = false;
    $('threat-stop').disabled = false;
    $('threat-stop').textContent = '■ Stop';
    const runButtons = [$('threat-run')].filter(Boolean);
    const originalLabels = runButtons.map(button => button.textContent);
    runButtons.forEach(button => {
      button.disabled = true;
      button.textContent = 'Running simulation…';
      button.setAttribute('aria-busy', 'true');
    });
    try {
      nav('live-simulation');
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      updateNetworkRoutes();
      $('simulation-visual-status').textContent = 'CONNECTING TO SIMULATION ENGINE';
      $('live-process-round').textContent = 'STARTING';
      const rounds = Number($('round-select').value);
      $('simulation-lane').classList.add('is-running');
      let restartPending = true;
      const restartTraffic = animateAttackTraffic(selected.active_vectors, () => restartPending && !stopRequested);
      try {
        sim = await request('/api/restart', { method: 'POST', body: JSON.stringify(selected), headers: { 'Content-Type': 'application/json' } });
      } finally {
        restartPending = false;
        await restartTraffic;
      }
      renderLiveSimulation();
      $('simulation-visual-status').textContent = 'ATTACK IN MOTION';
      for (let index = 0; index < rounds; index++) {
        if (stopRequested || sim.game_over || sim.round >= sim.max_rounds) break;
        const roundConfig = config();
        selected.active_vectors = roundConfig.active_vectors;
        let roundPending = true;
        const attackTraffic = animateAttackTraffic(roundConfig.active_vectors, () => roundPending && !stopRequested);
        try {
          // Read the controls for each round so changes during playback apply
          // to the next round and the packet animation stays in sync.
          sim = await request('/api/round', { method: 'POST', body: JSON.stringify(roundConfig), headers: { 'Content-Type': 'application/json' } });
        } finally {
          roundPending = false;
          await attackTraffic;
        }
        renderLiveSimulation();
        await animateRoundEvents((sim.attack_log || []).filter(event => Number(event.round) === Number(sim.round)));
      }
      renderLiveSimulation();
      $('simulation-visual-status').textContent = stopRequested ? `STOPPED AFTER ROUND ${sim.round}` : 'DEFENSE COMPLETE';
      $('simulation-lane').classList.remove('is-running');
      showToast(stopRequested
        ? `Simulation stopped after round ${sim.round}.`
        : `Round ${sim.round} · ${sim.metrics.blocked} of ${sim.metrics.total_attacks} attacks blocked.`);
    } catch (error) {
      $('simulation-visual-status').textContent = 'SIMULATION COULD NOT START';
      $('live-process-round').textContent = 'ERROR';
      showToast(error.message, true);
    } finally {
      running = false;
      runButtons.forEach((button, index) => {
        button.disabled = false;
        button.textContent = originalLabels[index];
        button.removeAttribute('aria-busy');
      });
      $('simulation-lane').classList.remove('is-running');
      document.querySelectorAll('.network-station.is-active').forEach(station => station.classList.remove('is-active'));
      document.querySelectorAll('.network-packet.packet-visible').forEach(packet => packet.classList.remove('packet-visible'));
      $('threat-stop').disabled = true;
      $('threat-stop').textContent = '■ Stop';
      document.querySelectorAll('.live-process-row.is-moving').forEach(row => row.classList.remove('is-moving'));
      renderLiveSimulation();
      try {
        renderOverview();
        renderAttackTable();
        $('agents-state').textContent = sim?.has_run ? `${sim.round} rounds · ${sim.metrics.blocked} blocks` : 'Awaiting simulation';
        renderReport();
      } catch (renderError) {
        console.error('Simulation completed, but a secondary dashboard panel could not refresh.', renderError);
      }
    }
  }

  function stopSimulation() {
    if (!running || stopRequested) return;
    stopRequested = true;
    $('threat-stop').disabled = true;
    $('threat-stop').textContent = 'Stopping…';
    $('simulation-visual-status').textContent = `STOPPING AFTER ROUND ${sim?.round || 0}`;
  }

  async function uploadDataset(event) {
    event?.preventDefault?.();
    const files = [...$('upload-file').files];
    if (!files.length) return;
    const totalBytes = files.reduce((total, file) => total + file.size, 0);
    if (totalBytes > 10 * 1024 * 1024) {
      $('upload-form').reset();
      showToast('Selected files must total 10 MB or less.', true);
      return;
    }
    const selectedFolder = $('upload-folder').value;
    if (!selectedFolder) {
      $('upload-form').reset();
      showToast('Choose a destination folder before uploading.', true);
      return;
    }
    uploading = true;
    const formData = new FormData($('upload-form'));
    const folderName = $('upload-folder').selectedOptions[0]?.textContent || 'your folder';
    showToast(`Uploading ${files.length} file${files.length === 1 ? '' : 's'} to ${folderName}…`);
    try {
      let result;
      try {
        result = await uploadWithProgress(formData, () => {});
      } catch (error) {
        if (error.status !== 409 || !error.payload?.duplicates?.length) throw error;
        const duplicateMode = await chooseDuplicateMode(error.payload.duplicates, files);
        if (!duplicateMode) throw new Error('Upload cancelled. No files were changed.');
        formData.set('duplicate_mode', duplicateMode);
        result = await uploadWithProgress(formData, () => {});
      }
      setSimulation(result.state);
      const updateSummary = (result.file_updates || []).map(file => `${file.filename} · v${file.version}`).join(', ');
      $('upload-form').reset();
      $('upload-folder').value = selectedFolder;
      const names = files.length === 1 ? files[0].name : `${files.length} files`;
      showToast(`${names} uploaded to ${result.folder}.${updateSummary ? ` Updated: ${updateSummary}.` : ''}`);
    } catch (error) {
      if (error.status === 401) showAuthScreen('Your session expired. Please sign in again.');
      showToast(error.message, true);
    } finally {
      uploading = false;
    }
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

  function chooseDuplicateMode(duplicates, selectedFiles) {
    const dialog = $('duplicate-dialog');
    $('duplicate-file-list').innerHTML = duplicates.map(item => {
      const incoming = selectedFiles.find(file => file.name.toLocaleLowerCase() === String(item.filename).toLocaleLowerCase());
      const savedWhen = item.created_at ? new Date(item.created_at).toLocaleString() : 'Saved in your cloud';
      return `<li><strong class="duplicate-name">${escapeHtml(item.filename)}</strong><div class="duplicate-compare"><div><span class="duplicate-label">CURRENT FILE</span><strong>Version ${Number(item.version) || 1} · ${formatBytes(Number(item.size_bytes || 0))}</strong><small>Saved ${escapeHtml(savedWhen)}</small></div><div><span class="duplicate-label">NEW UPLOAD</span><strong>${formatBytes(Number(incoming?.size || 0))}</strong><small>${incoming ? `File modified ${new Date(incoming.lastModified).toLocaleString()}` : 'Selected upload'}</small></div></div></li>`;
    }).join('');
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
    if (!dialog.open) dialog.showModal();
    try {
      const result = await request(`/api/file-groups/${encodeURIComponent(logicalId)}/versions`);
      $('version-list').innerHTML = result.versions.map(version => {
        const savedAt = new Date(version.created_at).toLocaleString();
        const status = version.current ? '<span class="pill green">CURRENT</span>' : '<span class="pill blue">HISTORY</span>';
        return `<div class="version-row"><div class="version-main"><div><strong>Version ${Number(version.version)}</strong> ${status}</div><small>${escapeHtml(savedAt)} · ${formatBytes(Number(version.size_bytes || 0))} · ${fmt(version.record_count)} record${Number(version.record_count) === 1 ? '' : 's'}</small></div><button class="btn" type="button" data-download-file="${escapeHtml(version.id)}" data-filename="${escapeHtml(filename)}">Download</button></div>`;
      }).join('') || '<div class="empty">No saved versions were found.</div>';
    } catch (error) {
      $('version-list').innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }

  function clearFileViewer() {
    fileViewerToken += 1;
    fileViewerBlob = null;
    if (fileViewerObjectUrl) URL.revokeObjectURL(fileViewerObjectUrl);
    fileViewerObjectUrl = null;
  }

  async function openCloudFile(fileId, filename, folderName = 'My Drive', folderId = '') {
    const dialog = $('file-viewer-dialog');
    const body = $('file-viewer-body');
    const token = ++fileViewerToken;
    if (fileViewerObjectUrl) URL.revokeObjectURL(fileViewerObjectUrl);
    fileViewerObjectUrl = null;
    fileViewerBlob = null;
    $('file-viewer-title').textContent = filename;
    $('file-viewer-filename').textContent = filename;
    $('file-viewer-folder-link').textContent = folderName;
    $('file-viewer-folder-link').dataset.folderId = folderId;
    $('file-viewer-meta').textContent = `${folderName} · Loading encrypted file…`;
    body.replaceChildren(Object.assign(document.createElement('p'), { textContent: 'Opening file from your Cloud-D drive…' }));
    if (!dialog.open) dialog.showModal();

    try {
      const response = await authorizedFetch(`/api/files/${encodeURIComponent(fileId)}/download`);
      if (response.status === 401) {
        dialog.close();
        showAuthScreen('Your session expired. Please sign in again.');
        return;
      }
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || `Could not open this file (${response.status}).`);
      }
      const blob = await response.blob();
      if (token !== fileViewerToken || !dialog.open) return;
      fileViewerBlob = blob;
      $('file-viewer-meta').textContent = `${folderName} · ${formatBytes(blob.size)} · ${blob.type || 'File'}`;
      const extension = filename.split('.').pop().toLowerCase();
      const imageTypes = { png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif', webp:'image/webp', avif:'image/avif' };
      if (imageTypes[extension]) {
        fileViewerObjectUrl = URL.createObjectURL(new Blob([blob], { type: imageTypes[extension] }));
        const image = document.createElement('img');
        image.className = 'file-viewer-preview-image';
        image.alt = filename;
        image.src = fileViewerObjectUrl;
        body.replaceChildren(image);
      } else if (extension === 'pdf') {
        fileViewerObjectUrl = URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
        const frame = document.createElement('iframe');
        frame.className = 'file-viewer-preview-frame';
        frame.title = filename;
        frame.setAttribute('sandbox', 'allow-scripts');
        frame.src = fileViewerObjectUrl;
        body.replaceChildren(frame);
      } else if (['txt','csv','tsv','json','jsonl','ndjson','md','log','xml','yaml','yml'].includes(extension)) {
        const preview = document.createElement('pre');
        preview.className = 'file-viewer-preview-text';
        preview.textContent = await blob.text();
        body.replaceChildren(preview);
      } else {
        const message = document.createElement('p');
        message.textContent = 'This file type cannot be previewed in the browser. Use Download below to open it with an app on your device.';
        body.replaceChildren(message);
      }
      addCloudActivity('File opened in Cloud-D', filename, 'download');
    } catch (error) {
      if (token !== fileViewerToken) return;
      const message = document.createElement('p');
      message.textContent = error.message || 'The file could not be opened. Check your cloud connection and try again.';
      body.replaceChildren(message);
    }
  }

  function handleCloudFileAction(event) {
    const openButton = event.target.closest('[data-open-file]');
    if (openButton) {
      openCloudFile(openButton.dataset.fileId, openButton.dataset.filename, openButton.dataset.folderName, openButton.dataset.folderId)
        .catch(error => showToast(error.message, true));
      return;
    }
    const starButton = event.target.closest('[data-star-file]');
    if (starButton) {
      const fileKey = starButton.dataset.starFile;
      updateDriveEntry(fileKey, starredFileIds.has(fileKey) ? 'unstar' : 'star', starButton);
      return;
    }
    const trashButton = event.target.closest('[data-trash-file]');
    if (trashButton) {
      updateDriveEntry(trashButton.dataset.trashFile, 'trash', trashButton);
      return;
    }
    const restoreTrashButton = event.target.closest('[data-restore-trash]');
    if (restoreTrashButton) {
      updateDriveEntry(restoreTrashButton.dataset.restoreTrash, 'restore', restoreTrashButton);
      return;
    }
    const restoreButton = event.target.closest('[data-restore-file]');
    if (restoreButton) {
      restoreBackedUpFile(restoreButton.dataset.restoreFile, restoreButton);
      return;
    }
    const versionButton = event.target.closest('[data-view-versions]');
    if (versionButton) {
      openVersionHistory(versionButton.dataset.viewVersions, versionButton.dataset.filename);
      return;
    }
    const downloadButton = event.target.closest('[data-download-file]');
    if (downloadButton) {
      downloadCloudFile(downloadButton.dataset.downloadFile, downloadButton.dataset.filename)
        .catch(error => showToast(error.message, true));
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
    if (!sim) { showToast('Connect to the Python simulation before exporting.', true); return; }
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
    if (!sim) { showToast('Connect to the Python simulation before exporting.', true); return; }
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
  $('page-live-simulation').querySelector('[data-page="threats"]').addEventListener('click', () => nav('threats'));
  $('threshold-lab').addEventListener('input', event => {
    $('threshold').value = event.target.value;
    $('threshold-label').textContent = $('threshold-lab-label').textContent = Number(event.target.value).toFixed(2);
    $('engine-threshold').textContent = Number(event.target.value).toFixed(2);
    $('simulation-visual-status').textContent = `UTILITY THRESHOLD ${Number(event.target.value).toFixed(2)}`;
    scheduleSimulationSettingsSave();
  });
  $('threat-run').addEventListener('click', () => runSimulation());
  $('threat-stop').addEventListener('click', stopSimulation);
  $('round-select').addEventListener('input', event => {
    $('round-value').textContent = event.target.value;
    $('threat-run').textContent = `▶ Run ${event.target.value} round${Number(event.target.value) === 1 ? '' : 's'}`;
  });
  $('intensity-select').addEventListener('input', event => {
    $('intensity-value').textContent = `${event.target.value} / 10`;
    $('simulation-visual-status').textContent = `ATTACK INTENSITY ${event.target.value} / 10`;
    scheduleSimulationSettingsSave();
  });
  document.querySelectorAll('.vector-toggle').forEach(input => input.addEventListener('change', scheduleSimulationSettingsSave));
  $('customer-alert-dismiss').addEventListener('click', () => $('customer-alert-dialog').close());
  $('print-report').addEventListener('click', () => window.print());
  $('download-report').addEventListener('click', exportJson);
  $('download-csv').addEventListener('click', exportCsv);
  $('drive-new-button').addEventListener('click', event => {
    event.stopPropagation();
    const menu = $('drive-new-menu');
    menu.hidden = !menu.hidden;
    event.currentTarget.setAttribute('aria-expanded', String(!menu.hidden));
  });
  document.addEventListener('click', event => {
    if (!event.target.closest('.drive-new-dropdown')) {
      $('drive-new-menu').hidden = true;
      $('drive-new-button').setAttribute('aria-expanded', 'false');
    }
  });
  function openUploadPicker() {
    const filteredFolder = $('cloud-folder-filter').value;
    const uploadFolder = $('upload-folder');
    if (filteredFolder !== 'all' && [...uploadFolder.options].some(option => option.value === filteredFolder)) {
      uploadFolder.value = filteredFolder;
    }
    $('upload-file').value = '';
    $('upload-file').click();
  }
  $('drive-upload-action').addEventListener('click', () => {
    $('drive-new-menu').hidden = true;
    $('drive-new-button').setAttribute('aria-expanded', 'false');
    if (!$('page-cloud').classList.contains('active')) nav('cloud');
    openUploadPicker();
  });
  $('drive-folder-action').addEventListener('click', () => {
    $('drive-new-menu').hidden = true;
    $('drive-new-button').setAttribute('aria-expanded', 'false');
    if (!$('page-cloud').classList.contains('active')) nav('cloud');
    $('folder-dialog').showModal();
    $('folder-name-input').focus();
  });
  document.querySelectorAll('[data-drive-view]').forEach(button => {
    button.addEventListener('click', () => switchDriveView(button.dataset.driveView));
  });
  $('cloud-upload-shortcut').addEventListener('click', () => {
    openUploadPicker();
  });
  $('cloud-file-search').addEventListener('input', renderFilteredCloudFiles);
  $('cloud-folder-filter').addEventListener('change', () => {
    if ($('cloud-folder-filter').value !== 'all') $('upload-folder').value = $('cloud-folder-filter').value;
    syncFolderLocationLabel();
    renderFolderCards([...$('cloud-folder-filter').options].filter(option => option.value !== 'all').map(option => ({ id: option.value, name: option.textContent })));
    renderFilteredCloudFiles();
  });
  function navigateDriveFolder(folderId = 'all') {
    const filter = $('cloud-folder-filter');
    const upload = $('upload-folder');
    const validFolder = folderId !== 'all' && [...upload.options].some(option => option.value === folderId);
    switchDriveView('my-drive');
    filter.value = validFolder ? folderId : 'all';
    if (validFolder) upload.value = folderId;
    syncFolderLocationLabel();
    renderFolderCards([...filter.options].filter(option => option.value !== 'all').map(option => ({ id: option.value, name: option.textContent })));
    renderFilteredCloudFiles();
  }
  $('folder-back-button').addEventListener('click', () => navigateDriveFolder('all'));
  function selectFolderTile(tile) {
    if (!$('page-cloud').classList.contains('active')) nav('cloud');
    switchDriveView('my-drive');
    $('cloud-folder-filter').value = tile.dataset.openFolder;
    $('upload-folder').value = tile.dataset.openFolder;
    syncFolderLocationLabel();
    document.querySelectorAll('[data-open-folder]').forEach(folder => {
      const selected = folder.dataset.openFolder === tile.dataset.openFolder;
      folder.classList.toggle('selected', selected);
      folder.setAttribute('aria-pressed', String(selected));
    });
    renderFilteredCloudFiles();
  }
  $('folder-grid').addEventListener('click', event => {
    const tile = event.target.closest('[data-open-folder]');
    if (!tile) return;
    selectFolderTile(tile);
    showToast(`Opened ${tile.querySelector('strong').textContent}. New uploads will go here.`);
  });
  $('cloud-type-filter').addEventListener('change', renderFilteredCloudFiles);
  $('cloud-files-body').addEventListener('click', handleCloudFileAction);
  $('version-list').addEventListener('click', handleCloudFileAction);
  $('close-version-dialog').addEventListener('click', () => $('version-dialog').close());
  $('file-viewer-close').addEventListener('click', () => $('file-viewer-dialog').close());
  $('file-viewer-dialog').addEventListener('close', () => {
    clearFileViewer();
    $('file-viewer-body').replaceChildren();
  });
  $('file-viewer-download').addEventListener('click', () => {
    if (!fileViewerBlob) return;
    const filename = $('file-viewer-filename').textContent || 'cloud-d-file';
    saveBlob(filename, fileViewerBlob);
    addCloudActivity('File downloaded from Cloud-D', filename, 'download');
  });
  $('file-viewer-drive-link').addEventListener('click', () => navigateDriveFolder('all'));
  $('file-viewer-folder-link').addEventListener('click', event => navigateDriveFolder(event.currentTarget.dataset.folderId || 'all'));
  $('upload-file').addEventListener('change', () => {
    if ($('upload-file').files.length) void uploadDataset();
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
  $('account-menu-button').addEventListener('click', event => {
    event.stopPropagation();
    const popover = $('account-popover');
    popover.hidden = !popover.hidden;
    event.currentTarget.setAttribute('aria-expanded', String(!popover.hidden));
  });
  document.addEventListener('click', event => {
    if (!event.target.closest('.account-menu')) {
      $('account-popover').hidden = true;
      $('account-menu-button').setAttribute('aria-expanded', 'false');
    }
  });
  $('add-account-button').addEventListener('click', () => changeAccount('signup'));
  $('switch-account-button').addEventListener('click', () => changeAccount('login'));
  $('logout-account-button').addEventListener('click', signOut);
  $('folder-form').addEventListener('submit', createFolder);
  $('close-folder-dialog').addEventListener('click', () => $('folder-dialog').close());
  $('cancel-folder-dialog').addEventListener('click', () => $('folder-dialog').close());

  async function bootstrapSession() {
    renderLiveProcesses();
    await staleWorkerCleanup;
    try {
      const response = await authorizedFetch('/api/auth/me');
      const result = await response.json().catch(() => ({}));
      if (result.user) await enterWorkspace(result.user);
      else showAuthScreen();
    } catch (_error) {
      showAuthScreen('Start the Cloud-D Python service, then refresh this page.');
    }
  }
  bootstrapSession();
  setInterval(syncCloudWorkspace, 6000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') syncCloudWorkspace();
  });
})();
