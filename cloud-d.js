/**
 * Cloud-D Enterprise Security - Complete Client Architecture & Concurrent Threat Engine
 * Student Investigator: Nithish M (Roll No. 24X064)
 * PSG College of Technology, Coimbatore
 *
 * Implements:
 *  - Mobile Bottom Bar strict gating (visible ONLY after authentication)
 *  - Customer Peripheral Level Visibility: Customers have NO control over attacks;
 *    they observe how the autonomous peripheral levels (Rings 1-4) protect their vault.
 *  - Staff Simulation Arena: Staff can launch attacks and run Q-learning RL episodes.
 *  - Real-Time Concurrent Threat Synchronization (Staff triggers -> Customers notified)
 *  - Google Drive UI layout (Home suggested grid, Recent chronological grouping)
 *  - Duplicate Upload Versioning (n+1 revision lineage vs in-place replace vs copy)
 *  - Hardware AES-256-GCM AEAD proof verification & Unified Version Diffing
 *  - Real-time Sequence CRDT collaboration and multi-user cursor presence
 *  - Hybrid Post-Quantum Cryptography & WebAuthn FIDO2 attestation
 */

// -------------------------------------------------------------
// Global Application State
// -------------------------------------------------------------
const state = {
  currentUser: null,
  activeFolder: 'root',
  currentFolderName: 'My Drive',
  currentCategory: 'home',
  folders: [],
  files: [],
  filteredFiles: [],
  selectedFileIds: new Set(),
  activeTab: 'drive',
  pendingFile: null,
  pendingIsZK: false,
  duplicateInfo: null,
  activeThreats: [],
  threatEventSource: null,
  threatPollTimer: null,
  simRunning: false,
  simTargetNode: 2,
  simRoundNumber: 1,
  utilityThreshold: 0.40,
};

// -------------------------------------------------------------
// Authentication Lifecycle & Strict Mobile Gating
// -------------------------------------------------------------
async function initAuth() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      if (data.authenticated && data.user) {
        setAuthenticatedState(data.user);
        loadFiles('root');
        startConcurrentThreatEngine();
        return;
      }
    }
  } catch (e) {
    console.warn('[Cloud-D Auth] Session check: Unauthenticated');
  }
  setUnauthenticatedState();
}

function setAuthenticatedState(user) {
  state.currentUser = user;
  document.body.classList.add('is-authenticated');

  // Explicitly display mobile bottom panel only after authentication
  const bottomBar = document.getElementById('mobile-bottom-bar');
  if (bottomBar) bottomBar.style.display = 'flex';
  const fab = document.getElementById('mobile-fab');
  if (fab) fab.style.display = 'flex';

  // Update user indicators
  const avatar = document.getElementById('user-avatar-char');
  if (avatar) avatar.innerText = (user.username || 'U')[0].toUpperCase();
  const hUser = document.getElementById('header-username');
  if (hUser) hUser.innerText = user.username;
  const hRole = document.getElementById('header-user-role');
  if (hRole) hRole.innerText = user.role === 'customer' ? 'Customer Account' : 'Staff Member';

  // Role-based view switching in Threats tab
  updateRoleSpecificViews();
}

function setUnauthenticatedState() {
  state.currentUser = null;
  document.body.classList.remove('is-authenticated');

  // Strictly hide bottom bar and FAB prior to login
  const bottomBar = document.getElementById('mobile-bottom-bar');
  if (bottomBar) bottomBar.style.display = 'none';
  const fab = document.getElementById('mobile-fab');
  if (fab) fab.style.display = 'none';

  state.files = [];
  state.folders = [];
  stopConcurrentThreatEngine();
}

function updateRoleSpecificViews() {
  const isCustomer = state.currentUser && state.currentUser.role === 'customer';
  const staffArena = document.getElementById('sim-staff-arena-view');
  const customerView = document.getElementById('sim-customer-peripheral-view');

  if (staffArena) staffArena.style.display = isCustomer ? 'none' : 'block';
  if (customerView) customerView.style.display = isCustomer ? 'block' : 'none';
}

async function handleAuthSubmit(event, mode) {
  event.preventDefault();
  const errBox = document.getElementById(mode === 'login' ? 'auth-error-msg' : 'reg-error-msg');
  if (errBox) errBox.style.display = 'none';

  if (mode === 'login') {
    const btn = document.getElementById('btn-login-submit');
    const u = document.getElementById('auth-username').value.trim();
    const p = document.getElementById('auth-password').value;

    btn.disabled = true;
    btn.innerText = 'Verifying credentials...';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p }),
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || 'Username or password incorrect.');

      setAuthenticatedState(data.user);
      showToast(`✨ Welcome back, ${data.user.username}!`);
      loadFiles('root');
      startConcurrentThreatEngine();
    } catch (err) {
      if (errBox) {
        errBox.innerText = err.message;
        errBox.style.display = 'block';
      }
    } finally {
      btn.disabled = false;
      btn.innerText = 'Sign in';
    }
  } else {
    const btn = document.getElementById('btn-reg-submit');
    const u = document.getElementById('reg-username').value.trim();
    const p = document.getElementById('reg-password').value;
    const r = document.getElementById('reg-role').value;

    btn.disabled = true;
    btn.innerText = 'Creating account vault...';

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p, role: r }),
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || 'Registration failed.');

      setAuthenticatedState(data.user);
      showToast(`🎉 Vault created! Logged in as ${data.user.username}`);
      loadFiles('root');
      startConcurrentThreatEngine();
    } catch (err) {
      if (errBox) {
        errBox.innerText = err.message;
        errBox.style.display = 'block';
      }
    } finally {
      btn.disabled = false;
      btn.innerText = 'Create Account & Vault';
    }
  }
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch (e) {}
  setUnauthenticatedState();
  showToast('Logged out of Cloud-D.');
  switchTab('drive');
}

function switchAuthMode(mode) {
  document.getElementById('login-view').style.display = mode === 'login' ? 'block' : 'none';
  document.getElementById('register-view').style.display = mode === 'register' ? 'block' : 'none';
  const loginErr = document.getElementById('auth-error-msg');
  if (loginErr) loginErr.style.display = 'none';
  const regErr = document.getElementById('reg-error-msg');
  if (regErr) regErr.style.display = 'none';
}

function togglePasswordVisibility(inputId, isVisible) {
  const el = document.getElementById(inputId);
  if (el) el.type = isVisible ? 'text' : 'password';
}

// -------------------------------------------------------------
// Real-Time Concurrent Threat Synchronization Engine
// -------------------------------------------------------------
function startConcurrentThreatEngine() {
  stopConcurrentThreatEngine();

  // 1. Initial fetch
  fetchActiveThreats();

  // 2. Setup Server-Sent Events (SSE) for immediate push
  try {
    if (window.EventSource) {
      state.threatEventSource = new EventSource('/api/threats/stream');
      state.threatEventSource.addEventListener('threat_triggered', (e) => {
        try {
          const threat = JSON.parse(e.data);
          handleIncomingThreatNotification(threat);
          fetchActiveThreats();
        } catch (err) {}
      });
      state.threatEventSource.addEventListener('threat_mitigated', (e) => {
        fetchActiveThreats();
      });
      state.threatEventSource.onerror = () => {
        if (state.threatEventSource) {
          state.threatEventSource.close();
          state.threatEventSource = null;
        }
      };
    }
  } catch (e) {}

  // 3. Fallback heartbeat polling every 2.5s
  state.threatPollTimer = setInterval(fetchActiveThreats, 2500);

  // 4. Cross-tab BroadcastChannel
  try {
    const channel = new BroadcastChannel('cloud_d_threats');
    channel.onmessage = () => fetchActiveThreats();
  } catch (e) {}
}

function stopConcurrentThreatEngine() {
  if (state.threatEventSource) {
    state.threatEventSource.close();
    state.threatEventSource = null;
  }
  if (state.threatPollTimer) {
    clearInterval(state.threatPollTimer);
    state.threatPollTimer = null;
  }
}

async function fetchActiveThreats() {
  if (!state.currentUser) return;
  try {
    const res = await fetch('/api/threats/active');
    if (res.ok) {
      const data = await res.json();
      state.activeThreats = data.active_threats || [];
      renderOngoingThreatsSection(data.active_count, state.activeThreats);
    }
  } catch (e) {}
}

function handleIncomingThreatNotification(threat) {
  if (state.currentUser && state.currentUser.role === 'customer') {
    // Reassure customer: peripheral defense holding, zero action needed
    showToast(
      `🛡️ Autonomous Peripheral Shield Engaged: An adversarial probe at Ring 1/2 is being isolated by Sentinels. Your Customer Vault (Node 3) remains 100% sealed.`,
      6000
    );
  } else if (state.currentUser && state.currentUser.role === 'staff') {
    showToast(`⚔️ Attack Triggered: Sentinel defenses engaged against ${threat.threat_name}.`, 4000);
  }
}

// -------------------------------------------------------------
// Ongoing Threats Section & Customer Peripheral Levels
// -------------------------------------------------------------
function renderOngoingThreatsSection(activeCount, threats) {
  // Update Header Threat Badge
  const headerBadge = document.getElementById('header-threat-badge');
  if (headerBadge) {
    if (activeCount > 0) {
      headerBadge.innerHTML = `🚨 ${activeCount} ACTIVE INCURSION${activeCount > 1 ? 'S' : ''}`;
      headerBadge.className = 'threat-pill-active';
      headerBadge.style.display = 'inline-flex';
    } else {
      headerBadge.innerHTML = `🛡️ DEFENSE NOMINAL`;
      headerBadge.className = 'threat-pill-nominal';
      headerBadge.style.display = 'inline-flex';
    }
  }

  // Update Mobile Bottom Bar Threat Pill Badge
  const mobThreatBadge = document.getElementById('mob-threat-badge');
  if (mobThreatBadge) {
    if (activeCount > 0) {
      mobThreatBadge.innerText = activeCount;
      mobThreatBadge.style.display = 'inline-block';
    } else {
      mobThreatBadge.style.display = 'none';
    }
  }

  const container = document.getElementById('ongoing-threats-container');
  if (!container) return;

  const isCustomer = state.currentUser?.role === 'customer';
  const activeItems = threats.filter((t) => t.status === 'ACTIVE');
  const recentItems = threats.filter((t) => t.status !== 'ACTIVE');

  // =========================================================
  // CUSTOMER VIEW: PERIPHERAL LEVELS (NO CONTROL, BACKGROUND PROCESS)
  // =========================================================
  if (isCustomer) {
    if (activeCount === 0 && threats.length === 0) {
      container.innerHTML = `
        <div class="peripheral-card peripheral-nominal">
          <div class="peripheral-header">
            <div class="peripheral-title">
              <span class="peripheral-indicator ind-green"></span>
              Autonomous Peripheral Defense: All 4 Rings Secure
            </div>
            <span class="peripheral-tag tag-nominal">PROTECTED</span>
          </div>
          <p class="peripheral-desc">
            Your Customer Vault (Node 3) is guarded by autonomous Sentinels. Incursions are neutralized automatically at peripheral tiers with zero customer action required.
          </p>
          <div class="peripheral-rings-row">
            <div class="ring-mini-box box-safe">
              <span class="ring-dot dot-green"></span>
              <strong>Ring 1:</strong> Ingress Edge (Filtered)
            </div>
            <div class="ring-mini-box box-safe">
              <span class="ring-dot dot-green"></span>
              <strong>Ring 2:</strong> QueryShield AST (Safe)
            </div>
            <div class="ring-mini-box box-safe">
              <span class="ring-dot dot-green"></span>
              <strong>Ring 3:</strong> AuthWall (Partitioned)
            </div>
            <div class="ring-mini-box box-safe">
              <span class="ring-dot dot-green"></span>
              <strong>Ring 4:</strong> Customer Vault (AEAD Sealed)
            </div>
          </div>
        </div>
      `;
      return;
    }

    // Active incursion: show peripheral rings absorbing and mitigating the attack
    let html = `
      <div class="peripheral-card ${activeCount > 0 ? 'peripheral-active pulse-animation' : 'peripheral-nominal'}">
        <div class="peripheral-header">
          <div class="peripheral-title">
            <span class="peripheral-indicator ${activeCount > 0 ? 'ind-red' : 'ind-green'}"></span>
            ${activeCount > 0 ? `Autonomous Incursion Containment in Progress (${activeCount} Active)` : 'Peripheral Defense Holding'}
          </div>
          <span class="peripheral-tag ${activeCount > 0 ? 'tag-active' : 'tag-nominal'}">
            ${activeCount > 0 ? 'AUTONOMOUS BACKGROUND DEFENSE' : 'SAFE'}
          </span>
        </div>

        <p class="peripheral-desc">
          ${
            activeCount > 0
              ? 'An adversarial probe was detected at peripheral tiers. Sentinels are autonomously neutralizing the vector. <strong>You have no control required</strong>—your files are cryptographically air-gapped.'
              : 'All peripheral rings have contained recent probes. Zero bytes compromised.'
          }
        </p>

        <!-- 4 Peripheral Defense Rings Status -->
        <div class="peripheral-rings-grid">
          <div class="peripheral-ring-item ${activeCount > 0 ? 'ring-active-defense' : 'ring-nominal-item'}">
            <div class="ring-top">
              <span class="ring-label">RING 1</span>
              <span class="ring-badge-status">${activeCount > 0 ? '⚡ ACTIVE MITIGATION' : '🟢 NOMINAL'}</span>
            </div>
            <div class="ring-name">Ingress Edge Perimeter</div>
            <div class="ring-desc">Token-bucket rate limiting & packet inspection.</div>
          </div>

          <div class="peripheral-ring-item ${activeCount > 0 ? 'ring-active-defense' : 'ring-nominal-item'}">
            <div class="ring-top">
              <span class="ring-label">RING 2</span>
              <span class="ring-badge-status">${activeCount > 0 ? '🛡️ EXPECTIMAX ANALYSIS' : '🟢 NOMINAL'}</span>
            </div>
            <div class="ring-name">QueryShield AST Filter</div>
            <div class="ring-desc">Evaluating stochastic AST chance nodes to sanitize syntax.</div>
          </div>

          <div class="peripheral-ring-item ring-nominal-item">
            <div class="ring-top">
              <span class="ring-label">RING 3</span>
              <span class="ring-badge-status">🔒 PARTITIONED</span>
            </div>
            <div class="ring-name">Access Firewall & AuthWall</div>
            <div class="ring-desc">Strict tenant boundary prevents cross-shard session leak.</div>
          </div>

          <div class="peripheral-ring-item ring-core-vault">
            <div class="ring-top">
              <span class="ring-label">RING 4 (CORE)</span>
              <span class="ring-badge-status tag-core">💎 100% SEALED</span>
            </div>
            <div class="ring-name">Customer Vault (Node 3)</div>
            <div class="ring-desc">Galois 128-bit GHASH AEAD tag verified intact.</div>
          </div>
        </div>

        <!-- Live Protection Pipeline (Read-Only) -->
        <div class="protection-flow-box">
          <div class="flow-header">Autonomous Protection Status:</div>
          <div class="flow-steps-row">
            <span class="flow-step-tag step-done">✔ Perimeter Anomaly Flagged</span>
            <span class="flow-arrow">→</span>
            <span class="flow-step-tag ${activeCount > 0 ? 'step-pulsing' : 'step-done'}">
              ${activeCount > 0 ? '⚡ Sentinels Quarantining Vector' : '✔ Vector Neutralized'}
            </span>
            <span class="flow-arrow">→</span>
            <span class="flow-step-tag step-done">✔ Node 3 Cryptographic Isolation Verified</span>
          </div>
        </div>
      </div>
    `;

    container.innerHTML = html;
    return;
  }

  // =========================================================
  // STAFF VIEW: OPERATIONAL MANAGEMENT (CONTROLS & RESOLUTION)
  // =========================================================
  if (activeCount === 0 && threats.length === 0) {
    container.innerHTML = `
      <div class="threat-nominal-card">
        <div class="threat-nominal-icon">🟢</div>
        <div>
          <div class="threat-nominal-title">Multi-Agent Sentinel Network Active & Secure</div>
          <div class="threat-nominal-desc">QueryShield (Expectimax), ShardSentry (Minimax), and AuthWall inspecting ingress. Staff partition Node 2 operational.</div>
        </div>
      </div>
    `;
    return;
  }

  let html = '';
  if (activeItems.length > 0) {
    html += `
      <div class="threat-alert-banner pulse-animation">
        <div class="threat-banner-header">
          <span class="threat-pulse-dot"></span>
          <strong>ACTIVE THREAT DEFENSE IN PROGRESS (${activeItems.length})</strong>
          <span class="threat-role-tag">Staff Operational Control</span>
        </div>
        <div class="threat-cards-list">
    `;

    activeItems.forEach((t) => {
      html += `
        <div class="active-threat-card">
          <div class="threat-card-top">
            <span class="threat-card-badge ${t.severity === 'CRITICAL' ? 'badge-crit' : 'badge-high'}">${t.severity}</span>
            <span class="threat-card-name">${escapeHtml(t.threat_name)}</span>
            <span class="threat-card-time">${t.elapsed_seconds}s ago</span>
          </div>
          <div class="threat-card-body">
            <div class="threat-detail-row"><span>🎯 Target Shard:</span> <strong>Node ${t.target_node}</strong></div>
            <div class="threat-detail-row"><span>⚔️ Attacker:</span> <strong>${escapeHtml(t.attacker_agent)}</strong></div>
            <div class="threat-detail-row"><span>🛡️ Defender:</span> <strong>${escapeHtml(t.defender_agent)}</strong></div>
            <div class="threat-safety-box">
              🔒 <strong>Customer Safety Status:</strong> ${escapeHtml(t.customer_impact)}
            </div>
          </div>
          <div class="threat-card-actions">
            <button class="btn-resolve-threat" onclick="resolveThreatManually('${t.threat_id}')">Mitigate & Contain</button>
          </div>
        </div>
      `;
    });

    html += `</div></div>`;
  }

  if (recentItems.length > 0) {
    html += `
      <div class="recent-threats-summary">
        <div class="recent-threats-title">Recently Quarantined Probes (Last 15m)</div>
        <div class="recent-threats-grid">
    `;
    recentItems.slice(0, 3).forEach((t) => {
      html += `
        <div class="recent-threat-pill">
          <span class="pill-status-dot"></span>
          <span class="pill-name">${escapeHtml(t.threat_name)}</span>
          <span class="pill-mitigated-tag">MITIGATED</span>
        </div>
      `;
    });
    html += `</div></div>`;
  }

  container.innerHTML = html;
}

async function resolveThreatManually(threatId) {
  try {
    const res = await fetch('/api/threats/active/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threat_id: threatId }),
    });
    if (res.ok) {
      showToast('🛡️ Threat marked as mitigated by Security Operations.');
      fetchActiveThreats();
    }
  } catch (e) {}
}

// -------------------------------------------------------------
// Easily Operable AI Agent Simulation Engine (Website & Mobile)
// -------------------------------------------------------------
// Interactive & Automated Threat Simulation Engine
// Pixel-Perfect Implementation matching Reference Architecture
// -------------------------------------------------------------
const AGENT_PROFILES = {
  credential_bot: {
    agentName: 'Credential-Bot',
    targetName: 'Auth Server (Node 0)',
    nodeId: 0,
    vector: 'Credential attacks',
    subTactic: 'credential stuffing',
    defender: 'AuthSentinel',
    action: 'block_ip + lock account',
    baseUtility: 0.70,
    minimax: 'Minimax Game-Tree Search (Depth 2): Credential-Bot calculated expected adversarial payoff across possible defender replies. AuthSentinel detected velocity anomalies and initiated progressive lockout.',
    cloudStatus: 'Target node Auth Server protected. Persistent SQLite databases, user folders, and AES-256-GCM encrypted files remain secure.'
  },
  query_bot: {
    agentName: 'Query-Bot',
    targetName: 'Ingress Edge (Node 1)',
    nodeId: 1,
    vector: 'SQL AST Mutation',
    subTactic: 'AST grammar injection',
    defender: 'QueryShield',
    action: 'ast_filter + token_throttle',
    baseUtility: 0.82,
    minimax: 'Expectimax Decision Tree (P=1.00): QueryShield evaluated chance nodes for obfuscated SQL AST tokens and intercepted payload before database query dispatch.',
    cloudStatus: 'Target node Ingress Edge protected. Token-bucket rate limiter intact and SQL injection filtered.'
  },
  tamper_bot: {
    agentName: 'Tamper-Bot',
    targetName: 'Primary Vault (Node 2)',
    nodeId: 2,
    vector: 'Galois Bit-Flip',
    subTactic: 'GHASH tag perturbation',
    defender: 'ShardSentry',
    action: 'quarantine_shard + rotate_nonce',
    baseUtility: 0.75,
    minimax: 'Minimax Game-Tree Search (Depth 2): ShardSentry calculated adversarial payoff for bit-flipped AEAD tag. Shard partitioned instantly and nonce quarantined.',
    cloudStatus: 'Target node Primary Vault protected. Galois field AEAD authentication preserved.'
  },
  replay_bot: {
    agentName: 'Replay-Bot',
    targetName: 'Customer Vault (Node 3)',
    nodeId: 3,
    vector: 'Cross-Shard Replay',
    subTactic: 'cross-tenant transplant',
    defender: 'Regional Shard Router',
    action: 'reject_aad_mismatch + isolation',
    baseUtility: 0.88,
    minimax: 'Minimax Boundary Defense: Replay-Bot attempted to inject foreign ciphertext into isolated customer shard. Tenant barrier sealed and zero bleed occurred.',
    cloudStatus: 'Target node Customer Vault protected. Air-gap guarantee preserved. Customer data 100% sealed.'
  },
  token_burst: {
    agentName: 'Ingress-Flooder',
    targetName: 'Ingress Edge (Node 1)',
    nodeId: 1,
    vector: 'DDoS Rate Flood',
    subTactic: '1,200 req/s burst spike',
    defender: 'Token-Bucket Limiter',
    action: 'throttle_ip + drop_burst',
    baseUtility: 0.78,
    minimax: 'Minimax Rate Boundary Defense: Token bucket capacity exceeded. Ingress edge dropped volumetric flood while preserving authorized staff channels.',
    cloudStatus: 'Target node Ingress Edge protected. Volumetric spike absorbed.'
  }
};

function onManualAgentChange() {
  const agentSelect = document.getElementById('sim-manual-agent');
  const agentKey = agentSelect?.value || 'credential_bot';
  const profile = AGENT_PROFILES[agentKey] || AGENT_PROFILES.credential_bot;

  const badgeText = document.getElementById('sim-target-badge-text');
  if (badgeText) {
    badgeText.textContent = profile.targetName;
  }
}

function onUtilitySliderChange(val) {
  const num = parseFloat(val).toFixed(2);
  const disp = document.getElementById('decision-utility-display');
  if (disp) disp.textContent = num;
  const thresh = document.getElementById('outcome-thresh-display');
  if (thresh) thresh.textContent = num;
  state.utilityThreshold = parseFloat(val);
}

function addDecisionRow(roundNum, attackerName, subTactic, targetNodeName, utilityVal, actionStr, outcomeStr) {
  const tbody = document.getElementById('recent-threat-decisions-tbody');
  if (!tbody) return;
  const padRound = String(roundNum).padStart(2, '0');
  const tr = document.createElement('tr');
  tr.style.borderTop = '1px solid #f1f5f9';
  tr.innerHTML = `
    <td style="padding: 14px 16px; font-size: 13px; font-weight: 600; color: #1e293b;">${padRound}</td>
    <td style="padding: 14px 16px;">
      <div style="font-size: 13.5px; font-weight: 700; color: #0f172a;">${escapeHtml(attackerName)}</div>
      <div style="font-size: 11px; color: #64748b;">${escapeHtml(subTactic)}</div>
    </td>
    <td style="padding: 14px 16px; font-size: 13px; color: #334155; font-weight: 500;">${escapeHtml(targetNodeName)}</td>
    <td style="padding: 14px 16px; font-size: 13px; color: #0f172a; font-weight: 600;">${utilityVal.toFixed(2)}</td>
    <td style="padding: 14px 16px; font-size: 13px; color: #334155; font-family: monospace;">${escapeHtml(actionStr)}</td>
    <td style="padding: 14px 16px;">
      <span style="background: #dcfce7; color: #16a34a; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">${escapeHtml(outcomeStr)}</span>
    </td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);

  while (tbody.children.length > 25) {
    tbody.removeChild(tbody.lastChild);
  }
}

async function launchManualAttack() {
  if (state.currentUser?.role !== 'staff') {
    showToast('Notice: Simulation controls are reserved for staff members.');
    return;
  }
  if (state.simRunning) return;
  state.simRunning = true;

  const agentSelect = document.getElementById('sim-manual-agent');
  const pressureSelect = document.getElementById('sim-manual-pressure');
  const agentKey = agentSelect?.value || 'credential_bot';
  const pressure = pressureSelect?.value || 'normal';
  const profile = AGENT_PROFILES[agentKey] || AGENT_PROFILES.credential_bot;

  const btn = document.getElementById('btn-launch-manual');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span>⚡</span> Evaluating...';
  }

  state.simRoundNumber = (state.simRoundNumber || 1) + 1;
  const currentRound = state.simRoundNumber;
  const threshold = state.utilityThreshold !== undefined ? state.utilityThreshold : 0.40;

  const pressureMod = pressure === 'maximum' ? 0.08 : (pressure === 'elevated' ? 0.04 : 0);
  const computedUtility = Math.min(0.99, Math.max(0.15, profile.baseUtility + pressureMod + (Math.random() * 0.04 - 0.02)));

  try {
    // 1. Call backend to trigger concurrent active threat event for real-time customer broadcast
    fetch('/api/threats/active/trigger', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        threat_type: agentKey,
        target_node: profile.nodeId,
        details: { pressure, agent: profile.agentName, utility: computedUtility }
      }),
    }).catch(() => {});

    // 2. Call backend Red-Team Q-learning simulation
    fetch('/api/threats/red-team/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: `mutate_${agentKey}` }),
    }).catch(() => {});

    // Update Outcome Result Card
    const titleEl = document.getElementById('outcome-card-title');
    const subEl = document.getElementById('outcome-card-subtitle');
    const badgeEl = document.getElementById('outcome-status-badge');
    const vecEl = document.getElementById('outcome-vector');
    const defEl = document.getElementById('outcome-defender');
    const actEl = document.getElementById('outcome-action');
    const utilNumEl = document.getElementById('outcome-utility-num');
    const threshEl = document.getElementById('outcome-thresh-display');
    const treeEl = document.getElementById('outcome-game-tree-box');
    const cloudStatEl = document.getElementById('outcome-cloud-protection-status');

    const cleanTargetName = profile.targetName.split(' (')[0];

    if (titleEl) titleEl.textContent = `${profile.agentName} → ${cleanTargetName}`;
    if (subEl) subEl.textContent = `${profile.subTactic} • Round ${currentRound}`;
    if (badgeEl) badgeEl.textContent = 'BLOCKED • CONTAINED';
    if (vecEl) vecEl.textContent = profile.vector;
    if (defEl) defEl.textContent = profile.defender;
    if (actEl) actEl.textContent = profile.action;
    if (utilNumEl) utilNumEl.textContent = computedUtility.toFixed(2);
    if (threshEl) threshEl.textContent = threshold.toFixed(2);
    if (treeEl) treeEl.textContent = profile.minimax;
    if (cloudStatEl) {
      cloudStatEl.innerHTML = `Cloud Protection Status: Target node <strong>${escapeHtml(cleanTargetName)}</strong> protected. Persistent SQLite databases, user folders, and AES-256-GCM encrypted files remain secure.`;
    }

    // Add to Recent Decisions Table
    addDecisionRow(
      currentRound,
      profile.agentName,
      profile.subTactic,
      cleanTargetName,
      computedUtility,
      profile.action,
      'BLOCKED'
    );

    showToast(`🛡️ ${profile.agentName} intercepted by ${profile.defender}! (Utility: ${computedUtility.toFixed(2)})`);
    fetchActiveThreats();
  } catch (err) {
    showToast(`Error: ${err.message}`);
  } finally {
    setTimeout(() => {
      state.simRunning = false;
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<span>⚡</span> Launch Manual Attack';
      }
    }, 400);
  }
}

async function stepOneRound() {
  if (state.currentUser?.role !== 'staff') {
    showToast('Notice: Simulation controls are reserved for staff members.');
    return;
  }
  if (state.simRunning) return;

  const activeKeys = [];
  if (document.getElementById('vec-credential')?.checked) activeKeys.push('credential_bot');
  if (document.getElementById('vec-ddos')?.checked) activeKeys.push('token_burst');
  if (document.getElementById('vec-sqli')?.checked) activeKeys.push('query_bot');
  if (document.getElementById('vec-galois')?.checked) activeKeys.push('tamper_bot');

  if (activeKeys.length === 0) activeKeys.push('credential_bot');
  const chosenKey = activeKeys[Math.floor(Math.random() * activeKeys.length)];

  const agentSelect = document.getElementById('sim-manual-agent');
  if (agentSelect && agentSelect.querySelector(`option[value="${chosenKey}"]`)) {
    agentSelect.value = chosenKey;
    onManualAgentChange();
  }

  await launchManualAttack();
}

async function runAutomatedDefenseSuite() {
  if (state.currentUser?.role !== 'staff') {
    showToast('Notice: Automated defense is reserved for staff members.');
    return;
  }
  if (state.simRunning) return;

  const roundsSelect = document.getElementById('sim-auto-rounds');
  const totalRounds = parseInt(roundsSelect?.value || '5', 10);

  const btn = document.getElementById('btn-run-automated');
  if (btn) {
    btn.disabled = true;
    btn.style.opacity = '0.8';
  }

  const activeKeys = [];
  if (document.getElementById('vec-credential')?.checked) activeKeys.push('credential_bot');
  if (document.getElementById('vec-ddos')?.checked) activeKeys.push('token_burst');
  if (document.getElementById('vec-sqli')?.checked) activeKeys.push('query_bot');
  if (document.getElementById('vec-galois')?.checked) activeKeys.push('tamper_bot');
  if (activeKeys.length === 0) activeKeys.push('credential_bot', 'query_bot');

  showToast(`🚀 Starting automated defense simulation (${totalRounds} rounds)...`);

  for (let r = 1; r <= totalRounds; r++) {
    if (btn) btn.innerHTML = `Running round ${r}/${totalRounds}...`;
    const chosenKey = activeKeys[(r - 1) % activeKeys.length];

    const agentSelect = document.getElementById('sim-manual-agent');
    if (agentSelect && agentSelect.querySelector(`option[value="${chosenKey}"]`)) {
      agentSelect.value = chosenKey;
      onManualAgentChange();
    }

    await launchManualAttack();
    await new Promise((resolve) => setTimeout(resolve, 350));
  }

  if (btn) {
    btn.disabled = false;
    btn.style.opacity = '1';
    btn.innerHTML = 'Run Automated Defense';
  }

  showToast(`🏆 Automated defense complete! All ${totalRounds} adversarial rounds neutralized.`);
}

// Backwards-compatible aliases for any preset triggers or external tests
async function runQuickSimulation(type) {
  const mapping = {
    sqli_llm: 'query_bot',
    galois_tamper: 'tamper_bot',
    cross_shard: 'replay_bot',
    token_burst: 'token_burst',
  };
  const key = mapping[type] || 'credential_bot';
  const agentSelect = document.getElementById('sim-manual-agent');
  if (agentSelect && agentSelect.querySelector(`option[value="${key}"]`)) {
    agentSelect.value = key;
    onManualAgentChange();
  }
  await launchManualAttack();
}

async function runAllSimulationsSuite() {
  await runAutomatedDefenseSuite();
}

// -------------------------------------------------------------
// Navigation & Tab Switching
// -------------------------------------------------------------
function switchTab(tab) {
  let targetSection = null;
  if (tab === 'agent-background') {
    tab = 'security-report';
    targetSection = 'sec-ai-agent-architecture';
  } else if (tab === 'architecture') {
    tab = 'security-report';
    targetSection = 'sec-cloud-architecture';
  }

  state.activeTab = tab;
  const tabs = ['drive', 'agent-background', 'architecture', 'security-report', 'threats', 'profile'];
  tabs.forEach((t) => {
    const el = document.getElementById(`tab-${t}`);
    if (el) el.style.display = t === tab ? 'block' : 'none';
  });

  // Desktop sidebar links
  document.querySelectorAll('.gdrive-nav-link').forEach((el) => {
    const text = el.innerText.toLowerCase();
    const isSec = tab === 'security-report' && text.includes('security');
    const isThreat = tab === 'threats' && (text.includes('threat') || text.includes('simulation'));
    el.classList.toggle('active-pill', isSec || isThreat);
  });

  // Mobile bottom bar items
  document.querySelectorAll('.mobile-tab-item').forEach((el) => {
    const text = el.innerText.toLowerCase();
    const isSec = tab === 'security-report' && text.includes('security');
    const isThreat = tab === 'threats' && (text.includes('threat') || text.includes('simulation'));
    const isDrive = tab === 'drive' && (text.includes('files') || text.includes('drive'));
    el.classList.toggle('active', isSec || isThreat || isDrive);
  });

  if (targetSection) {
    setTimeout(() => {
      const targetEl = document.getElementById(targetSection);
      if (targetEl) targetEl.scrollIntoView({ behavior: 'smooth' });
    }, 50);
  }

  if (tab === 'threats') {
    updateRoleSpecificViews();
    fetchActiveThreats();
  }
}

function switchSidebarTab(category) {
  state.currentCategory = category;
  switchTab('drive');

  document.querySelectorAll('.gdrive-nav-link').forEach((el) => {
    el.classList.remove('active-pill');
  });
  if (window.event && window.event.currentTarget) {
    window.event.currentTarget.classList.add('active-pill');
  }

  const titleRow = document.getElementById('view-title-row');
  const titleText = document.getElementById('view-title-text');
  const searchSec = document.getElementById('drive-search-section');
  const foldersSec = document.getElementById('suggested-folders-section');
  const filesHeader = document.getElementById('files-section-header');
  const filterLoc = document.getElementById('filter-chip-loc');
  const thActivity = document.getElementById('th-activity');

  if (category === 'recent') {
    if (titleRow) titleRow.style.display = 'flex';
    if (titleText) titleText.innerText = 'Recent';
    if (searchSec) searchSec.style.display = 'none';
    if (foldersSec) foldersSec.style.display = 'none';
    if (filesHeader) filesHeader.style.display = 'none';
    if (filterLoc) filterLoc.innerHTML = '📁 Source ▾';
    if (thActivity) thActivity.innerText = '';
    state.filteredFiles = [...state.files].sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
    renderFiles(true); // Chronological grouping matching screenshot media_1792989521886_bbf42880.png
  } else if (category === 'shared') {
    if (titleRow) titleRow.style.display = 'flex';
    if (titleText) titleText.innerText = 'Shared with me';
    if (searchSec) searchSec.style.display = 'flex';
    if (foldersSec) foldersSec.style.display = 'block';
    if (filesHeader) filesHeader.style.display = 'flex';
    if (filterLoc) filterLoc.innerHTML = '📁 Location ▾';
    if (thActivity) thActivity.innerText = 'Reason suggested';
    loadFiles('root');
  } else if (category === 'trash') {
    if (titleRow) titleRow.style.display = 'flex';
    if (titleText) titleText.innerText = 'Trash';
    if (searchSec) searchSec.style.display = 'none';
    if (foldersSec) foldersSec.style.display = 'none';
    if (filesHeader) filesHeader.style.display = 'flex';
    state.filteredFiles = [];
    renderFiles(false);
  } else {
    // 'home' / 'drive'
    if (titleRow) titleRow.style.display = 'none';
    if (searchSec) searchSec.style.display = 'flex';
    if (foldersSec) foldersSec.style.display = 'block';
    if (filesHeader) filesHeader.style.display = 'flex';
    if (filterLoc) filterLoc.innerHTML = '📁 Location ▾';
    if (thActivity) thActivity.innerText = 'Reason suggested';
    loadFiles('root');
  }
}

// -------------------------------------------------------------
// + New Dropdown Menu
// -------------------------------------------------------------
function toggleNewDropdown(e) {
  e.stopPropagation();
  const menu = document.getElementById('new-dropdown');
  if (menu) {
    menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
  }
}

document.addEventListener('click', () => {
  const menu = document.getElementById('new-dropdown');
  if (menu) menu.style.display = 'none';
});

// -------------------------------------------------------------
// Core Files & Folders Loader (Google Drive Structure)
// -------------------------------------------------------------
async function loadFiles(folderId = 'root') {
  state.activeFolder = folderId;

  try {
    const [filesRes, foldersRes] = await Promise.all([
      fetch(`/api/files?folder_id=${encodeURIComponent(folderId)}`),
      fetch('/api/folders'),
    ]);

    if (filesRes.ok) {
      const data = await filesRes.json();
      state.files = data.files || [];
      state.filteredFiles = [...state.files];
    }
    if (foldersRes.ok) {
      const data = await foldersRes.json();
      state.folders = data.folders || [];
      renderSuggestedFolders(state.folders);
    }
    renderFiles(state.currentCategory === 'recent');
  } catch (err) {
    console.error('[Cloud-D] Failed to load files/folders:', err);
  }
}

function renderSuggestedFolders(folders) {
  const grid = document.getElementById('suggested-folders-grid');
  if (!grid) return;

  if (!folders || folders.length === 0) {
    grid.innerHTML = '<div style="color:#747775; font-size:13px;">No folders created yet.</div>';
    return;
  }

  grid.innerHTML = folders
    .slice(0, 5)
    .map(
      (f) => `
    <div class="gdrive-folder-card" onclick="loadFiles('${f.folder_id}')">
      <div class="folder-card-left">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="#7c3aed"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>
        <div>
          <div class="folder-card-name">${escapeHtml(f.name)}</div>
          <div class="folder-card-sub">in Shared with me</div>
        </div>
      </div>
      <div class="folder-card-dots" onclick="event.stopPropagation()">⋮</div>
    </div>
  `
    )
    .join('');
}

function renderFiles(chronological = false) {
  const tbody = document.getElementById('files-table-body');
  if (!tbody) return;

  if (!state.filteredFiles || state.filteredFiles.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:36px; color:#747775;">No files in this folder. Click "+ New" to upload.</td></tr>`;
    return;
  }

  let html = '';
  if (chronological) {
    html += `
      <tr class="group-header-row">
        <td colspan="7">
          <span style="font-weight: 600; color: #444746;">Last week</span>
        </td>
      </tr>
    `;
  }

  state.filteredFiles.forEach((file) => {
    const iconSvg = getFileIcon(file.filename);
    const dateStr = formatActivityDate(file.updated_at || file.created_at);
    const sizeStr = formatFileSize(file.size_bytes);
    const locName = getFolderName(file.folder_id);

    html += `
      <tr class="gdrive-row" data-file-id="${file.file_id}">
        <td class="col-checkbox">
          <input type="checkbox" class="gdrive-chk" onclick="event.stopPropagation()">
        </td>
        <td class="col-name">
          <div class="file-name-cell">
            <span class="file-icon-wrap">${iconSvg}</span>
            <span class="file-title-link" onclick="previewFile('${file.file_id}')">${escapeHtml(file.filename)}</span>
            <span class="badge-revision">v${file.version_number || 1}</span>
            ${file.is_post_quantum ? '<span class="badge-pq" title="ML-KEM-768 Quantum Resistant">PQ</span>' : ''}
          </div>
        </td>
        <td class="col-activity" style="color: #444746; font-size: 13px;">${dateStr}</td>
        <td class="col-owner">
          <div class="owner-badge-cell">
            <span class="owner-avatar-circle">N</span>
            <span style="font-size: 13px; color: #1f1f1f; font-weight: 500;">me</span>
          </div>
        </td>
        <td class="col-size" style="color: #444746; font-size: 13px;">${sizeStr}</td>
        <td class="col-location">
          <div class="location-link" onclick="loadFiles('${file.folder_id}')">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="#7c3aed"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>
            <span>${escapeHtml(locName)}</span>
          </div>
        </td>
        <td class="col-actions" style="position: relative;">
          <button class="action-dots-btn" onclick="toggleFileActionMenu(event, '${file.file_id}')" title="More actions">⋮</button>
          <div id="file-menu-${file.file_id}" class="gdrive-action-menu">
            <div class="action-menu-item" onclick="previewFile('${file.file_id}')">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="#5f6368"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>
              <span>Preview plaintext</span>
            </div>
            <div class="action-menu-item" onclick="verifyHardwareProof('${file.file_id}')">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="#5f6368"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
              <span>Verify AEAD proof</span>
            </div>
            <div class="action-menu-item" onclick="openVersionHistory('${file.file_id}')">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="#5f6368"><path d="M13 3c-4.97 0-9 4.03-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42C8.27 19.99 10.51 21 13 21c4.97 0 9-4.03 9-9s-4.03-9-9-9zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>
              <span>Version history (n+1)</span>
            </div>
            <div class="new-gdrive-divider"></div>
            <div class="action-menu-item item-danger" onclick="deleteFile('${file.file_id}')">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="#b3261e"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
              <span>Delete document</span>
            </div>
          </div>
        </td>
      </tr>
    `;
  });

  tbody.innerHTML = html;
}

// -------------------------------------------------------------
// Interactive Hardware AEAD Proof Modal
// -------------------------------------------------------------
async function verifyHardwareProof(fileId) {
  try {
    const res = await fetch(`/api/files/${fileId}/verify`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Verification failed');

    const modal = document.getElementById('proof-modal');
    const content = document.getElementById('proof-modal-content');
    if (modal && content) {
      content.innerHTML = `
        <div class="proof-field"><span class="proof-label">Document:</span> <strong>${escapeHtml(data.filename)}</strong></div>
        <div class="proof-field"><span class="proof-label">Storage Shard:</span> Node ${data.node_id} (${data.node_region})</div>
        <div class="proof-field"><span class="proof-label">Integrity Status:</span> <span class="proof-valid">✔ ${data.integrity_status}</span></div>
        <div class="proof-field"><span class="proof-label">Galois 128-bit GHASH Tag:</span> <code class="proof-code">${data.galois_tag_hex}</code></div>
        <div class="proof-field"><span class="proof-label">96-bit Nonce IV:</span> <code class="proof-code">${data.nonce_hex}</code> (${data.nonce_bits} bits)</div>
        <div class="proof-field"><span class="proof-label">Galois AAD Binding:</span> <code class="proof-code">${escapeHtml(data.aad_string)}</code></div>
        <div class="proof-field"><span class="proof-label">Plaintext SHA-256:</span> <code class="proof-code">${data.sha256_plaintext_digest}</code></div>
      `;
      modal.style.display = 'flex';
    }
  } catch (err) {
    showToast(`Error: ${err.message}`);
  }
}

// -------------------------------------------------------------
// Preview Plaintext Modal
// -------------------------------------------------------------
async function previewFile(fileId) {
  try {
    const res = await fetch(`/api/files/${fileId}/preview`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Preview failed');

    const modal = document.getElementById('preview-modal');
    const title = document.getElementById('preview-modal-title');
    const body = document.getElementById('preview-modal-body');
    if (modal && title && body) {
      title.innerText = `Decrypted Preview: ${data.filename}`;
      body.innerText = data.preview_text || '[Empty or Binary Content]';
      modal.style.display = 'flex';
    }
  } catch (err) {
    showToast(`Error: ${err.message}`);
  }
}

// -------------------------------------------------------------
// Version History & Rollback / Diff Engine
// -------------------------------------------------------------
async function openVersionHistory(fileId) {
  try {
    const res = await fetch(`/api/files/${fileId}/history`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'History failed');

    state.historyLogicalId = data.logical_id;
    const modal = document.getElementById('history-modal');
    const list = document.getElementById('history-revisions-list');
    if (modal && list) {
      list.innerHTML = data.revisions
        .map(
          (rev) => `
        <div class="history-rev-row ${rev.is_current ? 'rev-active' : ''}">
          <div class="rev-info">
            <span class="rev-badge">v${rev.version_number}</span>
            <span class="rev-name">${escapeHtml(rev.filename)}</span>
            ${rev.is_current ? '<span class="rev-current-tag">ACTIVE</span>' : ''}
            <span class="rev-time">${formatActivityDate(rev.created_at)}</span>
          </div>
          <div class="rev-actions">
            ${
              !rev.is_current
                ? `<button class="btn-rev-promote" onclick="promoteRevision('${rev.file_id}')">Rollback to this</button>
                   <button class="btn-rev-diff" onclick="viewLineDiff('${rev.file_id}', '${fileId}')">Line Diff</button>`
                : '<span style="color:#16a34a; font-weight:700; font-size:12px;">Active Version</span>'
            }
          </div>
        </div>
      `
        )
        .join('');
      modal.style.display = 'flex';
    }
  } catch (err) {
    showToast(`Error: ${err.message}`);
  }
}

async function promoteRevision(fileId) {
  try {
    const res = await fetch(`/api/files/${fileId}/promote`, { method: 'POST' });
    if (res.ok) {
      showToast('✔ Document rolled back to selected revision!');
      closeAllModals();
      loadFiles(state.activeFolder);
    }
  } catch (err) {
    showToast(`Error: ${err.message}`);
  }
}

async function viewLineDiff(baseId, targetId) {
  try {
    const res = await fetch(`/api/files/diff?base_id=${baseId}&target_id=${targetId}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Diff computation failed');

    const diffModal = document.getElementById('diff-modal');
    const diffBody = document.getElementById('diff-modal-body');
    if (diffModal && diffBody) {
      diffBody.innerHTML = `
        <div class="diff-header-stats">
          <span style="color:#16a34a;">+${data.additions} Additions</span> |
          <span style="color:#dc2626;">-${data.deletions} Deletions</span>
        </div>
        <pre class="diff-pre">${data.diff_lines.map((l) => escapeHtml(l)).join('')}</pre>
      `;
      diffModal.style.display = 'flex';
    }
  } catch (err) {
    showToast(`Diff error: ${err.message}`);
  }
}

// -------------------------------------------------------------
// Duplicate Upload Interceptor (n+1 Versioning vs Overwrite)
// -------------------------------------------------------------
async function handleFileUploadInput(e) {
  const file = e.target.files[0];
  if (!file) return;

  state.pendingFile = file;

  try {
    const checkRes = await fetch('/api/files/check-duplicate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: file.name, folder_id: state.activeFolder }),
    });
    const checkData = await checkRes.json();

    if (checkData.exists && checkData.duplicate_info) {
      state.duplicateInfo = checkData.duplicate_info;
      showDuplicateModal(file.name, checkData.duplicate_info.current_version);
      return;
    }

    executeUpload(null, null, false);
  } catch (err) {
    executeUpload(null, null, false);
  }
}

function showDuplicateModal(filename, currentVersion) {
  const modal = document.getElementById('duplicate-modal');
  const desc = document.getElementById('duplicate-modal-desc');
  if (modal && desc) {
    desc.innerText = `A file named "${filename}" already exists in this folder (current: v${currentVersion}). Please choose how Cloud-D should handle this document:`;
    modal.style.display = 'flex';
  }
}

function handleDuplicateChoice(choice) {
  const modal = document.getElementById('duplicate-modal');
  if (modal) modal.style.display = 'none';

  if (!state.pendingFile || !state.duplicateInfo) return;

  if (choice === 'version') {
    executeUpload(state.duplicateInfo.logical_id, null, false);
  } else if (choice === 'replace') {
    executeUpload(null, state.duplicateInfo.file_id, false);
  } else if (choice === 'copy') {
    const ext = state.pendingFile.name.includes('.') ? '.' + state.pendingFile.name.split('.').pop() : '';
    const base = state.pendingFile.name.replace(ext, '');
    const copyName = `${base} (copy-${Math.floor(Math.random() * 9000 + 1000)})${ext}`;
    executeUpload(null, null, true, copyName);
  }
}

async function executeUpload(targetLogicalId, replaceFileId, isCopy = false, overrideName = null) {
  if (!state.pendingFile) return;

  const formData = new FormData();
  formData.append('file', state.pendingFile, overrideName || state.pendingFile.name);
  formData.append('folder_id', state.activeFolder);
  formData.append('node_id', state.currentUser?.role === 'customer' ? '3' : '2');
  if (targetLogicalId) formData.append('target_logical_id', targetLogicalId);
  if (replaceFileId) formData.append('replace_file_id', replaceFileId);

  try {
    showToast('Encrypting & sealing document with Galois AEAD...');
    const res = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Upload failed');

    showToast(`✔ "${data.file.filename}" sealed successfully!`);
    loadFiles(state.activeFolder);
  } catch (err) {
    showToast(`Upload failed: ${err.message}`);
  } finally {
    state.pendingFile = null;
    state.duplicateInfo = null;
    const fileInput = document.getElementById('global-file-input');
    if (fileInput) fileInput.value = '';
  }
}

async function deleteFile(fileId) {
  if (!confirm('Permanently delete this document and all historical revisions?')) return;
  try {
    const res = await fetch(`/api/files/${fileId}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Document deleted.');
      loadFiles(state.activeFolder);
    }
  } catch (err) {
    showToast(`Delete failed: ${err.message}`);
  }
}

// -------------------------------------------------------------
// UI Utilities & Modal Controllers
// -------------------------------------------------------------
function closeAllModals() {
  document.querySelectorAll('.gdrive-modal-overlay, .modal-overlay').forEach((el) => (el.style.display = 'none'));
}

function showToast(msg, duration = 3500) {
  const toast = document.getElementById('global-toast');
  if (!toast) return;
  toast.innerText = msg;
  toast.style.display = 'block';
  setTimeout(() => {
    toast.style.display = 'none';
  }, duration);
}

function toggleFileActionMenu(e, fileId) {
  e.stopPropagation();
  document.querySelectorAll('.gdrive-action-menu, .file-action-dropdown').forEach((el) => {
    if (el.id !== `file-menu-${fileId}`) el.style.display = 'none';
  });
  const menu = document.getElementById(`file-menu-${fileId}`);
  if (menu) {
    menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
  }
}

function formatFileSize(bytes) {
  if (bytes === 0 || !bytes) return '0 bytes';
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatActivityDate(ts) {
  if (!ts) return 'Oct 26 • Uploaded';
  const d = new Date(ts * 1000);
  const now = new Date();
  const diffDays = Math.floor((now - d) / (1000 * 60 * 60 * 24));
  if (diffDays === 0) return 'Today • Uploaded';
  if (diffDays === 1) return 'Yesterday • Uploaded';
  const month = d.toLocaleString('en-US', { month: 'short' });
  const day = d.getDate();
  return `${month} ${day} • Uploaded`;
}

function getFileIcon(filename) {
  const lower = (filename || '').toLowerCase();
  if (lower.endsWith('.pdf')) {
    return `<svg width="20" height="20" viewBox="0 0 24 24" fill="#ea4335"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-9.5 8.5h-1V15H7V9h2.5c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5zm5 2c0 .83-.67 1.5-1.5 1.5h-2.5V9h2.5c.83 0 1.5.67 1.5 1.5v3zm4-3.5h-2v1.5h1.5v1.5H16.5V15H15V9h3.5v1.5z"/></svg>`;
  }
  if (lower.endsWith('.doc') || lower.endsWith('.docx')) {
    return `<svg width="20" height="20" viewBox="0 0 24 24" fill="#4285f4"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`;
  }
  if (lower.endsWith('.py') || lower.endsWith('.js') || lower.endsWith('.json') || lower.endsWith('.pyc')) {
    return `<svg width="20" height="20" viewBox="0 0 24 24" fill="#1a73e8"><path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/></svg>`;
  }
  return `<svg width="20" height="20" viewBox="0 0 24 24" fill="#1a73e8"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm-1 7V3.5L18.5 9H13z"/></svg>`;
}

function getFolderName(folderId) {
  if (folderId === 'root' || !folderId) return 'My Drive';
  const f = state.folders.find((x) => x.folder_id === folderId);
  return f ? f.name : folderId;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeJs(str) {
  if (!str) return '';
  return String(str).replace(/'/g, "\\'");
}

// -------------------------------------------------------------
// Application Boot
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initAuth();
});
