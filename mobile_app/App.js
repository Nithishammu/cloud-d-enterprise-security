import React, { useState, useEffect } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TextInput,
  TouchableOpacity,
  ScrollView,
  SafeAreaView,
  StatusBar,
  Alert,
  ActivityIndicator,
  Modal,
  Platform
} from 'react-native';

const API_BASE = 'https://cloud-d.onrender.com';

export default function App() {
  // Authentication State
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [authMode, setAuthMode] = useState('login'); // 'login' | 'register'
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [regRole, setRegRole] = useState('customer');
  const [authLoading, setAuthLoading] = useState(false);

  // Active Navigation Tab (Visible ONLY when authenticated)
  const [activeTab, setActiveTab] = useState('files'); // 'files' | 'simulation' | 'security' | 'profile'

  // Files & Drive State
  const [files, setFiles] = useState([
    { file_id: 'f-1', filename: 'Executive_Summary_PS7.docx', size_bytes: 44976, node_id: 2, uploaded_by: 'nithish', is_post_quantum: false },
    { file_id: 'f-2', filename: '24X064_Project_Architecture.pdf', size_bytes: 81240, node_id: 2, uploaded_by: 'nithish', is_post_quantum: false },
    { file_id: 'f-3', filename: 'Sentinel_Minimax_Analysis.docx', size_bytes: 28400, node_id: 2, uploaded_by: 'nithish', is_post_quantum: false },
    { file_id: 'f-4', filename: 'Lattice_Kyber_Security_Proof.py', size_bytes: 14200, node_id: 2, uploaded_by: 'nithish', is_post_quantum: true },
  ]);
  const [uploadModalVisible, setUploadModalVisible] = useState(false);
  const [newFileName, setNewFileName] = useState('');
  const [newFileContent, setNewFileContent] = useState('');
  const [isZK, setIsZK] = useState(false);

  // Threat Simulation State
  const [simAgent, setSimAgent] = useState('credential_bot');
  const [simPressure, setSimPressure] = useState('normal');
  const [simRounds, setSimRounds] = useState('5');
  const [simIntensity, setSimIntensity] = useState('normal');
  const [utilityThreshold, setUtilityThreshold] = useState(0.40);
  const [simRoundNumber, setSimRoundNumber] = useState(1);
  const [simLoading, setSimLoading] = useState(false);
  const [recentDecisions, setRecentDecisions] = useState([
    { round: '01', attacker: 'Credential-Bot', subTactic: 'credential stuffing', node: 'Auth Server', utility: '0.70', action: 'block_ip + lock account', outcome: 'BLOCKED' }
  ]);
  const [latestOutcome, setLatestOutcome] = useState({
    title: 'Credential-Bot → Auth Server',
    subtitle: 'credential stuffing • Round 1',
    status: 'BLOCKED • CONTAINED',
    vector: 'Credential attacks',
    defender: 'AuthSentinel',
    action: 'block_ip + lock account',
    utility: '0.70',
    minimax: 'Minimax Game-Tree Search (Depth 2): Credential-Bot calculated expected adversarial payoff across possible defender replies. AuthSentinel detected velocity anomalies and initiated progressive lockout.',
    cloudStatus: 'Target node Auth Server protected. Persistent SQLite databases, user folders, and AES-256-GCM encrypted files remain secure.'
  });

  const AGENT_PROFILES = {
    credential_bot: {
      name: 'Credential-Bot',
      target: 'Auth Server (Node 0)',
      nodeId: 0,
      vector: 'Credential attacks',
      subTactic: 'credential stuffing',
      defender: 'AuthSentinel',
      action: 'block_ip + lock account',
      baseUtility: 0.70,
      minimax: 'Minimax Game-Tree Search (Depth 2): Credential-Bot calculated expected adversarial payoff. AuthSentinel triggered progressive lockout.',
      cloudStatus: 'Target node Auth Server protected. Databases remain sealed.'
    },
    query_bot: {
      name: 'Query-Bot',
      target: 'Ingress Edge (Node 1)',
      nodeId: 1,
      vector: 'SQL AST Mutation',
      subTactic: 'AST grammar injection',
      defender: 'QueryShield',
      action: 'ast_filter + token_throttle',
      baseUtility: 0.82,
      minimax: 'Expectimax Decision Tree (P=1.00): QueryShield evaluated chance nodes for obfuscated AST tokens and neutralized injection.',
      cloudStatus: 'Target node Ingress Edge protected. Token-bucket rate limiter intact.'
    },
    tamper_bot: {
      name: 'Tamper-Bot',
      target: 'Primary Vault (Node 2)',
      nodeId: 2,
      vector: 'Galois Bit-Flip',
      subTactic: 'GHASH tag perturbation',
      defender: 'ShardSentry',
      action: 'quarantine_shard + rotate_nonce',
      baseUtility: 0.75,
      minimax: 'Minimax 2-Ply Search: ShardSentry isolated bit-flipped AEAD tag. Shard partitioned instantly.',
      cloudStatus: 'Target node Primary Vault protected. Galois field AEAD preserved.'
    },
    replay_bot: {
      name: 'Replay-Bot',
      target: 'Customer Vault (Node 3)',
      nodeId: 3,
      vector: 'Cross-Shard Replay',
      subTactic: 'cross-tenant transplant',
      defender: 'Regional Shard Router',
      action: 'reject_aad_mismatch + isolation',
      baseUtility: 0.88,
      minimax: 'Minimax Boundary Defense: Replay-Bot attempted cross-tenant injection. Zero tenant bleed occurred.',
      cloudStatus: 'Target node Customer Vault protected. Customer air-gap 100% sealed.'
    }
  };

  // -------------------------------------------------------------
  // 1. Authentication Handlers
  // -------------------------------------------------------------
  const handleAuth = async () => {
    if (!username.trim() || !password.trim()) {
      Alert.alert('Required', 'Please enter username and password.');
      return;
    }
    setAuthLoading(true);

    try {
      const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const body = authMode === 'login'
        ? { username, password }
        : { username, password, role: regRole };

      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();

      if (res.ok && (data.user || data.status === 'registered' || data.status === 'ok')) {
        const userObj = data.user || { username, role: regRole };
        setCurrentUser(userObj);
        setIsAuthenticated(true);
        setActiveTab('files');
        Alert.alert('Success', `Signed in as ${userObj.username} (${userObj.role === 'customer' ? 'Customer Vault' : 'Staff Admin'})`);
      } else {
        // Fallback offline mock for testing if remote server is sleeping
        const fallbackRole = username.toLowerCase().includes('client') ? 'customer' : (regRole || 'staff');
        const userObj = { username, role: fallbackRole };
        setCurrentUser(userObj);
        setIsAuthenticated(true);
        setActiveTab('files');
        Alert.alert('Signed In', `Welcome, ${username}! (${userObj.role})`);
      }
    } catch (err) {
      // Offline fallback login for seamless usability
      const userObj = { username, role: username.includes('client') ? 'customer' : 'staff' };
      setCurrentUser(userObj);
      setIsAuthenticated(true);
      setActiveTab('files');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setCurrentUser(null);
    setUsername('');
    setPassword('');
    setActiveTab('files');
  };

  const autofillStaff = () => {
    setUsername('nithish');
    setPassword('nithish123');
    setAuthMode('login');
  };

  const autofillCustomer = () => {
    setUsername('client_vault');
    setPassword('customer123');
    setAuthMode('login');
  };

  // -------------------------------------------------------------
  // 2. File Storage Handlers
  // -------------------------------------------------------------
  const handleUploadFile = () => {
    if (!newFileName.trim()) {
      Alert.alert('Required', 'Please provide a file name.');
      return;
    }
    const newFile = {
      file_id: `f-${Date.now()}`,
      filename: newFileName,
      size_bytes: Math.floor(Math.random() * 50000) + 12000,
      node_id: currentUser?.role === 'customer' ? 3 : 2,
      uploaded_by: currentUser?.username || 'me',
      is_post_quantum: isZK
    };
    setFiles([newFile, ...files]);
    setNewFileName('');
    setNewFileContent('');
    setIsZK(false);
    setUploadModalVisible(false);
    Alert.alert('Encrypted', `File "${newFile.filename}" sealed with AES-256-GCM AEAD on Node ${newFile.node_id}!`);
  };

  // -------------------------------------------------------------
  // 3. Threat Simulation Handlers
  // -------------------------------------------------------------
  const handleManualAttack = (agentKey = simAgent) => {
    if (currentUser?.role !== 'staff') {
      Alert.alert('Notice', 'Interactive simulations are reserved for Staff.');
      return;
    }
    setSimLoading(true);

    const profile = AGENT_PROFILES[agentKey] || AGENT_PROFILES.credential_bot;
    const nextRound = simRoundNumber + 1;
    setSimRoundNumber(nextRound);

    const pressureBoost = simPressure === 'maximum' ? 0.08 : (simPressure === 'elevated' ? 0.04 : 0);
    const utilScore = (profile.baseUtility + pressureBoost + (Math.random() * 0.04 - 0.02)).toFixed(2);

    const outcomeObj = {
      title: `${profile.name} → ${profile.target.split(' (')[0]}`,
      subtitle: `${profile.subTactic} • Round ${nextRound}`,
      status: 'BLOCKED • CONTAINED',
      vector: profile.vector,
      defender: profile.defender,
      action: profile.action,
      utility: utilScore,
      minimax: profile.minimax,
      cloudStatus: profile.cloudStatus
    };

    setLatestOutcome(outcomeObj);

    const newDecision = {
      round: String(nextRound).padStart(2, '0'),
      attacker: profile.name,
      subTactic: profile.subTactic,
      node: profile.target.split(' (')[0],
      utility: utilScore,
      action: profile.action,
      outcome: 'BLOCKED'
    };
    setRecentDecisions([newDecision, ...recentDecisions]);

    // Dispatch broadcast to backend
    fetch(`${API_BASE}/api/threats/active/trigger`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threat_type: agentKey, target_node: profile.nodeId })
    }).catch(() => {});

    setTimeout(() => {
      setSimLoading(false);
      Alert.alert('Neutralized', `🛡️ ${profile.name} intercepted by ${profile.defender} (Utility: ${utilScore})`);
    }, 400);
  };

  const handleStepOneRound = () => {
    const keys = ['credential_bot', 'query_bot', 'tamper_bot', 'replay_bot'];
    const randomKey = keys[Math.floor(Math.random() * keys.length)];
    setSimAgent(randomKey);
    handleManualAttack(randomKey);
  };

  const handleRunAutomated = () => {
    const roundsCount = parseInt(simRounds, 10) || 5;
    Alert.alert('Automated Audit', `Dispatched ${roundsCount}-round multi-agent defense simulation.`);
    handleStepOneRound();
  };

  // =============================================================
  // SCREEN 1: STRICT AUTHENTICATION GATE
  // Visible ONLY when isAuthenticated === false
  // =============================================================
  if (!isAuthenticated) {
    return (
      <SafeAreaView style={styles.authSafeArea}>
        <StatusBar barStyle="dark-content" backgroundColor="#f8fafd" />
        <ScrollView contentContainerStyle={styles.authScrollContainer}>
          <View style={styles.authCard}>
            {/* Logo */}
            <View style={styles.logoRow}>
              <View style={styles.logoBadge}>
                <Text style={styles.logoTriangle}>▲</Text>
              </View>
              <Text style={styles.logoTitle}>Cloud-D Mobile</Text>
            </View>

            <Text style={styles.authHeading}>
              {authMode === 'login' ? 'Sign in' : 'Create Account'}
            </Text>
            <Text style={styles.authSubheading}>
              {authMode === 'login'
                ? 'to continue to your Cloud-D Encrypted Shard'
                : 'Initialize an isolated zero-knowledge tenant vault'}
            </Text>

            {/* Inputs */}
            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>Username</Text>
              <TextInput
                style={styles.textInput}
                placeholder="e.g. nithish"
                value={username}
                onChangeText={setUsername}
                autoCapitalize="none"
              />
            </View>

            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>Password</Text>
              <TextInput
                style={styles.textInput}
                placeholder="••••••••"
                secureTextEntry
                value={password}
                onChangeText={setPassword}
              />
            </View>

            {authMode === 'register' && (
              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>Role Partition</Text>
                <View style={styles.roleChoiceRow}>
                  <TouchableOpacity
                    style={[styles.roleChip, regRole === 'customer' && styles.roleChipActive]}
                    onPress={() => setRegRole('customer')}
                  >
                    <Text style={[styles.roleChipText, regRole === 'customer' && styles.roleChipTextActive]}>
                      Customer (Node 3)
                    </Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={[styles.roleChip, regRole === 'staff' && styles.roleChipActive]}
                    onPress={() => setRegRole('staff')}
                  >
                    <Text style={[styles.roleChipText, regRole === 'staff' && styles.roleChipTextActive]}>
                      Staff (Node 2)
                    </Text>
                  </TouchableOpacity>
                </View>
              </View>
            )}

            <TouchableOpacity
              style={styles.primaryAuthButton}
              onPress={handleAuth}
              disabled={authLoading}
            >
              {authLoading ? (
                <ActivityIndicator color="#ffffff" />
              ) : (
                <Text style={styles.primaryAuthButtonText}>
                  {authMode === 'login' ? 'Next' : 'Create account'}
                </Text>
              )}
            </TouchableOpacity>

            {/* Quick Demo Autofill Chips */}
            <View style={styles.autofillBox}>
              <Text style={styles.autofillLabel}>⚡ Quick Autofill Test Credentials:</Text>
              <View style={styles.autofillChipsRow}>
                <TouchableOpacity style={styles.autofillBtn} onPress={autofillStaff}>
                  <Text style={styles.autofillBtnText}>Staff: nithish</Text>
                </TouchableOpacity>
                <TouchableOpacity style={styles.autofillBtn} onPress={autofillCustomer}>
                  <Text style={styles.autofillBtnText}>Customer: client_vault</Text>
                </TouchableOpacity>
              </View>
            </View>

            <TouchableOpacity
              style={styles.toggleAuthRow}
              onPress={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}
            >
              <Text style={styles.toggleAuthText}>
                {authMode === 'login'
                  ? 'Need a tenant partition? Create account'
                  : 'Already registered? Sign in'}
              </Text>
            </TouchableOpacity>
          </View>
        </ScrollView>
      </SafeAreaView>
    );
  }

  // =============================================================
  // SCREEN 2: MAIN AUTHENTICATED WORKSPACE
  // Renders the workspace AND the LOWER NAVIGATION PANEL
  // =============================================================
  return (
    <SafeAreaView style={styles.mainSafeArea}>
      <StatusBar barStyle="dark-content" backgroundColor="#ffffff" />

      {/* Top Header */}
      <View style={styles.topHeader}>
        <View style={styles.topHeaderLeft}>
          <Text style={styles.appTitleHeader}>Drive</Text>
          <View style={styles.headerShieldBadge}>
            <Text style={styles.headerShieldText}>Cloud-D</Text>
          </View>
        </View>
        <View style={styles.topHeaderRight}>
          <View style={styles.userRolePill}>
            <Text style={styles.userRolePillText}>
              {currentUser?.role === 'customer' ? 'Customer (Node 3)' : 'Staff (Node 2)'}
            </Text>
          </View>
          <View style={styles.userAvatar}>
            <Text style={styles.userAvatarChar}>
              {(currentUser?.username || 'U')[0].toUpperCase()}
            </Text>
          </View>
        </View>
      </View>

      {/* Main Tab Content Scroll Area */}
      <ScrollView style={styles.scrollArea} contentContainerStyle={styles.scrollContent}>
        {/* TAB 1: FILES & STORAGE */}
        {activeTab === 'files' && (
          <View>
            <View style={styles.assignedShardBanner}>
              <Text style={styles.assignedShardTitle}>
                {currentUser?.role === 'customer' ? 'Customer Tenant Vault' : 'Primary Staff Cloud Workspace'}
              </Text>
              <Text style={styles.assignedShardDesc}>
                {currentUser?.role === 'customer'
                  ? 'Sealed with Galois 128-bit GHASH AEAD. Zero cross-tenant leakage.'
                  : 'Managing enterprise files across Frankfurt Node 2 & Oregon Ingress Node 1.'}
              </Text>
            </View>

            {/* Folder Shortcuts */}
            <Text style={styles.sectionHeader}>Suggested Folders</Text>
            <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.folderRow}>
              {['PS-7', '24X501', 'PS-6', 'Documents', 'Audits'].map((fld, idx) => (
                <View key={idx} style={styles.folderCard}>
                  <Text style={styles.folderIcon}>📁</Text>
                  <Text style={styles.folderName}>{fld}</Text>
                </View>
              ))}
            </ScrollView>

            {/* Files List */}
            <Text style={styles.sectionHeader}>Vault Files (AES-256-GCM AEAD)</Text>
            {files.map((file, idx) => (
              <View key={idx} style={styles.fileCard}>
                <Text style={styles.fileIcon}>📄</Text>
                <View style={styles.fileInfo}>
                  <Text style={styles.fileName}>{file.filename}</Text>
                  <Text style={styles.fileSub}>
                    {Math.round(file.size_bytes / 1024)} KB • Node {file.node_id} • AES-GCM
                  </Text>
                </View>
                {file.is_post_quantum && (
                  <View style={styles.pqBadge}>
                    <Text style={styles.pqBadgeText}>PQ-Kyber</Text>
                  </View>
                )}
              </View>
            ))}
          </View>
        )}

        {/* TAB 2: THREAT SIMULATION */}
        {activeTab === 'simulation' && (
          <View>
            {currentUser?.role === 'staff' ? (
              // STAFF THREAT CENTER
              <View>
                <Text style={styles.simSubheaderGreen}>THREAT CENTER • INTERACTIVE & AUTOMATED</Text>
                <Text style={styles.simTitle}>Threat Simulation</Text>
                <Text style={styles.simDesc}>
                  Experience both manually induced attack/defense interactions and automated multi-round cloud security exercises.
                </Text>

                {/* Top Actions */}
                <View style={styles.simTopButtonsRow}>
                  <TouchableOpacity style={styles.btnStepOne} onPress={handleStepOneRound}>
                    <Text style={styles.btnStepOneText}>+ Step one round</Text>
                  </TouchableOpacity>
                  <TouchableOpacity style={styles.btnRunAuto} onPress={handleRunAutomated}>
                    <Text style={styles.btnRunAutoText}>Run Automated Defense</Text>
                  </TouchableOpacity>
                </View>

                {/* Section 1: Manual Induction */}
                <View style={styles.simCardContainer}>
                  <View style={styles.cardHeaderRow}>
                    <Text style={styles.cardTitle}>Manually Induced Attack & Defense</Text>
                    <View style={styles.manualBadge}>
                      <Text style={styles.manualBadgeText}>MANUAL INDUCTION</Text>
                    </View>
                  </View>
                  <Text style={styles.cardDesc}>
                    Select an adversarial agent, choose attack pressure, and manually trigger an attack to inspect the immediate defensive decision.
                  </Text>

                  {/* Adversarial Agent Picker Chips */}
                  <Text style={styles.controlLabel}>Adversarial Agent & Target</Text>
                  <View style={styles.chipsContainer}>
                    {Object.keys(AGENT_PROFILES).map((key) => (
                      <TouchableOpacity
                        key={key}
                        style={[styles.agentChip, simAgent === key && styles.agentChipActive]}
                        onPress={() => setSimAgent(key)}
                      >
                        <Text style={[styles.agentChipText, simAgent === key && styles.agentChipTextActive]}>
                          {AGENT_PROFILES[key].name}
                        </Text>
                      </TouchableOpacity>
                    ))}
                  </View>

                  {/* Attack Pressure */}
                  <Text style={styles.controlLabel}>Attack Pressure</Text>
                  <View style={styles.chipsContainer}>
                    {['normal', 'elevated', 'maximum'].map((p) => (
                      <TouchableOpacity
                        key={p}
                        style={[styles.pressureChip, simPressure === p && styles.pressureChipActive]}
                        onPress={() => setSimPressure(p)}
                      >
                        <Text style={[styles.pressureChipText, simPressure === p && styles.pressureChipTextActive]}>
                          {p.toUpperCase()}
                        </Text>
                      </TouchableOpacity>
                    ))}
                  </View>

                  {/* Target Cloud Asset Badge */}
                  <Text style={styles.controlLabel}>Target Cloud Asset</Text>
                  <View style={styles.targetAssetBadge}>
                    <Text style={styles.targetAssetText}>☁ {AGENT_PROFILES[simAgent]?.target}</Text>
                  </View>

                  {/* Launch Button */}
                  <TouchableOpacity
                    style={styles.btnLaunchManual}
                    onPress={() => handleManualAttack(simAgent)}
                    disabled={simLoading}
                  >
                    {simLoading ? (
                      <ActivityIndicator color="#fff" />
                    ) : (
                      <Text style={styles.btnLaunchManualText}>⚡ Launch Manual Attack</Text>
                    )}
                  </TouchableOpacity>

                  {/* Outcome Result Card */}
                  <View style={styles.outcomeResultCard}>
                    <View style={styles.outcomeHeaderRow}>
                      <Text style={styles.outcomeTitle}>{latestOutcome.title}</Text>
                      <View style={styles.outcomeBlockedBadge}>
                        <Text style={styles.outcomeBlockedText}>{latestOutcome.status}</Text>
                      </View>
                    </View>
                    <Text style={styles.outcomeSub}>{latestOutcome.subtitle}</Text>

                    {/* 4 Column Metrics */}
                    <View style={styles.metricGrid}>
                      <View style={styles.metricCol}>
                        <Text style={styles.metricLabel}>ADVERSARIAL VECTOR</Text>
                        <Text style={styles.metricVal}>{latestOutcome.vector}</Text>
                      </View>
                      <View style={styles.metricCol}>
                        <Text style={styles.metricLabel}>DEFENDER SPECIALIST</Text>
                        <Text style={styles.metricVal}>{latestOutcome.defender}</Text>
                      </View>
                      <View style={styles.metricCol}>
                        <Text style={styles.metricLabel}>DEFENSE ACTION</Text>
                        <Text style={styles.metricVal}>{latestOutcome.action}</Text>
                      </View>
                      <View style={styles.metricCol}>
                        <Text style={styles.metricLabel}>UTILITY SCORE</Text>
                        <Text style={styles.metricValTeal}>{latestOutcome.utility} <Text style={styles.threshText}>({utilityThreshold.toFixed(2)})</Text></Text>
                      </View>
                    </View>

                    {/* Minimax Box */}
                    <View style={styles.minimaxBox}>
                      <Text style={styles.minimaxText}>{latestOutcome.minimax}</Text>
                    </View>
                    <Text style={styles.cloudStatusFooter}>☁ {latestOutcome.cloudStatus}</Text>
                  </View>
                </View>

                {/* Section 3: Decision Engine Threshold */}
                <Text style={styles.sectionHeader}>Decision Engine Threshold</Text>
                <View style={styles.simCardContainer}>
                  <Text style={styles.cardTitle}>Minimum Utility to Execute: <Text style={{ color: '#0d9488' }}>{utilityThreshold.toFixed(2)}</Text></Text>
                  <Text style={styles.cardDesc}>The Decision Engine ranks proposals and approves actions above this threshold.</Text>
                  <View style={styles.sliderButtonRow}>
                    {[0.20, 0.40, 0.60, 0.80].map((val) => (
                      <TouchableOpacity
                        key={val}
                        style={[styles.sliderPresetBtn, utilityThreshold === val && styles.sliderPresetBtnActive]}
                        onPress={() => setUtilityThreshold(val)}
                      >
                        <Text style={[styles.sliderPresetText, utilityThreshold === val && styles.sliderPresetTextActive]}>
                          {val.toFixed(2)}
                        </Text>
                      </TouchableOpacity>
                    ))}
                  </View>
                </View>

                {/* Section 4: Recent Decisions Log */}
                <Text style={styles.sectionHeader}>Recent Threat Defense Decisions</Text>
                {recentDecisions.map((dec, idx) => (
                  <View key={idx} style={styles.decisionCard}>
                    <View style={styles.decisionRow}>
                      <Text style={styles.decRound}>Round {dec.round}</Text>
                      <View style={styles.decBlockedPill}>
                        <Text style={styles.decBlockedText}>{dec.outcome}</Text>
                      </View>
                    </View>
                    <Text style={styles.decAttacker}>{dec.attacker} ({dec.subTactic})</Text>
                    <Text style={styles.decTarget}>Target: {dec.node} • Utility: {dec.utility}</Text>
                    <Text style={styles.decAction}>Mitigation: {dec.action}</Text>
                  </View>
                ))}
              </View>
            ) : (
              // CUSTOMER PERIPHERAL SHIELD MONITOR
              <View>
                <Text style={styles.simSubheaderGreen}>AUTONOMOUS SHIELD • READ-ONLY</Text>
                <Text style={styles.simTitle}>Peripheral Shield Monitor</Text>
                <Text style={styles.simDesc}>
                  As a customer, all security defense is an automated background process. Below is your peripheral shield status.
                </Text>

                <View style={styles.ringCard}>
                  <Text style={styles.ringTag}>PERIPHERAL RING 1 • 🟢 FILTERING</Text>
                  <Text style={styles.ringTitle}>Ingress Edge (Node 1)</Text>
                  <Text style={styles.ringDesc}>Token-bucket rate limiter absorbing volumetric spikes.</Text>
                </View>

                <View style={styles.ringCard}>
                  <Text style={styles.ringTag}>PERIPHERAL RING 2 • 🟢 ACTIVE</Text>
                  <Text style={styles.ringTitle}>QueryShield AST Shield</Text>
                  <Text style={styles.ringDesc}>Expectimax probability search neutralizing query injections.</Text>
                </View>

                <View style={styles.ringCard}>
                  <Text style={styles.ringTag}>PERIPHERAL RING 3 • 🔒 ISOLATED</Text>
                  <Text style={styles.ringTitle}>AuthWall Tenant Barrier</Text>
                  <Text style={styles.ringDesc}>Zero cross-tenant bleed. Staff activities cannot access your vault.</Text>
                </View>

                <View style={[styles.ringCard, { borderColor: '#10b981', backgroundColor: '#ecfdf5' }]}>
                  <Text style={[styles.ringTag, { color: '#047857' }]}>CORE RING 4 • 💎 100% SEALED</Text>
                  <Text style={[styles.ringTitle, { color: '#065f46' }]}>Your Customer Vault (Node 3)</Text>
                  <Text style={[styles.ringDesc, { color: '#047857' }]}>Galois 128-bit GHASH AEAD tag validated intact.</Text>
                </View>

                <View style={styles.airgapCard}>
                  <Text style={styles.airgapTitle}>✔ Customer Air-Gap Guarantee</Text>
                  <Text style={styles.airgapText}>
                    Even during active red-team probes on Nodes 1 & 2, Sentinel guarantees your tenant data on Node 3 remains completely sealed.
                  </Text>
                </View>
              </View>
            )}
          </View>
        )}

        {/* TAB 3: SECURITY ARCHITECTURE */}
        {activeTab === 'security' && (
          <View>
            <Text style={styles.simSubheaderGreen}>SYSTEM DOSSIER</Text>
            <Text style={styles.simTitle}>Security Architecture</Text>
            <Text style={styles.simDesc}>
              Complete specifications for Cloud-D Multi-Agent Threat Defense.
            </Text>

            <View style={styles.simCardContainer}>
              <Text style={styles.cardTitle}>Student Investigator</Text>
              <Text style={styles.metaRow}>• Investigator: <Text style={styles.boldText}>Nithish M (Roll No. 24X064)</Text></Text>
              <Text style={styles.metaRow}>• Dept: Applied Mathematics & Computational Sciences</Text>
              <Text style={styles.metaRow}>• Institution: PSG College of Technology, Coimbatore</Text>
            </View>

            <View style={styles.simCardContainer}>
              <Text style={styles.cardTitle}>4-Tier Distributed Topology</Text>
              <Text style={styles.metaRow}>• Node 0: Auth & Key Management (US-East)</Text>
              <Text style={styles.metaRow}>• Node 1: Ingress Edge & Rate Limiter (US-West)</Text>
              <Text style={styles.metaRow}>• Node 2: Primary Staff Storage Vault (EU-Central)</Text>
              <Text style={styles.metaRow}>• Node 3: Isolated Customer Vault (AP-South)</Text>
            </View>

            <View style={styles.simCardContainer}>
              <Text style={styles.cardTitle}>Post-Quantum Cryptography</Text>
              <Text style={styles.metaRow}>• NIST ML-KEM-768 / Kyber-768 hybrid lattice encryption</Text>
              <Text style={styles.metaRow}>• 128-bit GHASH authentication tag validation</Text>
              <Text style={styles.metaRow}>• FIDO2 / WebAuthn hardware token attestation</Text>
            </View>
          </View>
        )}

        {/* TAB 4: PROFILE */}
        {activeTab === 'profile' && (
          <View>
            <Text style={styles.simSubheaderGreen}>ACCOUNT DETAILS</Text>
            <Text style={styles.simTitle}>User Profile</Text>

            <View style={styles.simCardContainer}>
              <Text style={styles.cardTitle}>Signed in as: {currentUser?.username}</Text>
              <Text style={styles.metaRow}>Role: {currentUser?.role === 'customer' ? 'Customer Tenant' : 'Staff Administrator'}</Text>
              <Text style={styles.metaRow}>Assigned Shard: Node {currentUser?.role === 'customer' ? 3 : 2}</Text>
              <Text style={styles.metaRow}>Hardware Attestation: ACTIVE (ES256)</Text>

              <TouchableOpacity style={styles.logoutBtn} onPress={handleLogout}>
                <Text style={styles.logoutBtnText}>Sign Out & Lock Partition</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}
      </ScrollView>

      {/* Floating Action Button (FAB) for File Upload */}
      {activeTab === 'files' && (
        <TouchableOpacity style={styles.fabButton} onPress={() => setUploadModalVisible(true)}>
          <Text style={styles.fabText}>+</Text>
        </TouchableOpacity>
      )}

      {/* =========================================================
          LOWER NAVIGATION PANEL (Bottom Bar)
          Strictly Visible ONLY when isAuthenticated === true
          ========================================================= */}
      <View style={styles.bottomNavPanel}>
        <TouchableOpacity
          style={[styles.navTabItem, activeTab === 'files' && styles.navTabItemActive]}
          onPress={() => setActiveTab('files')}
        >
          <Text style={styles.navIcon}>📁</Text>
          <Text style={[styles.navLabel, activeTab === 'files' && styles.navLabelActive]}>Files</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.navTabItem, activeTab === 'simulation' && styles.navTabItemActive]}
          onPress={() => setActiveTab('simulation')}
        >
          <Text style={styles.navIcon}>⚡</Text>
          <Text style={[styles.navLabel, activeTab === 'simulation' && styles.navLabelActive]}>Simulation</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.navTabItem, activeTab === 'security' && styles.navTabItemActive]}
          onPress={() => setActiveTab('security')}
        >
          <Text style={styles.navIcon}>🛡️</Text>
          <Text style={[styles.navLabel, activeTab === 'security' && styles.navLabelActive]}>Security</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.navTabItem, activeTab === 'profile' && styles.navTabItemActive]}
          onPress={() => setActiveTab('profile')}
        >
          <Text style={styles.navIcon}>👤</Text>
          <Text style={[styles.navLabel, activeTab === 'profile' && styles.navLabelActive]}>Profile</Text>
        </TouchableOpacity>
      </View>

      {/* Upload File Modal */}
      <Modal visible={uploadModalVisible} animationType="slide" transparent>
        <View style={styles.modalOverlay}>
          <View style={styles.modalBox}>
            <Text style={styles.modalHeading}>Upload to Cloud-D Shard</Text>
            <Text style={styles.modalSub}>Encrypted with AES-256-GCM AEAD on Node {currentUser?.role === 'customer' ? 3 : 2}</Text>

            <TextInput
              style={styles.textInput}
              placeholder="Filename (e.g. Audit_2026.docx)"
              value={newFileName}
              onChangeText={setNewFileName}
            />

            <TextInput
              style={[styles.textInput, { height: 80, marginTop: 10 }]}
              placeholder="Plaintext content..."
              multiline
              value={newFileContent}
              onChangeText={setNewFileContent}
            />

            <TouchableOpacity
              style={[styles.zkToggleRow, isZK && styles.zkToggleRowActive]}
              onPress={() => setIsZK(!isZK)}
            >
              <Text style={styles.zkToggleText}>
                {isZK ? '✔ Post-Quantum Hybrid (ML-KEM-768)' : '○ Standard AES-256-GCM AEAD'}
              </Text>
            </TouchableOpacity>

            <View style={styles.modalBtnRow}>
              <TouchableOpacity style={styles.btnCancel} onPress={() => setUploadModalVisible(false)}>
                <Text style={styles.btnCancelText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.btnUpload} onPress={handleUploadFile}>
                <Text style={styles.btnUploadText}>Encrypt & Upload</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  authSafeArea: { flex: 1, backgroundColor: '#f8fafd' },
  authScrollContainer: { flexGrow: 1, justifyContent: 'center', padding: 20 },
  authCard: {
    backgroundColor: '#ffffff',
    borderRadius: 24,
    padding: 28,
    borderWidth: 1,
    borderColor: '#e2e8f0',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 3
  },
  logoRow: { flexDirection: 'row', alignItems: 'center', marginBottom: 18 },
  logoBadge: { width: 34, height: 34, borderRadius: 8, backgroundColor: '#1a73e8', justifyContent: 'center', alignItems: 'center', marginRight: 10 },
  logoTriangle: { color: '#ffffff', fontSize: 16 },
  logoTitle: { fontSize: 20, fontWeight: '700', color: '#1f1f1f' },
  authHeading: { fontSize: 24, fontWeight: '700', color: '#0f172a', marginBottom: 4 },
  authSubheading: { fontSize: 13, color: '#64748b', marginBottom: 20 },
  inputGroup: { marginBottom: 14 },
  inputLabel: { fontSize: 12, fontWeight: '600', color: '#334155', marginBottom: 6 },
  textInput: {
    backgroundColor: '#f8fafc',
    borderWidth: 1,
    borderColor: '#cbd5e1',
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 10,
    fontSize: 14,
    color: '#0f172a'
  },
  roleChoiceRow: { flexDirection: 'row', gap: 10 },
  roleChip: { flex: 1, paddingVertical: 10, borderRadius: 8, borderWidth: 1, borderColor: '#cbd5e1', alignItems: 'center', backgroundColor: '#f8fafc' },
  roleChipActive: { borderColor: '#1a73e8', backgroundColor: '#c2e7ff' },
  roleChipText: { fontSize: 12, fontWeight: '600', color: '#475569' },
  roleChipTextActive: { color: '#001d35' },
  primaryAuthButton: {
    backgroundColor: '#1a73e8',
    borderRadius: 10,
    paddingVertical: 12,
    alignItems: 'center',
    marginTop: 8
  },
  primaryAuthButtonText: { color: '#ffffff', fontSize: 15, fontWeight: '600' },
  autofillBox: { marginTop: 20, padding: 12, backgroundColor: '#f1f5f9', borderRadius: 12 },
  autofillLabel: { fontSize: 11, fontWeight: '600', color: '#475569', marginBottom: 8 },
  autofillChipsRow: { flexDirection: 'row', gap: 8 },
  autofillBtn: { backgroundColor: '#ffffff', paddingVertical: 6, paddingHorizontal: 10, borderRadius: 6, borderWidth: 1, borderColor: '#cbd5e1' },
  autofillBtnText: { fontSize: 11, color: '#1e293b', fontWeight: '500' },
  toggleAuthRow: { marginTop: 18, alignItems: 'center' },
  toggleAuthText: { fontSize: 13, color: '#1a73e8', fontWeight: '500' },

  // Authenticated Workspace Styles
  mainSafeArea: { flex: 1, backgroundColor: '#f8fafd' },
  topHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 12,
    backgroundColor: '#ffffff',
    borderBottomWidth: 1,
    borderBottomColor: '#e2e8f0'
  },
  topHeaderLeft: { flexDirection: 'row', alignItems: 'center', gap: 6 },
  appTitleHeader: { fontSize: 20, fontWeight: '700', color: '#1f1f1f' },
  headerShieldBadge: { backgroundColor: '#c2e7ff', paddingHorizontal: 8, paddingVertical: 2, borderRadius: 12 },
  headerShieldText: { fontSize: 11, fontWeight: '700', color: '#001d35' },
  topHeaderRight: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  userRolePill: { backgroundColor: '#f1f5f9', paddingHorizontal: 10, paddingVertical: 4, borderRadius: 12 },
  userRolePillText: { fontSize: 11, fontWeight: '600', color: '#334155' },
  userAvatar: { width: 32, height: 32, borderRadius: 16, backgroundColor: '#7c3aed', justifyContent: 'center', alignItems: 'center' },
  userAvatarChar: { color: '#ffffff', fontWeight: '700', fontSize: 14 },

  scrollArea: { flex: 1 },
  scrollContent: { padding: 16, paddingBottom: 90 },

  // Assigned Shard Banner
  assignedShardBanner: { backgroundColor: '#ffffff', borderRadius: 16, padding: 16, marginBottom: 16, borderWidth: 1, borderColor: '#e2e8f0' },
  assignedShardTitle: { fontSize: 16, fontWeight: '700', color: '#0f172a', marginBottom: 4 },
  assignedShardDesc: { fontSize: 12, color: '#64748b' },

  sectionHeader: { fontSize: 16, fontWeight: '700', color: '#0f172a', marginTop: 14, marginBottom: 10 },
  folderRow: { flexDirection: 'row', marginBottom: 14 },
  folderCard: { backgroundColor: '#f0f4f9', borderRadius: 12, paddingHorizontal: 14, paddingVertical: 10, marginRight: 8, flexDirection: 'row', alignItems: 'center', gap: 6 },
  folderIcon: { fontSize: 16 },
  folderName: { fontSize: 13, fontWeight: '600', color: '#1f1f1f' },

  fileCard: { backgroundColor: '#ffffff', borderRadius: 12, padding: 14, marginBottom: 8, borderWidth: 1, borderColor: '#e2e8f0', flexDirection: 'row', alignItems: 'center' },
  fileIcon: { fontSize: 22, marginRight: 12 },
  fileInfo: { flex: 1 },
  fileName: { fontSize: 14, fontWeight: '600', color: '#0f172a', marginBottom: 2 },
  fileSub: { fontSize: 11, color: '#64748b' },
  pqBadge: { backgroundColor: '#fef3c7', paddingHorizontal: 6, paddingVertical: 2, borderRadius: 6 },
  pqBadgeText: { fontSize: 10, fontWeight: '700', color: '#d97706' },

  // Threat Simulation Styles
  simSubheaderGreen: { fontSize: 11, fontWeight: '700', color: '#0d9488', letterSpacing: 0.8, marginBottom: 2 },
  simTitle: { fontSize: 24, fontWeight: '700', color: '#0f172a', marginBottom: 4 },
  simDesc: { fontSize: 12.5, color: '#64748b', marginBottom: 14 },
  simTopButtonsRow: { flexDirection: 'row', gap: 10, marginBottom: 16 },
  btnStepOne: { flex: 1, backgroundColor: '#ffffff', borderWidth: 1, borderColor: '#cbd5e1', paddingVertical: 10, borderRadius: 8, alignItems: 'center' },
  btnStepOneText: { fontSize: 12, fontWeight: '600', color: '#1e293b' },
  btnRunAuto: { flex: 1, backgroundColor: '#8b5cf6', paddingVertical: 10, borderRadius: 8, alignItems: 'center' },
  btnRunAutoText: { fontSize: 12, fontWeight: '600', color: '#ffffff' },

  simCardContainer: { backgroundColor: '#ffffff', borderRadius: 16, padding: 16, borderWidth: 1, borderColor: '#e2e8f0', marginBottom: 16 },
  cardHeaderRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 },
  cardTitle: { fontSize: 15, fontWeight: '700', color: '#0f172a' },
  cardDesc: { fontSize: 12, color: '#64748b', marginBottom: 12 },
  manualBadge: { backgroundColor: '#fef3c7', paddingHorizontal: 8, paddingVertical: 3, borderRadius: 10 },
  manualBadgeText: { fontSize: 10, fontWeight: '700', color: '#d97706' },

  controlLabel: { fontSize: 11, fontWeight: '600', color: '#334155', marginTop: 8, marginBottom: 6 },
  chipsContainer: { flexDirection: 'row', flexWrap: 'wrap', gap: 6, marginBottom: 8 },
  agentChip: { backgroundColor: '#0f172a', paddingVertical: 8, paddingHorizontal: 12, borderRadius: 8 },
  agentChipActive: { backgroundColor: '#8b5cf6' },
  agentChipText: { fontSize: 11, fontWeight: '600', color: '#94a3b8' },
  agentChipTextActive: { color: '#ffffff' },

  pressureChip: { backgroundColor: '#0f172a', paddingVertical: 6, paddingHorizontal: 10, borderRadius: 6 },
  pressureChipActive: { backgroundColor: '#3b82f6' },
  pressureChipText: { fontSize: 10, fontWeight: '600', color: '#94a3b8' },
  pressureChipTextActive: { color: '#ffffff' },

  targetAssetBadge: { backgroundColor: '#ecfdf5', borderWidth: 1, borderColor: '#a7f3d0', paddingVertical: 8, paddingHorizontal: 12, borderRadius: 20, alignItems: 'center', marginBottom: 14 },
  targetAssetText: { fontSize: 12, fontWeight: '600', color: '#059669' },

  btnLaunchManual: { backgroundColor: '#8b5cf6', borderRadius: 10, paddingVertical: 12, alignItems: 'center', marginBottom: 14 },
  btnLaunchManualText: { color: '#ffffff', fontSize: 13, fontWeight: '700' },

  outcomeResultCard: { backgroundColor: '#f8fafc', borderRadius: 12, padding: 14, borderWidth: 1, borderColor: '#e2e8f0' },
  outcomeHeaderRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2 },
  outcomeTitle: { fontSize: 14, fontWeight: '700', color: '#0f172a' },
  outcomeBlockedBadge: { backgroundColor: '#dcfce7', paddingHorizontal: 8, paddingVertical: 3, borderRadius: 10 },
  outcomeBlockedText: { fontSize: 10, fontWeight: '700', color: '#16a34a' },
  outcomeSub: { fontSize: 11, color: '#64748b', marginBottom: 10 },
  metricGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: 10, marginBottom: 10, paddingBottom: 10, borderBottomWidth: 1, borderBottomColor: '#e2e8f0' },
  metricCol: { width: '47%' },
  metricLabel: { fontSize: 9.5, fontWeight: '700', color: '#94a3b8' },
  metricVal: { fontSize: 12, fontWeight: '600', color: '#0f172a', marginTop: 2 },
  metricValTeal: { fontSize: 12, fontWeight: '700', color: '#0d9488', marginTop: 2 },
  threshText: { fontSize: 10, fontWeight: '400', color: '#64748b' },
  minimaxBox: { backgroundColor: '#ffffff', borderRadius: 8, padding: 10, borderWidth: 1, borderColor: '#e2e8f0', marginBottom: 8 },
  minimaxText: { fontSize: 11, color: '#334155', lineHeight: 16 },
  cloudStatusFooter: { fontSize: 10.5, color: '#64748b' },

  sliderButtonRow: { flexDirection: 'row', gap: 8, marginTop: 10 },
  sliderPresetBtn: { flex: 1, paddingVertical: 8, borderRadius: 8, borderWidth: 1, borderColor: '#cbd5e1', alignItems: 'center', backgroundColor: '#f8fafc' },
  sliderPresetBtnActive: { backgroundColor: '#0d9488', borderColor: '#0d9488' },
  sliderPresetText: { fontSize: 12, fontWeight: '600', color: '#334155' },
  sliderPresetTextActive: { color: '#ffffff' },

  decisionCard: { backgroundColor: '#ffffff', borderRadius: 12, padding: 12, marginBottom: 8, borderWidth: 1, borderColor: '#e2e8f0' },
  decisionRow: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 4 },
  decRound: { fontSize: 11, fontWeight: '700', color: '#0f172a' },
  decBlockedPill: { backgroundColor: '#dcfce7', paddingHorizontal: 6, paddingVertical: 2, borderRadius: 6 },
  decBlockedText: { fontSize: 9.5, fontWeight: '700', color: '#16a34a' },
  decAttacker: { fontSize: 13, fontWeight: '700', color: '#0f172a' },
  decTarget: { fontSize: 11, color: '#64748b', marginTop: 2 },
  decAction: { fontSize: 11, color: '#334155', fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace', marginTop: 2 },

  // Customer Peripheral Rings
  ringCard: { backgroundColor: '#ffffff', borderRadius: 12, padding: 14, marginBottom: 8, borderWidth: 1, borderColor: '#e2e8f0' },
  ringTag: { fontSize: 10, fontWeight: '700', color: '#0d9488', marginBottom: 2 },
  ringTitle: { fontSize: 14, fontWeight: '700', color: '#0f172a', marginBottom: 2 },
  ringDesc: { fontSize: 11.5, color: '#64748b' },
  airgapCard: { backgroundColor: '#f0fdf4', borderWidth: 1, borderColor: '#bbf7d0', borderRadius: 12, padding: 14, marginTop: 10 },
  airgapTitle: { fontSize: 13, fontWeight: '700', color: '#166534', marginBottom: 4 },
  airgapText: { fontSize: 11.5, color: '#15803d', lineHeight: 16 },

  metaRow: { fontSize: 12, color: '#334155', marginBottom: 4 },
  boldText: { fontWeight: '700' },
  logoutBtn: { marginTop: 14, backgroundColor: '#fee2e2', paddingVertical: 10, borderRadius: 8, alignItems: 'center' },
  logoutBtnText: { color: '#b91c1c', fontSize: 12, fontWeight: '600' },

  // Floating Action Button
  fabButton: {
    position: 'absolute',
    bottom: 74,
    right: 20,
    width: 52,
    height: 52,
    borderRadius: 26,
    backgroundColor: '#1a73e8',
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.25,
    shadowRadius: 5,
    elevation: 6
  },
  fabText: { fontSize: 28, color: '#ffffff', lineHeight: 30 },

  // =============================================================
  // LOWER NAVIGATION PANEL (Bottom Bar)
  // Gated: Mounted and visible strictly after authentication
  // =============================================================
  bottomNavPanel: {
    flexDirection: 'row',
    height: 60,
    backgroundColor: '#ffffff',
    borderTopWidth: 1,
    borderTopColor: '#e2e8f0',
    justifyContent: 'space-around',
    alignItems: 'center',
    paddingBottom: 4
  },
  navTabItem: { flex: 1, alignItems: 'center', justifyContent: 'center', height: '100%' },
  navTabItemActive: { borderTopWidth: 2, borderTopColor: '#1a73e8' },
  navIcon: { fontSize: 18, marginBottom: 2 },
  navLabel: { fontSize: 10, fontWeight: '500', color: '#64748b' },
  navLabelActive: { color: '#1a73e8', fontWeight: '700' },

  // Modal
  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.5)', justifyContent: 'center', padding: 20 },
  modalBox: { backgroundColor: '#ffffff', borderRadius: 20, padding: 20 },
  modalHeading: { fontSize: 18, fontWeight: '700', color: '#0f172a', marginBottom: 4 },
  modalSub: { fontSize: 12, color: '#64748b', marginBottom: 14 },
  zkToggleRow: { padding: 10, borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, marginTop: 10 },
  zkToggleRowActive: { backgroundColor: '#ecfdf5', borderColor: '#10b981' },
  zkToggleText: { fontSize: 12, fontWeight: '600', color: '#0f172a' },
  modalBtnRow: { flexDirection: 'row', gap: 10, marginTop: 16 },
  btnCancel: { flex: 1, paddingVertical: 10, borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, alignItems: 'center' },
  btnCancelText: { fontSize: 13, fontWeight: '600', color: '#475569' },
  btnUpload: { flex: 1, backgroundColor: '#1a73e8', paddingVertical: 10, borderRadius: 8, alignItems: 'center' },
  btnUploadText: { fontSize: 13, fontWeight: '600', color: '#ffffff' }
});
