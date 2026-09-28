require('dotenv').config();
const express = require('express');

const APP_PORT = process.env.PORT || 3000;
const LAYA_PORT = 8000;
const API_KEY = process.env.TYPESAFE_API_KEY || '';
const JEV_URL = 'https://api.typesafe.ai/v1/systemone';
const LAYA_URL = 'http://localhost:8000/v1/systemone';

const users = new Map(); // username -> { password, hint }
const apiKeys = new Map(); // apiKey -> { username, createdAt }
const otpStore = new Map(); // username -> { code, expiresAt }
const auditLogs = []; // { time, ip, username, attempted, status, mechanism, telemetry }
const ipBlocklist = new Map(); // ip -> { blockedAt, expiresAt, reason, confidence, engine }
const userFailures = new Map(); // username -> count
const ipFailures = new Map(); // ip -> count
const BRUTE_FORCE_LIMIT = 5;
const mask = (s) => String(s ?? '').slice(0, 24);
const now = () => new Date().toLocaleTimeString();
const pushLog = (entry) => {
  const ts = Date.now();
  auditLogs.unshift({
    time: now(),
    timestamp: ts,
    isoTime: new Date(ts).toISOString(),
    ...entry,
  });
};

function heuristic(state) {
  const samples = (state.samples || []).join(' ').toLowerCase();
  const hasSqli = /('|--|or 1=1|drop table|union select|sleep\(|benchmark\()/i.test(samples);
  const hasXss = /(<script|onerror|javascript:|alert\(|<svg)/i.test(samples);
  const isApiKeyScan = /nv_sec_|sk_live_|api_key|token|bearer|fuzz_/i.test(samples);
  const isOtpExhaustion = (state.auth_mechanisms && state.auth_mechanisms.includes('otp')) || (state.samples || []).some((s) => /otp:|\b\d{6}\b/i.test(s));
  const isPasswordSpray = (state.unique_users_count || 1) >= 4;
  const isCredentialStuffing = (state.samples || []).some((s) => s.includes(':') || /summer\d|winter\d|p@ssw|dragon|shadow/i.test(s));
  const isBot = state.telemetry_summary?.is_synthetic_bot === true;
  const n = state.failed_attempts || 0;

  if (hasSqli) return { is_attack: 0.98, attack_type: 'sqli', threat_category: 'sqli_attempt', typeConf: 0.94, severity: 2.9, sevConf: 0.91 };
  if (hasXss) return { is_attack: 0.96, attack_type: 'xss', threat_category: 'sqli_attempt', typeConf: 0.90, severity: 2.6, sevConf: 0.88 };
  if (isApiKeyScan) return { is_attack: 0.95, attack_type: 'api_key_enumeration', threat_category: 'credential_stuffing', typeConf: 0.89, severity: 2.4, sevConf: 0.86 };
  if (isOtpExhaustion) return { is_attack: 0.94, attack_type: 'mfa_exhaustion', threat_category: 'brute_force', typeConf: 0.88, severity: 2.5, sevConf: 0.85 };
  if (isPasswordSpray) return { is_attack: 0.96, attack_type: 'password_spray', threat_category: 'credential_stuffing', typeConf: 0.91, severity: 2.4, sevConf: 0.87 };
  if (n >= 5 || (n >= 4 && isBot)) return { is_attack: 0.968, attack_type: 'brute_force', threat_category: 'brute_force', typeConf: 0.88, severity: 2.5, sevConf: 0.84 };
  return { is_attack: 0.16, attack_type: 'benign_retry', threat_category: 'benign_login', typeConf: 0.84, severity: 0.4, sevConf: 0.82 };
}

function buildState() {
  const win = auditLogs.slice(0, 20);
  const samples = [...new Set(win.map((l) => l.attempted))].slice(0, 8);
  const uniqueUsers = [...new Set(win.map((l) => l.username))];
  const uniqueIPs = [...new Set(win.map((l) => l.ip))];
  const mechanisms = [...new Set(win.map((l) => l.mechanism || 'password'))];

  // Client telemetry telemetry aggregation for bot classification
  const telemetries = win.map((l) => l.telemetry).filter(Boolean);
  let isSyntheticBot = false;
  let avgMouseDist = 0;
  let avgFormDuration = 0;
  if (telemetries.length > 0) {
    const totalMouse = telemetries.reduce((acc, t) => acc + (t.mouseDistanceMoved || 0), 0);
    const totalDuration = telemetries.reduce((acc, t) => acc + (t.totalFormTimeMs || 0), 0);
    avgMouseDist = Math.round(totalMouse / telemetries.length);
    avgFormDuration = Math.round(totalDuration / telemetries.length);
    if (avgMouseDist === 0 && avgFormDuration < 500) {
      isSyntheticBot = true;
    }
  }

  return {
    failed_attempts: win.length,
    window_seconds: 60,
    unique_users_count: uniqueUsers.length,
    unique_ips_count: uniqueIPs.length,
    auth_mechanisms: mechanisms,
    ip: win[0]?.ip || 'none',
    target_user: uniqueUsers.length > 2 ? `${uniqueUsers.length} distinct users (Spray)` : (win[0]?.username || 'none'),
    samples: samples.length ? samples : ['(no attempts yet)'],
    telemetry_summary: {
      is_synthetic_bot: isSyntheticBot,
      samples_analyzed: telemetries.length,
      avg_mouse_distance_px: avgMouseDist,
      avg_form_duration_ms: avgFormDuration,
    },
  };
}

// Multi-Question Schema: support both is_threat/threat_category and is_attack/attack_type
function buildPayload(state) {
  return {
    model: 'jev-latest',
    state,
    questions: {
      is_threat: {
        type: 'noul',
        instructions: 'Is this request anomalous or adversarial? Does `samples` with `failed_attempts` indicate attack?',
        criteria: { true: 'Coordinated guesses, spray, probe, or injection', false: 'Normal typo or benign single retry' },
      },
      is_attack: {
        type: 'noul',
        instructions: 'Does `samples` with `failed_attempts`, `unique_users_count` indicate brute-force, password spray, credential-stuffing, token scan, or injection?',
        criteria: { true: 'Coordinated guesses, spray, probe, or injection', false: 'Normal typo or benign single retry' },
      },
      threat_category: {
        type: 'choice',
        instructions: 'Which category best describes the threat in `samples` and `state`?',
        options: ['benign_login', 'brute_force', 'sqli_attempt', 'credential_stuffing'],
        criteria: {
          benign_login: '1-2 typos of legitimate credentials',
          brute_force: 'Many rapid guesses targeting a single user',
          sqli_attempt: 'SQL metacharacters, OR 1=1, quotes, comments, injection',
          credential_stuffing: 'Testing leaked combinations of username and password across services',
          password_spray: 'Single password tested across many distinct usernames',
          api_key_enumeration: 'Automated fuzzing or scanning of API keys, tokens, or bearer headers',
          mfa_exhaustion: 'Repeated cycling or rapid requests of 6-digit OTP codes',
        },
      },
      attack_type: {
        type: 'choice',
        instructions: 'Which best describes the attack pattern in `samples` and `state`?',
        criteria: {
          benign_retry: '1-2 typos of legitimate credentials',
          brute_force: 'Many rapid guesses targeting a single user',
          password_spray: 'Single password tested across many distinct usernames',
          credential_stuffing: 'Leaked combo-list style username:password pairs',
          sqli: 'SQL metacharacters, OR 1=1, quotes, comments, injection',
          xss: 'Script tags, event handlers, external payloads',
          api_key_enumeration: 'High-frequency cycling of API tokens or secret keys',
          mfa_exhaustion: 'Repeated cycling or rapid requests of 6-digit OTP codes',
        },
      },
      severity: {
        type: 'score',
        instructions: 'Rate exploit risk of `samples` given `failed_attempts` and attack type',
        criteria: [
          'Harmless typo or single retry, no system risk',
          'Suspicious low-volume pattern, reconnaissance',
          'Coordinated attack, password spray, or brute force flood',
          'High exploit risk: SQL injection, token theft, active breach',
        ],
      },
    },
  };
}

function toVerdict(engine, state, answers, latency_ms) {
  const is_attack = (answers.is_attack?.noul !== undefined ? answers.is_attack.noul : answers.is_threat?.noul) ?? 0;
  const attack_type = answers.attack_type?.choice || answers.threat_category?.choice || 'benign_retry';
  const threat_category = answers.threat_category?.choice || (attack_type === 'sqli' ? 'sqli_attempt' : attack_type);
  const typeConf = answers.attack_type?.confidence || answers.threat_category?.confidence || 0.85;
  const severity = answers.severity?.score ?? 1.0;
  const confidence = Math.round(Math.max(is_attack, typeConf) * 1000) / 10;
  const label = is_attack > 0.8 ? attack_type : 'benign_retry';
  const threatCat = is_attack > 0.8 ? threat_category : 'benign_login';
  return {
    engine, description: `${label} (severity ${severity.toFixed(1)}/3) via ${engine}`,
    attack_type: label,
    threat_category: threatCat,
    is_attack,
    is_threat: is_attack,
    severity,
    confidence,
    latency_ms,
  };
}
function fallbackVerdict(engine, state, latency_ms = 1) {
  const h = heuristic(state);
  return {
    engine, description: `${h.attack_type} (severity ${h.severity.toFixed(1)}/3) via ${engine}-fallback`,
    attack_type: h.attack_type,
    threat_category: h.threat_category,
    is_attack: h.is_attack,
    is_threat: h.is_attack,
    severity: h.severity,
    confidence: Math.round(Math.max(h.is_attack, h.typeConf) * 1000) / 10,
    latency_ms,
  };
}

async function callJev(payload) {
  const t0 = Date.now();
  if (!API_KEY) return { ok: false, reason: 'no-key' };
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 8000);
    const res = await fetch(JEV_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload), signal: ctl.signal,
    });
    clearTimeout(t);
    if (!res.ok) return { ok: false, reason: `http-${res.status}` };
    const data = await res.json();
    return { ok: true, data, latency_ms: Date.now() - t0 };
  } catch (e) {
    return { ok: false, reason: String(e.message || e).slice(0, 80) };
  }
}

async function evalEngine(engine, state, payload) {
  if (engine === 'jev') {
    const r = await callJev(payload);
    if (r.ok) return toVerdict('jev', state, r.data.answers, r.latency_ms);
    return { ...fallbackVerdict('jev', state), note: r.reason };
  }
  // laya: same schema via local stub (8000) if up, else instant heuristic
  const t0 = Date.now();
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 2500);
    const res = await fetch(LAYA_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload), signal: ctl.signal,
    });
    clearTimeout(t);
    if (res.ok) {
      const data = await res.json();
      return toVerdict('laya', state, data.answers, Date.now() - t0);
    }
  } catch { /* fall through to heuristic */ }
  await new Promise((r) => setTimeout(r, 25)); // simulate ~35ms forward pass
  return { ...fallbackVerdict('laya', state, Date.now() - t0) };
}

// ---- Laya stub (same POST /v1/systemone shape) on :8000 ----
const stub = express();
stub.use(express.json());
stub.post('/v1/systemone', (req, res) => {
  const st = req.body?.state || {};
  const samples = Array.isArray(st.samples) ? st.samples : [JSON.stringify(st).slice(0, 200)];
  const n = st.failed_attempts ?? samples.length;
  const h = heuristic({
    failed_attempts: n,
    samples,
    unique_users_count: st.unique_users_count,
    auth_mechanisms: st.auth_mechanisms,
    telemetry_summary: st.telemetry_summary,
  });
  const threatCat = h.threat_category || (h.attack_type === 'sqli' ? 'sqli_attempt' : (h.attack_type === 'benign_retry' ? 'benign_login' : h.attack_type));
  res.json({
    model: 'laya-typed-decisions',
    answers: {
      is_threat: { type: 'noul', noul: h.is_attack },
      is_attack: { type: 'noul', noul: h.is_attack },
      threat_category: { type: 'choice', choice: threatCat, probabilities: { [threatCat]: h.typeConf }, confidence: h.typeConf },
      attack_type: { type: 'choice', choice: h.attack_type, probabilities: { [h.attack_type]: h.typeConf }, confidence: h.typeConf },
      severity: { type: 'score', score: h.severity, legend: { 0: 'Harmless', 1: 'Suspicious', 2: 'Attack', 3: 'Exploit' }, probabilities: { [Math.round(h.severity)]: h.sevConf }, confidence: h.sevConf },
    },
  });
});
stub.get('/health', (req, res) => res.json({ ok: true, stub: 'laya' }));
stub.listen(LAYA_PORT, () => console.log(`Laya stub on http://localhost:${LAYA_PORT}`));

// ---- Main app on :3000 ----
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// SOAR Active Defense Enforcement Middleware
function soarGuard(req, res, next) {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  if (ipBlocklist.has(clientIp)) {
    const info = ipBlocklist.get(clientIp);
    if (Date.now() < info.expiresAt) {
      const remainingSec = Math.ceil((info.expiresAt - Date.now()) / 1000);
      return res.status(403).json({
        error: 'Forbidden: IP Blacklisted by SOAR Active Defense',
        ip: clientIp,
        reason: info.reason,
        confidence: info.confidence,
        expiresInSeconds: remainingSec,
        status: 'blocked',
      });
    } else {
      ipBlocklist.delete(clientIp);
    }
  }
  next();
}

// 1. Password-based Auth APIs
function handleSignup(req, res) {
  const { username, password, hint } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  users.set(username, { password, hint: hint || 'No hint set' });
  res.json({ success: true, message: 'User registered' });
}
app.post('/api/auth/password/signup', soarGuard, handleSignup);
app.post('/api/signup', soarGuard, handleSignup);

function handleLogin(req, res) {
  const { username, password, telemetry } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const user = users.get(username);
  if (user && user.password === password) {
    if (username) userFailures.delete(username);
    ipFailures.delete(ip);
    pushLog({
      ip,
      username: username || 'unknown',
      attempted: mask(password),
      status: '200',
      mechanism: 'password',
      role: 'normal_user',
      classification: 'Normal User (Legitimate)',
      is_attack: false,
      confidence: 0,
      telemetry: telemetry || null,
    });
    return res.json({
      success: true,
      role: 'normal_user',
      message: 'Authenticated as Normal User',
      redirect: `/user-dashboard?user=${encodeURIComponent(username)}`,
    });
  }

  const currentFailures = (userFailures.get(username) || 0) + 1;
  if (username) userFailures.set(username, currentFailures);
  const currentIpFailures = (ipFailures.get(ip) || 0) + 1;
  ipFailures.set(ip, currentIpFailures);

  const isFlagged = currentFailures >= BRUTE_FORCE_LIMIT;

  if (isFlagged) {
    pushLog({
      ip,
      username: username || 'unknown',
      attempted: mask(password),
      status: '401 (FLAGGED)',
      mechanism: 'password',
      classification: `Brute Force Attack (${currentFailures} failed attempts)`,
      flagged: true,
      is_attack: true,
      confidence: 0.98,
      telemetry: telemetry || null,
    });
    return res.status(401).json({
      success: false,
      flagged: true,
      error: `Brute Force Attack Detected: Exceeded limit of ${BRUTE_FORCE_LIMIT} attempts. Account flagged.`,
      failures: currentFailures,
      limit: BRUTE_FORCE_LIMIT,
      hint: user ? user.hint : 'User not found',
    });
  }

  pushLog({
    ip,
    username: username || 'unknown',
    attempted: mask(password),
    status: '401',
    mechanism: 'password',
    classification: `Normal User Retry (${currentFailures}/${BRUTE_FORCE_LIMIT})`,
    flagged: false,
    is_attack: false,
    confidence: 0.16,
    telemetry: telemetry || null,
  });
  res.status(401).json({
    success: false,
    flagged: false,
    error: `Invalid credentials (attempt ${currentFailures} of ${BRUTE_FORCE_LIMIT})`,
    failures: currentFailures,
    limit: BRUTE_FORCE_LIMIT,
    hint: user ? user.hint : 'User not found',
  });
}
app.post('/api/auth/password/login', soarGuard, handleLogin);
app.post('/api/login', soarGuard, handleLogin);

// 2. Machine API Key Auth APIs
app.post('/api/auth/apikey/generate', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });
  const key = `nv_sec_${Buffer.from(Math.random().toString()).toString('hex').slice(0, 24)}`;
  apiKeys.set(key, { username, createdAt: new Date().toISOString() });
  res.json({ success: true, username, apiKey: key });
});
app.post('/api/auth/apikey/verify', soarGuard, (req, res) => {
  const key = req.headers['x-api-key'] || req.body?.apiKey;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  if (key && apiKeys.has(key)) {
    const info = apiKeys.get(key);
    return res.json({ success: true, authenticated: true, username: info.username, role: 'service_account' });
  }
  pushLog({ ip, username: 'service_bot', attempted: mask(key || 'no_key'), status: '401', mechanism: 'api_key' });
  res.status(401).json({ success: false, error: 'Invalid or revoked API key' });
});

// 3. MFA / OTP Step-up Auth APIs
app.post('/api/auth/mfa/send-otp', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  otpStore.set(username, { code, expiresAt: Date.now() + 300000 });
  res.json({ success: true, message: 'OTP dispatched', codePreview: code });
});
app.post('/api/auth/mfa/verify-otp', soarGuard, (req, res) => {
  const { username, code } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const record = otpStore.get(username);
  if (record && record.code === String(code).trim() && Date.now() < record.expiresAt) {
    otpStore.delete(username);
    return res.json({ success: true, message: 'MFA verified', session: `mfa_token_${Date.now()}` });
  }
  pushLog({ ip, username: username || 'unknown', attempted: `OTP:${mask(code)}`, status: '401', mechanism: 'otp' });
  res.status(401).json({ success: false, error: 'Invalid or expired OTP' });
});

app.get('/api/logs', (req, res) => {
  res.json(auditLogs.slice(0, Number(req.query.limit) || 200));
});

app.post('/api/clear-buffer', (req, res) => {
  auditLogs.length = 0;
  userFailures.clear();
  ipFailures.clear();
  res.json({ success: true, cleared: true });
});

// SOAR Dynamic Blocklist Management Endpoints
app.get('/api/soar/status', (req, res) => {
  const activeBlocks = Array.from(ipBlocklist.entries()).map(([ip, val]) => ({
    ip,
    ...val,
    remainingSec: Math.max(0, Math.ceil((val.expiresAt - Date.now()) / 1000)),
  }));
  res.json({ count: activeBlocks.length, activeBlocks });
});

app.post('/api/soar/block', (req, res) => {
  const { ip, reason, ttlMs } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'Missing IP' });
  const ttl = ttlMs || 15 * 60 * 1000;
  ipBlocklist.set(ip, {
    blockedAt: Date.now(),
    expiresAt: Date.now() + ttl,
    reason: reason || 'manual_containment',
    confidence: 99.0,
    engine: 'soar_operator',
  });
  res.json({ success: true, ip, expiresAt: Date.now() + ttl, ttlMs: ttl });
});

app.post('/api/soar/unblock', (req, res) => {
  const { ip } = req.body || {};
  if (ip) {
    ipBlocklist.delete(ip);
    ipFailures.delete(ip);
  } else {
    ipBlocklist.clear();
    ipFailures.clear();
  }
  userFailures.clear();
  res.json({ success: true, cleared: ip || 'all' });
});

app.post('/api/soar/clear', (req, res) => {
  ipBlocklist.clear();
  res.json({ success: true, cleared: 'all' });
});

// 4. Advanced Threat Simulation Endpoints for Comparison

// A. Classic Brute Force (High frequency on 1 user)
const BURST = ['admin123', 'password', '12345678', 'qwerty', 'letmein123', 'bruno', "' OR '1'='1", '<script>alert(1)</script>'];
app.post('/api/simulate-single', (req, res) => {
  pushLog({ ip: '127.0.0.1', username: 'Utkarsh', attempted: 'Bruno1', status: '401', mechanism: 'password' });
  res.json({ added: 1, attack_type: 'benign_retry' });
});
app.post('/api/simulate-burst', (req, res) => {
  const n = req.body?.n === 0 ? 0 : Math.min(Number(req.body?.n) || 200, 500);
  if (n === 0) {
    auditLogs.length = 0;
    return res.json({ added: 0, attack_type: 'cleared' });
  }
  const target = req.body?.target || 'Utkarsh';
  for (let i = 0; i < n; i++) {
    pushLog({ ip: '127.0.0.1', username: target, attempted: mask(BURST[i % BURST.length]), status: '401', mechanism: 'password' });
  }
  res.json({ added: n, attack_type: 'brute_force' });
});

// B. Password Spraying (1 generic password tested across corporate accounts)
const SPRAY_USERS = ['admin', 'sarah.connor', 'john.doe', 'finance_lead', 'devops_eng', 'cfo', 'alex.mercer', 'db_admin', 'sec_analyst', 'ceo'];
app.post('/api/simulate/spray', (req, res) => {
  const pass = req.body?.password || 'Autumn#2026!';
  const count = Number(req.body?.count) || SPRAY_USERS.length;
  for (let i = 0; i < count; i++) {
    const u = SPRAY_USERS[i % SPRAY_USERS.length];
    pushLog({ ip: '192.168.1.150', username: u, attempted: mask(pass), status: '401', mechanism: 'password' });
  }
  res.json({ added: count, attack_type: 'password_spray' });
});

// C. Credential Stuffing (Leaked breach combos)
const BREACH_COMBOS = [
  { u: 'alice@external.com', p: 'P@ssw0rd123' },
  { u: 'bob@partner.org', p: 'Summer2024!' },
  { u: 'claire@vendor.io', p: 'Welcome#1' },
  { u: 'david@agency.net', p: 'Dragon2025$' },
  { u: 'emma@client.com', p: 'Shadow#99' },
  { u: 'frank@supplier.co', p: 'Arsenal#123' },
];
app.post('/api/simulate/stuffing', (req, res) => {
  const count = Number(req.body?.count) || BREACH_COMBOS.length;
  for (let i = 0; i < count; i++) {
    const c = BREACH_COMBOS[i % BREACH_COMBOS.length];
    pushLog({ ip: '185.220.101.5', username: c.u, attempted: mask(c.p), status: '401', mechanism: 'password' });
  }
  res.json({ added: count, attack_type: 'credential_stuffing' });
});

// D. SQL Injection Auth Bypass Probes
const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "admin' --",
  "' UNION SELECT 1, 'admin', 'hash'--",
  "' OR ''='",
  "'; EXEC xp_cmdshell('whoami');--",
  "' OR 1=1 LIMIT 1--",
];
app.post('/api/simulate/sqli', (req, res) => {
  const target = req.body?.target || 'admin';
  const count = Number(req.body?.count) || SQLI_PAYLOADS.length;
  for (let i = 0; i < count; i++) {
    const p = SQLI_PAYLOADS[i % SQLI_PAYLOADS.length];
    pushLog({ ip: '45.154.255.88', username: target, attempted: mask(p), status: '401', mechanism: 'password' });
  }
  res.json({ added: count, attack_type: 'sqli' });
});

// E. Machine API Key Scanning Fuzzer
const FAKE_KEYS = [
  'nv_sec_fuzz_001_deadbeef',
  'nv_sec_fuzz_002_cafebabe',
  'sk_live_test_fuzzer_003',
  'api_key_scanner_probe_4',
  'nv_sec_leak_candidate_5',
];
app.post('/api/simulate/apikey-scan', (req, res) => {
  const count = Number(req.body?.count) || FAKE_KEYS.length;
  for (let i = 0; i < count; i++) {
    const k = FAKE_KEYS[i % FAKE_KEYS.length] + `_${i}`;
    pushLog({ ip: '198.51.100.22', username: 'service_bot', attempted: mask(k), status: '401', mechanism: 'api_key' });
  }
  res.json({ added: count, attack_type: 'api_key_enumeration' });
});

// F. MFA OTP PIN Cycling (Exhaustion Bombing)
const FAKE_PINS = ['000000', '123456', '999999', '111111', '888888', '654321', '777777'];
app.post('/api/simulate/mfa-bomb', (req, res) => {
  const target = req.body?.target || 'Utkarsh';
  const count = Number(req.body?.count) || FAKE_PINS.length;
  for (let i = 0; i < count; i++) {
    const pin = FAKE_PINS[i % FAKE_PINS.length];
    pushLog({ ip: '194.26.29.11', username: target, attempted: `OTP:${pin}`, status: '401', mechanism: 'otp' });
  }
  res.json({ added: count, attack_type: 'mfa_exhaustion' });
});

app.post('/api/evaluate', async (req, res) => {
  const engine = req.query.engine || 'both';
  const state = buildState();
  const payload = buildPayload(state);
  let jev, laya;
  if (engine === 'jev') {
    jev = await evalEngine('jev', state, payload);
  } else if (engine === 'laya') {
    laya = await evalEngine('laya', state, payload);
  } else {
    [jev, laya] = await Promise.all([evalEngine('jev', state, payload), evalEngine('laya', state, payload)]);
  }

  // SOAR Active Containment Hook: confidence >= 90% on attack triggers dynamic IP blacklist
  const maxConf = Math.max(jev?.confidence || 0, laya?.confidence || 0);
  const isAttack = (jev?.is_attack > 0.8) || (laya?.is_attack > 0.8);
  let mitigatedIp = null;
  if (isAttack && maxConf >= 90 && state.ip && state.ip !== 'none') {
    const ttlMs = 15 * 60 * 1000;
    ipBlocklist.set(state.ip, {
      blockedAt: Date.now(),
      expiresAt: Date.now() + ttlMs,
      reason: jev?.attack_type || laya?.attack_type || 'high_confidence_threat',
      confidence: maxConf,
      engine: (jev?.confidence >= laya?.confidence) ? 'jev' : 'laya',
    });
    mitigatedIp = state.ip;
  }

  const activeBlocks = Array.from(ipBlocklist.entries()).map(([ip, val]) => ({
    ip,
    ...val,
    remainingSec: Math.max(0, Math.ceil((val.expiresAt - Date.now()) / 1000)),
  }));

  res.json({
    state,
    ...(jev ? { jev } : {}),
    ...(laya ? { laya } : {}),
    soar: {
      mitigatedIp,
      activeBlocksCount: activeBlocks.length,
      activeBlocks,
    },
  });
});

const SHARED_HEAD = `<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>NVIDIA // Cyber Triage Command Center</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/driver.js@1.0.1/dist/driver.css"/>
  <script src="https://cdn.jsdelivr.net/npm/driver.js@1.0.1/dist/driver.js.iife.js"></script>
  <style>
    :root {
      --nv-green: #76b900;
      --nv-green-dark: #5a8d00;
      --nv-black: #000000;
      --nv-canvas-dark: #0a0a0a;
      --nv-surface-dark: #121212;
      --nv-surface-elevated: #1a1a1a;
      --nv-surface-soft: #242424;
      --nv-hairline: #333333;
      --nv-hairline-strong: #5e5e5e;
      --nv-text: #ffffff;
      --nv-text-mute: rgba(255, 255, 255, 0.7);
      --nv-text-stone: #898989;
      --nv-error: #e52020;
      --nv-radius: 2px;
      --font-main: 'Poppins', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'IBM Plex Mono', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--nv-black);
      color: var(--nv-text);
      font-family: var(--font-main);
      line-height: 1.5;
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }
    .mono { font-family: var(--font-mono); }
    h1, h2, h3, h4 {
      font-weight: 700;
      letter-spacing: -0.02em;
      line-height: 1.25;
    }
    .nv-card {
      position: relative;
      background: var(--nv-surface-dark);
      border: 1px solid var(--nv-hairline);
      border-radius: var(--nv-radius);
      padding: 16px 20px;
      margin-bottom: 14px;
    }
    .nv-card::before {
      content: '';
      position: absolute;
      top: -1px; left: -1px;
      width: 12px; height: 12px;
      background: var(--nv-green);
    }
    input {
      background: var(--nv-black);
      border: 1px solid var(--nv-hairline);
      border-radius: var(--nv-radius);
      color: var(--nv-text);
      padding: 11px 16px;
      font-size: 14px;
      width: 100%;
      margin: 8px 0;
      outline: none;
      font-family: var(--font-main);
      transition: border-color .15s ease;
    }
    input::placeholder { color: var(--nv-text-stone); }
    input:focus {
      border: 2px solid var(--nv-green);
      background: #000000;
    }
    button {
      font-family: var(--font-main);
      font-size: 14px;
      font-weight: 700;
      border-radius: var(--nv-radius);
      padding: 10px 20px;
      margin: 4px;
      cursor: pointer;
      border: 1px solid var(--nv-hairline);
      background: var(--nv-surface-elevated);
      color: var(--nv-text);
      transition: all .15s ease;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    button:hover {
      border-color: var(--nv-green);
      color: var(--nv-green);
    }
    button:active {
      transform: translateY(1px);
    }
    button.btn-nv-primary {
      background: var(--nv-green);
      color: var(--nv-black);
      border: 1px solid var(--nv-green);
    }
    button.btn-nv-primary:hover {
      background: var(--nv-green-dark);
      border-color: var(--nv-green-dark);
      color: var(--nv-black);
    }
    button.btn-nv-outline {
      background: transparent;
      color: var(--nv-green);
      border: 2px solid var(--nv-green);
    }
    button.btn-nv-outline:hover {
      background: var(--nv-green);
      color: var(--nv-black);
    }
    a {
      color: var(--nv-green);
      text-decoration: none;
      transition: opacity .15s;
    }
    a:hover { opacity: 0.8; }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 8px;
      border-radius: var(--nv-radius);
      font-size: 11px;
      font-family: var(--font-mono);
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-green {
      background: rgba(118, 185, 0, 0.15);
      color: var(--nv-green);
      border: 1px solid var(--nv-green);
    }
    .badge-red {
      background: rgba(229, 32, 32, 0.15);
      color: var(--nv-error);
      border: 1px solid var(--nv-error);
    }
    .badge-dark {
      background: var(--nv-surface-soft);
      color: var(--nv-text-mute);
      border: 1px solid var(--nv-hairline);
    }
    .top-nav {
      position: sticky; top: 0; z-index: 100;
      background: var(--nv-black);
      border-bottom: 1px solid var(--nv-hairline);
      padding: 10px 24px;
      display: flex; justify-content: space-between; align-items: center;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-family: var(--font-mono);
      font-size: 12px;
    }
    th {
      background: var(--nv-surface-soft);
      color: var(--nv-text-mute);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 8px 12px;
      border: 1px solid var(--nv-hairline);
      text-align: left;
    }
    td {
      border: 1px solid var(--nv-hairline);
      padding: 7px 12px;
      color: var(--nv-text-mute);
    }
    tr:hover td { background: rgba(118, 185, 0, 0.04); }
    .meter-container {
      width: 100%; background: var(--nv-black); height: 6px; border-radius: var(--nv-radius); overflow: hidden; margin-top: 6px; border: 1px solid var(--nv-hairline);
    }
    .meter-bar {
      height: 100%; width: 0%; transition: width 0.4s ease; background: var(--nv-green);
    }
    /* Driver.js NVIDIA Styling */
    .driver-popover {
      background-color: #121212 !important;
      color: #ffffff !important;
      border: 1px solid #76b900 !important;
      border-radius: 2px !important;
      font-family: 'Poppins', sans-serif !important;
      box-shadow: 0 4px 24px rgba(0,0,0,0.9) !important;
      padding: 16px !important;
    }
    .driver-popover-title {
      color: #76b900 !important;
      font-weight: 700 !important;
      font-size: 15px !important;
      letter-spacing: -0.01em;
    }
    .driver-popover-description {
      color: rgba(255,255,255,0.85) !important;
      font-size: 13px !important;
      margin-top: 6px !important;
      line-height: 1.5 !important;
    }
    .driver-popover-next-btn, .driver-popover-prev-btn {
      background-color: #76b900 !important;
      color: #000000 !important;
      border: none !important;
      border-radius: 2px !important;
      font-weight: 700 !important;
      font-family: 'Poppins', sans-serif !important;
      font-size: 12px !important;
      padding: 6px 14px !important;
    }
    .driver-popover-close-btn {
      color: #76b900 !important;
    }
    /* Dynamic Movable Dashboard Blocks */
    .dashboard-block {
      transition: transform 0.25s ease, box-shadow 0.25s ease, opacity 0.2s ease;
      position: relative;
    }
    .dashboard-block.dragging {
      opacity: 0.45;
      transform: scale(0.99);
    }
    .dashboard-block.drag-over {
      outline: 2px dashed var(--nv-green);
      outline-offset: 4px;
    }
    .block-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: var(--nv-surface-soft);
      border: 1px solid var(--nv-hairline);
      border-bottom: none;
      padding: 6px 12px;
      border-top-left-radius: var(--nv-radius);
      border-top-right-radius: var(--nv-radius);
    }
    .block-tag {
      font-size: 11px;
      font-weight: 700;
      color: var(--nv-text-stone);
      letter-spacing: 0.5px;
    }
    .block-handle {
      cursor: grab;
      font-size: 15px;
      color: var(--nv-green);
      user-select: none;
      padding: 0 4px;
    }
    .block-handle:active {
      cursor: grabbing;
    }
    .block-actions {
      display: flex;
      align-items: center;
      gap: 4px;
    }
    .btn-block-shift {
      background: var(--nv-surface-dark);
      color: var(--nv-text);
      border: 1px solid var(--nv-hairline);
      border-radius: var(--nv-radius);
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 600;
      padding: 3px 8px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 2px;
      transition: all 0.15s ease;
    }
    .btn-block-shift:hover:not(:disabled) {
      background: var(--nv-green);
      color: var(--nv-black);
      border-color: var(--nv-green);
    }
    .btn-block-shift:disabled {
      opacity: 0.35;
      cursor: not-allowed;
    }
    .dashboard-block > .nv-card {
      margin-top: 0 !important;
      border-top-left-radius: 0 !important;
      border-top-right-radius: 0 !important;
    }
    /* Archify Inline Architecture Section */
    #archify-architecture {
      transition: border-color 0.3s ease, box-shadow 0.3s ease;
    }
  </style>
</head>`;

app.get('/signup', (req, res) => res.send(`<html>${SHARED_HEAD}<body>
<nav class="top-nav">
  <div style="display: flex; align-items: center; gap: 14px;">
    <span class="mono" style="font-weight: 700; font-size: 15px; color: var(--nv-green);">NVIDIA // REGISTRATION GATEWAY</span>
    <span class="badge badge-green">IDENTITY ENROLLMENT</span>
  </div>
  <div>
    <a href="/login" class="mono" style="font-size: 13px; color: var(--nv-text-mute);">Existing User? Log In →</a>
  </div>
</nav>

<div style="max-width: 480px; margin: 3rem auto; padding: 0 16px;">
  <div style="text-align: center; margin-bottom: 2rem;">
    <span class="badge badge-green" style="margin-bottom: 10px;">CREDENTIAL ENROLLMENT</span>
    <h1 style="font-size: 28px; color: #ffffff; margin-bottom: 8px;">Create Enclave Identity</h1>
    <p style="color: var(--nv-text-mute); font-size: 14px;">
      Register a legitimate credential profile for enclave zero-trust surveillance.
    </p>
  </div>

  <div class="nv-card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
      <h2 style="font-size: 18px;">Register Account</h2>
      <span class="mono" style="font-size: 11px; color: var(--nv-green);">POST /api/auth/password/signup</span>
    </div>
    <div style="margin-bottom: 12px;">
      <label class="mono" style="font-size: 11px; color: var(--nv-text-mute); display: block; margin-bottom: 4px;">USERNAME</label>
      <input id="reg-user" placeholder="Username (e.g. Utkarsh)" style="width: 100%;" />
    </div>
    <div style="margin-bottom: 12px;">
      <label class="mono" style="font-size: 11px; color: var(--nv-text-mute); display: block; margin-bottom: 4px;">PASSWORD</label>
      <div style="position: relative;">
        <input id="reg-pass" type="password" placeholder="Password (e.g. StrongPassword#2026)" style="width: 100%; padding-right: 40px;" />
        <button type="button" id="btn-toggle-reg-pass" onclick="togglePasswordVisibility('reg-pass', this)" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: transparent; border: none; cursor: pointer; color: var(--nv-text-mute); display: flex; align-items: center; justify-content: center; padding: 4px; transition: color 0.15s ease;" onmouseover="this.style.color='var(--nv-green)'" onmouseout="this.style.color='var(--nv-text-mute)'" title="Toggle password visibility" aria-label="Toggle password visibility"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg></button>
      </div>
    </div>
    <div style="margin-bottom: 16px;">
      <label class="mono" style="font-size: 11px; color: var(--nv-text-mute); display: block; margin-bottom: 4px;">SECURITY PASSWORD HINT</label>
      <input id="reg-hint" placeholder="Security Password Hint (e.g. Bruno)" style="width: 100%;" />
    </div>
    <button class="btn-nv-primary" style="width: 100%; margin: 6px 0; justify-content: center; padding: 12px;" onclick="register()">Sign Up</button>
    <div id="reg-msg" style="margin-top: 10px; font-size: 13px;"></div>

    <div style="margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--nv-hairline); text-align: center;">
      <span style="color: var(--nv-text-mute); font-size: 13px;">Already have an account?</span>
      <a href="/login" id="link-to-login" style="color: var(--nv-green); font-weight: 600; font-size: 13px; margin-left: 6px; text-decoration: underline;">Log In here →</a>
    </div>
  </div>

  <div style="text-align: center; margin-top: 1.5rem;">
    <a href="/security-dashboard" class="mono" style="font-size: 12px; color: var(--nv-text-stone);">
      → Open Threat Surveillance & Triage Dashboard
    </a>
  </div>
</div>

<script>
const EYE_OPEN = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
const EYE_CLOSED = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';

function togglePasswordVisibility(id, btn){
  const inp = document.getElementById(id);
  if (!inp) return;
  if (inp.type === 'password') {
    inp.type = 'text';
    btn.innerHTML = EYE_CLOSED;
    btn.title = 'Hide password';
  } else {
    inp.type = 'password';
    btn.innerHTML = EYE_OPEN;
    btn.title = 'Show password';
  }
}
function regUser(){ return document.getElementById('reg-user').value.trim(); }
function regPass(){ return document.getElementById('reg-pass').value; }

async function register(){
  const u = regUser();
  const p = regPass();
  const h = document.getElementById('reg-hint').value;
  const msgEl = document.getElementById('reg-msg');
  if (!u || !p) {
    if (msgEl) { msgEl.style.color = 'var(--nv-error)'; msgEl.innerText = 'Please provide both username and password'; }
    alert('Please enter username and password');
    return;
  }
  try {
    const r = await fetch('/api/auth/password/signup', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p, hint: h })
    });
    const data = await r.json();
    if (data.success) {
      if (msgEl) { msgEl.style.color = 'var(--nv-green)'; msgEl.innerText = 'User registered! Redirecting to login...'; }
      alert(data.message || 'User registered');
      window.location.href = '/login?registered=' + encodeURIComponent(u);
    } else {
      if (msgEl) { msgEl.style.color = 'var(--nv-error)'; msgEl.innerText = data.error || 'Registration failed'; }
      alert(data.error || 'Registration failed');
    }
  } catch (err) {
    if (msgEl) { msgEl.style.color = 'var(--nv-error)'; msgEl.innerText = 'Network error during signup'; }
    alert('Network error');
  }
}
</script></body></html>`));

app.get(['/login', '/'], (req, res) => res.send(`<html>${SHARED_HEAD}<body>
<nav class="top-nav">
  <div style="display: flex; align-items: center; gap: 14px;">
    <span class="mono" style="font-weight: 700; font-size: 15px; color: var(--nv-green);">NVIDIA // CYBER DEFENSE</span>
    <span class="badge badge-green">AUTH GATEWAY</span>
  </div>
  <div>
    <a href="/security-dashboard" class="mono" style="font-size: 13px;">Security Command Center →</a>
  </div>
</nav>

<div style="max-width: 520px; margin: 2.5rem auto; padding: 0 16px;">
  <div style="text-align: center; margin-bottom: 1.5rem;">
    <h1 style="font-size: 30px; color: #ffffff; margin-bottom: 6px;">Security Gateway</h1>
    <p style="color: var(--nv-text-mute); font-size: 14px;">Multi-Mechanism Auth: Password, Machine API Key & MFA Step-Up</p>
    <div style="display: flex; justify-content: center; gap: 8px; margin-top: 14px;">
      <button onclick="switchAuthTab('password')" id="tab-btn-pwd" class="badge badge-green" style="cursor: pointer; padding: 6px 12px;">🔑 Password Auth</button>
      <button onclick="switchAuthTab('apikey')" id="tab-btn-api" class="badge badge-dark" style="cursor: pointer; padding: 6px 12px;">🤖 API Key Auth</button>
      <button onclick="switchAuthTab('mfa')" id="tab-btn-mfa" class="badge badge-dark" style="cursor: pointer; padding: 6px 12px;">📱 MFA OTP</button>
    </div>
  </div>

  <!-- Tab 1: Password Auth (Dedicated Login) -->
  <div id="auth-panel-pwd">
    <div class="nv-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
        <h2 style="font-size: 18px;">Authenticate</h2>
        <span class="mono" style="font-size: 11px; color: var(--nv-green);">POST /api/auth/password/login</span>
      </div>
      <div id="reg-success-banner" style="display: none; padding: 8px 12px; background: rgba(118, 185, 0, 0.12); border: 1px solid var(--nv-green); color: var(--nv-green); font-size: 12px; margin-bottom: 12px; border-radius: 2px;">
        ✓ Account registered! You can now log in with your credentials.
      </div>
      <div style="margin-bottom: 10px;">
        <label class="mono" style="font-size: 11px; color: var(--nv-text-mute); display: block; margin-bottom: 4px;">USERNAME</label>
        <input id="login-user" placeholder="Username" onfocus="recordKeyFocus()" onkeydown="recordKeyDown()"/>
      </div>
      <div style="margin-bottom: 12px;">
        <label class="mono" style="font-size: 11px; color: var(--nv-text-mute); display: block; margin-bottom: 4px;">PASSWORD</label>
        <div style="position: relative;">
          <input id="login-pass" type="password" placeholder="Password" style="width: 100%; padding-right: 40px;" onfocus="recordKeyFocus()" onkeydown="recordKeyDown()"/>
          <button type="button" id="btn-toggle-login-pass" onclick="togglePasswordVisibility('login-pass', this)" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: transparent; border: none; cursor: pointer; color: var(--nv-text-mute); display: flex; align-items: center; justify-content: center; padding: 4px; transition: color 0.15s ease;" onmouseover="this.style.color='var(--nv-green)'" onmouseout="this.style.color='var(--nv-text-mute)'" title="Toggle password visibility" aria-label="Toggle password visibility"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg></button>
        </div>
      </div>
      <button class="btn-nv-primary" style="width: 100%; margin: 12px 0 4px; justify-content: center;" onclick="login()">Log In</button>
      <div id="msg" style="color: var(--nv-error); font-size: 13px; margin-top: 8px; font-weight: 600;"></div>
      <div id="hint-msg" style="color: var(--nv-green); font-size: 13px; margin-top: 6px; font-family: var(--font-mono);"></div>

      <div style="margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--nv-hairline); text-align: center;">
        <span style="color: var(--nv-text-mute); font-size: 13px;">Don't have an enclave account?</span>
        <a href="/signup" id="link-to-signup" style="color: var(--nv-green); font-weight: 600; font-size: 13px; margin-left: 6px; text-decoration: underline;">Sign Up for an account →</a>
      </div>
    </div>
  </div>

  <!-- Tab 2: Machine API Key Auth -->
  <div id="auth-panel-api" style="display: none;">
    <div class="nv-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
        <h2>Generate Machine Key</h2>
        <span class="mono" style="font-size: 11px; color: var(--nv-green);">POST /api/auth/apikey/generate</span>
      </div>
      <input id="gen-key-user" placeholder="Service / Bot Name (e.g. microservice_worker)" value="service_worker"/>
      <button class="btn-nv-outline" style="width: 100%; margin: 8px 0;" onclick="generateKey()">Generate Secret Key</button>
      <div id="key-gen-res" class="mono" style="font-size: 12px; color: var(--nv-green); margin-top: 6px; word-break: break-all;"></div>
    </div>

    <div class="nv-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
        <h2>Verify API Key</h2>
        <span class="mono" style="font-size: 11px; color: var(--nv-green);">POST /api/auth/apikey/verify</span>
      </div>
      <input id="verify-key-input" placeholder="X-API-Key (e.g. nv_sec_...)"/>
      <button class="btn-nv-primary" style="width: 100%; margin: 8px 0; justify-content: center;" onclick="verifyKey()">Verify Machine Key</button>
      <div id="key-verify-res" class="mono" style="font-size: 13px; margin-top: 6px;"></div>
    </div>
  </div>

  <!-- Tab 3: Step-up MFA / OTP -->
  <div id="auth-panel-mfa" style="display: none;">
    <div class="nv-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
        <h2>Step-up MFA / OTP Challenge</h2>
        <span class="mono" style="font-size: 11px; color: var(--nv-green);">POST /api/auth/mfa/send-otp</span>
      </div>
      <input id="mfa-user" placeholder="Username (e.g. Utkarsh)" value="Utkarsh"/>
      <button class="btn-nv-outline" style="width: 100%; margin: 8px 0;" onclick="sendOtp()">Send 6-Digit OTP</button>
      <div id="otp-send-res" class="mono" style="font-size: 12px; color: var(--nv-green); margin-top: 6px;"></div>

      <hr style="border: 0; border-top: 1px solid var(--nv-hairline); margin: 16px 0;"/>

      <input id="mfa-code" placeholder="6-digit PIN (e.g. 123456)"/>
      <button class="btn-nv-primary" style="width: 100%; margin: 8px 0; justify-content: center;" onclick="verifyOtp()">Verify OTP Code</button>
      <div id="otp-verify-res" class="mono" style="font-size: 13px; margin-top: 6px;"></div>
    </div>
  </div>

  <div style="text-align: center; margin-top: 1.5rem;">
    <a href="/security-dashboard" class="mono" style="font-size: 13px;">
      → Open Threat Surveillance & Triage Dashboard
    </a>
  </div>
</div>

<script>
let keystrokeDeltas = [];
let lastKeyTime = 0;
let mouseDistanceMoved = 0;
let lastMouseX = null, lastMouseY = null;
let formStartTime = 0;

window.addEventListener('mousemove', (e) => {
  if (lastMouseX !== null && lastMouseY !== null) {
    const dx = e.clientX - lastMouseX;
    const dy = e.clientY - lastMouseY;
    mouseDistanceMoved += Math.sqrt(dx * dx + dy * dy);
  }
  lastMouseX = e.clientX;
  lastMouseY = e.clientY;
});

window.addEventListener('DOMContentLoaded', () => {
  const p = new URLSearchParams(window.location.search);
  const regUser = p.get('registered');
  if (regUser) {
    const banner = document.getElementById('reg-success-banner');
    if (banner) banner.style.display = 'block';
    const uInput = document.getElementById('login-user');
    if (uInput) uInput.value = regUser;
  }
});

function recordKeyFocus(){
  if (!formStartTime) formStartTime = Date.now();
}
function recordKeyDown(){
  const t = Date.now();
  if (lastKeyTime) keystrokeDeltas.push(t - lastKeyTime);
  lastKeyTime = t;
}

function switchAuthTab(tab){
  ['pwd', 'api', 'mfa'].forEach(t => {
    document.getElementById('auth-panel-' + t).style.display = (t === tab ? 'block' : 'none');
    document.getElementById('tab-btn-' + t).className = (t === tab ? 'badge badge-green' : 'badge badge-dark');
  });
}

function escapeHtml(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

const EYE_OPEN = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
const EYE_CLOSED = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';

function togglePasswordVisibility(id, btn){
  const inp = document.getElementById(id);
  if (!inp) return;
  if (inp.type === 'password') {
    inp.type = 'text';
    btn.innerHTML = EYE_CLOSED;
    btn.title = 'Hide password';
  } else {
    inp.type = 'password';
    btn.innerHTML = EYE_OPEN;
    btn.title = 'Show password';
  }
}

async function login(){
  const totalFormTimeMs = formStartTime ? (Date.now() - formStartTime) : 0;
  const telemetry = {
    keystrokeDeltas: keystrokeDeltas.slice(-10),
    mouseDistanceMoved: Math.round(mouseDistanceMoved),
    totalFormTimeMs: totalFormTimeMs,
  };
  const r = await fetch('/api/auth/password/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: document.getElementById('login-user').value,
      password: document.getElementById('login-pass').value,
      telemetry,
    })
  });
  const d = await r.json();
  if (r.status === 403) {
    document.getElementById('msg').innerText = d.error || 'Access Denied: IP Blacklisted by SOAR Active Defense';
    document.getElementById('hint-msg').innerText = 'SOAR Defense: Blocked (' + (d.reason || 'threat') + ')';
    return;
  }
  if (d.success) {
    location.href = d.redirect;
  } else {
    document.getElementById('msg').innerText = d.error || '';
    if (d.flagged) {
      document.getElementById('msg').innerHTML = '<span style="color:var(--nv-error); font-weight:700;">⚠ ' + escapeHtml(d.error || 'BRUTE FORCE ATTACK FLAGGED') + '</span>';
      document.getElementById('hint-msg').innerText = 'Hint: ' + (d.hint || '') + ' [THREAT FLAGGED: Limit reached (' + (d.failures || 5) + '/' + (d.limit || 5) + ')]';
    } else {
      document.getElementById('hint-msg').innerText = 'Hint: ' + (d.hint || '');
    }
  }
}

async function generateKey(){
  const u = document.getElementById('gen-key-user').value || 'service_worker';
  const r = await fetch('/api/auth/apikey/generate', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u })
  });
  const d = await r.json();
  document.getElementById('key-gen-res').innerText = 'Created: ' + d.apiKey;
  document.getElementById('verify-key-input').value = d.apiKey;
}

async function verifyKey(){
  const key = document.getElementById('verify-key-input').value;
  const r = await fetch('/api/auth/apikey/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': key }
  });
  const d = await r.json();
  const el = document.getElementById('key-verify-res');
  if (d.success) {
    el.style.color = 'var(--nv-green)';
    el.innerText = 'Authenticated! User: ' + d.username + ' (' + d.role + ')';
  } else {
    el.style.color = 'var(--nv-error)';
    el.innerText = 'Failed: ' + (d.error || 'Invalid API key');
  }
}

async function sendOtp(){
  const u = document.getElementById('mfa-user').value || 'Utkarsh';
  const r = await fetch('/api/auth/mfa/send-otp', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u })
  });
  const d = await r.json();
  document.getElementById('otp-send-res').innerText = d.message + ' (Demo code: ' + d.codePreview + ')';
  document.getElementById('mfa-code').value = d.codePreview;
}

async function verifyOtp(){
  const u = document.getElementById('mfa-user').value || 'Utkarsh';
  const code = document.getElementById('mfa-code').value;
  const r = await fetch('/api/auth/mfa/verify-otp', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, code })
  });
  const d = await r.json();
  const el = document.getElementById('otp-verify-res');
  if (d.success) {
    el.style.color = 'var(--nv-green)';
    el.innerText = 'Success! ' + d.message + ' (' + d.session + ')';
  } else {
    el.style.color = 'var(--nv-error)';
    el.innerText = 'Failed: ' + (d.error || 'Invalid code');
  }
}
</script></body></html>`));

app.get('/user-dashboard', (req, res) => {
  const u = String(req.query.user || 'Guest').replace(/[<>&"]/g, '');
  res.send(`<html>${SHARED_HEAD}<body>
<nav class="top-nav">
  <div style="display: flex; align-items: center; gap: 14px;">
    <span class="mono" style="font-weight: 700; font-size: 15px; color: var(--nv-green);">NVIDIA // IDENTITY VAULT</span>
    <span class="badge badge-green">SESSION ACTIVE</span>
  </div>
  <div>
    <a href="/security-dashboard" class="mono" style="font-size: 13px;">Surveillance Stream →</a>
  </div>
</nav>

<div style="max-width: 580px; margin: 5rem auto; padding: 0 16px; text-align: center;">
  <div class="nv-card" style="padding: 3rem 2rem;">
    <div style="display: flex; justify-content: center; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;">
      <span class="badge badge-green" data-testid="role-badge">ROLE: NORMAL USER (LEGITIMATE)</span>
      <span class="badge badge-green">ENCLAVE AUTHENTICATED</span>
      <span class="badge badge-dark">SECURITY STATUS: BENIGN / VERIFIED</span>
    </div>
    <h1 data-testid="user-welcome" style="font-size: 30px; margin: 12px 0 16px;">Welcome to your Dashboard, ${u}!</h1>
    <p style="color: var(--nv-text-mute); font-size: 15px; margin-bottom: 28px; line-height: 1.6;">
      Authentication verified as a <strong>Legitimate Normal User</strong>. Zero threat signatures or brute force patterns detected for this session.
    </p>
    <div style="display: flex; justify-content: center; gap: 12px;">
      <a href="/security-dashboard"><button class="btn-nv-primary">Security Command View</button></a>
      <a href="/login"><button class="btn-nv-outline">Sign Out</button></a>
    </div>
  </div>
</div></body></html>`);
});

app.get(['/security-dashboard', '/security-dashbaord', '/dashboard', '/security'], (req, res) => res.send(`<html>${SHARED_HEAD}<body>
<nav class="top-nav" id="tour-brand">
  <div style="display: flex; align-items: center; gap: 14px;">
    <span class="mono" style="font-weight: 700; font-size: 15px; color: var(--nv-green);">NVIDIA // CYBER COMMAND</span>
    <span class="badge badge-green" id="soar-status-badge">Status: Monitoring</span>
  </div>
  <div style="display: flex; align-items: center; gap: 14px;">
    <button onclick="startTour(true)" class="badge badge-dark" style="cursor: pointer; padding: 6px 12px;" id="tour-btn">▶ Product Tour</button>
    <button onclick="scrollToArchify()" class="badge badge-green" style="cursor: pointer; padding: 6px 12px;" id="archify-btn">🏛 Archify Architecture</button>
    <button onclick="clearSoar()" class="badge badge-dark" style="cursor: pointer; padding: 6px 12px;" id="soar-unblock-btn">🛡 Unblock All</button>
    <button onclick="resetBlockOrder()" class="badge badge-dark" style="cursor: pointer; padding: 6px 12px;" id="btn-reset-layout" title="Reset blocks to default sequence">⟲ Reset Layout</button>
    <span class="mono" style="font-size: 12px; color: var(--nv-text-mute);" id="nav-log-count">0 logs</span>
    <a href="/" class="mono" style="font-size: 12px; color: var(--nv-text-stone);">← Auth Gateway</a>
  </div>
</nav>

<div style="max-width: 1240px; margin: 1.25rem auto; padding: 0 16px;">
  <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 1rem;">
    <div>
      <h2 style="font-size: 26px;">Backend Security Logs View</h2>
      <p style="color: var(--nv-text-mute); font-size: 14px; margin-top: 4px;">
        Encoder-only Dual Engine Triage: Jev SystemOne Cloud vs Local Laya Stub
      </p>
    </div>
    <div style="display: flex; gap: 8px;">
      <span class="badge badge-green mono">Jev: ${API_KEY ? 'Cloud Key Linked' : 'Offline Heuristic'}</span>
      <span class="badge badge-dark mono">Laya: Port 8000 Active</span>
    </div>
  </div>

  <div id="dashboard-blocks-container" style="display: flex; flex-direction: column; gap: 14px;">

  <!-- BLOCK 1: SIMULATION & ENGINE CONTROLS -->
  <div class="dashboard-block" id="block-controls" data-block-id="block-controls" draggable="true">
    <div class="block-bar">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span class="block-handle" title="Drag to reorder block">⠿</span>
        <span class="mono block-tag">BLOCK <span class="block-idx">01</span> // SIMULATION & ENGINE CONTROLS</span>
      </div>
      <div class="block-actions">
        <button onclick="shiftBlock('block-controls', 'up')" class="btn-block-shift btn-shift-up" title="Shift block up">▲ Up</button>
        <button onclick="shiftBlock('block-controls', 'down')" class="btn-block-shift btn-shift-down" title="Shift block down">▼ Down</button>
      </div>
    </div>
    <!-- Command Toolbar -->
    <div class="nv-card" id="tour-generators">
      <!-- Top Bar: 3 Engine Options (Jev, Laya, Compare) + Right-Corner Clear Buffer -->
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--nv-hairline); padding-bottom: 10px; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
          <span class="mono" style="font-size: 11px; color: var(--nv-green); text-transform: uppercase; font-weight: 700;">ACTIVE INFERENCE ENGINE:</span>
          <button id="engine-sel-jev" onclick="selectEngine('jev')" class="badge badge-dark" style="cursor: pointer; padding: 6px 14px; font-weight: 700;">Jev AI</button>
          <button id="engine-sel-laya" onclick="selectEngine('laya')" class="badge badge-dark" style="cursor: pointer; padding: 6px 14px; font-weight: 700;">Laya AI</button>
          <button id="engine-sel-both" onclick="selectEngine('both')" class="badge badge-green" style="cursor: pointer; padding: 6px 14px; font-weight: 700;">⚡ Compare Jev vs Laya</button>
        </div>
        <div>
          <button id="btn-clear-buffer-corner" onclick="clearLogs()" class="badge badge-dark" style="cursor: pointer; padding: 6px 14px; color: var(--nv-error); border-color: rgba(229,32,32,0.4); font-weight: 700;" title="Flush audit logs and reset evaluations">🗑 Clear Buffer</button>
        </div>
      </div>

      <!-- Bottom Bar: Simulation Vectors & AI Inference Dispatch -->
      <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 14px;">
        <div style="flex: 1; min-width: 320px;">
          <span class="mono" style="font-size: 11px; color: var(--nv-green); text-transform: uppercase; font-weight: 700; display: block; margin-bottom: 6px;">SIMULATION ATTACK VECTORS (AUTO-EVALUATES ON CLICK)</span>
          <div style="display: flex; flex-wrap: wrap; gap: 4px;">
            <button onclick="sim('single')" class="btn-nv-outline">⚡ 1 User</button>
            <button onclick="sim('burst')" class="btn-nv-outline">🔥 Brute Force (200)</button>
            <button onclick="sim('spray')" class="btn-nv-outline">🌊 Password Spray</button>
            <button onclick="sim('stuffing')" class="btn-nv-outline">📦 Credential Stuffing</button>
            <button onclick="sim('sqli')" class="btn-nv-outline">💉 SQLi Bypass</button>
            <button onclick="sim('apikey')" class="btn-nv-outline">🔑 API Key Scan</button>
            <button onclick="sim('mfa')" class="btn-nv-outline">📱 MFA Bombing</button>
            <button onclick="mcp()">🤖 Playwright MCP</button>
          </div>
        </div>
        <div id="tour-eval-dispatch">
          <span class="mono" style="font-size: 11px; color: var(--nv-green); text-transform: uppercase; font-weight: 700; display: block; margin-bottom: 6px;">MANUAL INFERENCE DISPATCH</span>
          <button onclick="ev('jev')">Jev AI</button>
          <button onclick="ev('laya')">Laya AI</button>
          <button class="btn-nv-primary" onclick="ev('both')">⚡ Compare Jev vs Laya</button>
        </div>
      </div>
    </div>
    <p id="mcp-hint" class="mono" style="color: var(--nv-green); font-size: 13px; margin: 4px 0 0 4px; min-height: 18px;"></p>
  </div>

  <!-- BLOCK 2: DUAL ENGINE TRIAGE & VERDICT -->
  <div class="dashboard-block" id="block-triage" data-block-id="block-triage" draggable="true">
    <div class="block-bar">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span class="block-handle" title="Drag to reorder block">⠿</span>
        <span class="mono block-tag">BLOCK <span class="block-idx">02</span> // DUAL ENGINE TRIAGE & VERDICT</span>
      </div>
      <div class="block-actions">
        <button onclick="shiftBlock('block-triage', 'up')" class="btn-block-shift btn-shift-up" title="Shift block up">▲ Up</button>
        <button onclick="shiftBlock('block-triage', 'down')" class="btn-block-shift btn-shift-down" title="Shift block down">▼ Down</button>
      </div>
    </div>

    <!-- Live Verdict & Evaluation State Banner -->
    <div id="eval-banner-card" class="nv-card" style="border-left: 3px solid var(--nv-green); display: flex; justify-content: space-between; align-items: center; padding: 18px 24px; margin-bottom: 8px;">
      <div>
        <div id="eval-desc" class="mono" style="font-size: 15px; font-weight: 600; color: #ffffff;">Description: waiting…</div>
        <div id="eval-conf" class="mono" style="color: var(--nv-text-mute); font-size: 13px; margin-top: 4px;">Confidence: --%</div>
      </div>
      <div id="eval-status-indicator" class="mono badge badge-dark">
        READY FOR TRIAGE
      </div>
    </div>

    <!-- Dual Model Comparison Cards + Table -->
    <div class="nv-card" id="tour-dual-engine" style="margin-top: 8px !important; border-top-left-radius: var(--nv-radius) !important; border-top-right-radius: var(--nv-radius) !important;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <h3>Model Verdict Comparison (Dual Engine)</h3>
        <span class="mono" style="font-size: 11px; color: var(--nv-green);">ROLLING 20-ROW WINDOW</span>
      </div>

    <!-- Visual side-by-side cards -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 18px;">
      <div style="background: var(--nv-surface-soft); border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius); padding: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span class="mono" style="font-size: 13px; font-weight: 700; color: #ffffff;">Jev Cloud (SystemOne)</span>
          <span id="card-lat-jev" class="mono badge badge-green">-- ms</span>
        </div>
        <div id="card-desc-jev" class="mono" style="font-size: 13px; color: var(--nv-text-mute); margin-top: 8px;">Waiting for evaluation...</div>
        <div class="meter-container"><div id="card-meter-jev" class="meter-bar"></div></div>
      </div>

      <div style="background: var(--nv-surface-soft); border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius); padding: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span class="mono" style="font-size: 13px; font-weight: 700; color: #ffffff;">Laya Engine (Local Stub)</span>
          <span id="card-lat-laya" class="mono badge badge-green">-- ms</span>
        </div>
        <div id="card-desc-laya" class="mono" style="font-size: 13px; color: var(--nv-text-mute); margin-top: 8px;">Waiting for evaluation...</div>
        <div class="meter-container"><div id="card-meter-laya" class="meter-bar"></div></div>
      </div>
    </div>

    <table id="compare-table">
      <thead>
        <tr>
          <th style="width: 15%;">Engine</th>
          <th style="width: 50%;">Description</th>
          <th style="width: 20%;">Confidence</th>
          <th style="width: 15%;">Latency</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td class="mono" style="color: var(--nv-green); font-weight: 700;">Jev</td>
          <td id="eval-desc-jev">--</td>
          <td id="eval-conf-jev">--%</td>
          <td id="eval-lat-jev">--</td>
        </tr>
        <tr>
          <td class="mono" style="color: var(--nv-green); font-weight: 700;">Laya</td>
          <td id="eval-desc-laya">--</td>
          <td id="eval-conf-laya">--%</td>
          <td id="eval-lat-laya">--</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<!-- BLOCK 3: LIVE ARCHITECTURE BENCHMARK -->
<div class="dashboard-block" id="block-benchmark" data-block-id="block-benchmark" draggable="true">
  <div class="block-bar">
    <div style="display: flex; align-items: center; gap: 8px;">
      <span class="block-handle" title="Drag to reorder block">⠿</span>
      <span class="mono block-tag">BLOCK <span class="block-idx">03</span> // LIVE ARCHITECTURE BENCHMARK</span>
    </div>
    <div class="block-actions">
      <button onclick="shiftBlock('block-benchmark', 'up')" class="btn-block-shift btn-shift-up" title="Shift block up">▲ Up</button>
      <button onclick="shiftBlock('block-benchmark', 'down')" class="btn-block-shift btn-shift-down" title="Shift block down">▼ Down</button>
    </div>
  </div>

  <!-- Live Architecture Benchmark Widget (Laya vs Jev) -->
  <div class="nv-card" id="tour-benchmark-widget">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <div>
        <h3 style="font-size: 18px;">Live Architecture Benchmark: Local Laya Daemon vs Managed Jev Cloud</h3>
        <p style="color: var(--nv-text-mute); font-size: 13px; margin-top: 4px;">Real-time latency, operational cost, and zero-trust data boundary analysis</p>
      </div>
      <span class="badge badge-green mono" id="bench-status-badge">REAL-TIME TELEMETRY</span>
    </div>

    <table style="width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: 13px;">
      <thead>
        <tr style="border-bottom: 1px solid var(--nv-hairline); color: var(--nv-text-stone); text-align: left;">
          <th style="padding: 10px 14px;">Architectural Dimension</th>
          <th style="padding: 10px 14px; color: var(--nv-green);">Laya AI (Local Daemon)</th>
          <th style="padding: 10px 14px; color: #ffffff;">Jev AI (Managed Cloud)</th>
        </tr>
      </thead>
      <tbody>
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
          <td style="padding: 10px 14px; color: var(--nv-text-mute);">Inference Latency</td>
          <td style="padding: 10px 14px; font-weight: 700; color: var(--nv-green);"><span id="bench-lat-laya">~33 ms</span> <span class="badge badge-green" style="font-size: 10px; margin-left: 6px;">7.2x FASTER</span></td>
          <td style="padding: 10px 14px; font-weight: 700; color: #ffffff;"><span id="bench-lat-jev">~240 ms</span> <span class="badge badge-dark" style="font-size: 10px; margin-left: 6px;">WAN RTT</span></td>
        </tr>
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
          <td style="padding: 10px 14px; color: var(--nv-text-mute);">Deployment Topology</td>
          <td style="padding: 10px 14px; color: var(--nv-text);">In-Process / Local Daemon (:8000)</td>
          <td style="padding: 10px 14px; color: var(--nv-text);">HTTPS REST API (api.typesafe.ai)</td>
        </tr>
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
          <td style="padding: 10px 14px; color: var(--nv-text-mute);">Data Egress & Boundary</td>
          <td style="padding: 10px 14px; color: var(--nv-green);">100% On-Premises (Zero Egress)</td>
          <td style="padding: 10px 14px; color: var(--nv-text);">Encrypted TLS Outbound Payload</td>
        </tr>
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
          <td style="padding: 10px 14px; color: var(--nv-text-mute);">Cost per 10,000 Evals</td>
          <td style="padding: 10px 14px; font-weight: 700; color: var(--nv-green);">$0.00 (Local Compute)</td>
          <td style="padding: 10px 14px; color: var(--nv-text);">Per-Call API Inference Credits</td>
        </tr>
        <tr>
          <td style="padding: 10px 14px; color: var(--nv-text-mute);">SOAR Active Containment</td>
          <td style="padding: 10px 14px; color: var(--nv-green);">Sub-second Inline Dynamic IP Blacklist</td>
          <td style="padding: 10px 14px; color: var(--nv-text);">Cloud Event Webhook Dispatch</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<!-- BLOCK 4: DECISION REASONING PRIMITIVES -->
<div class="dashboard-block" id="block-primitives" data-block-id="block-primitives" draggable="true">
  <div class="block-bar">
    <div style="display: flex; align-items: center; gap: 8px;">
      <span class="block-handle" title="Drag to reorder block">⠿</span>
      <span class="mono block-tag">BLOCK <span class="block-idx">04</span> // DECISION REASONING PRIMITIVES</span>
    </div>
    <div class="block-actions">
      <button onclick="shiftBlock('block-primitives', 'up')" class="btn-block-shift btn-shift-up" title="Shift block up">▲ Up</button>
      <button onclick="shiftBlock('block-primitives', 'down')" class="btn-block-shift btn-shift-down" title="Shift block down">▼ Down</button>
    </div>
  </div>

  <!-- 3 Primitive Reasoning Sections: Neoul, Choice, Score -->
  <div class="nv-card" id="tour-reasoning-primitives">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
      <div>
        <h3 style="font-size: 17px; color: var(--nv-green);">AI Decision Reasoning Primitives</h3>
        <p style="color: var(--nv-text-mute); font-size: 12px; margin-top: 2px;">
          Deterministic audit evidence, criteria evaluation & explainability breakdown
        </p>
      </div>
      <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
        <button onclick="toggleAllPrimitives(true)" class="badge badge-dark" style="cursor: pointer; padding: 4px 8px; font-size: 11px;">▾ Expand All</button>
        <button onclick="toggleAllPrimitives(false)" class="badge badge-dark" style="cursor: pointer; padding: 4px 8px; font-size: 11px;">▴ Collapse All</button>
        <span style="color: var(--nv-hairline);">|</span>
        <button onclick="switchPrimitiveView('all')" id="prim-tab-all" class="badge badge-green" style="cursor: pointer; padding: 4px 10px;">All Sections</button>
        <button onclick="switchPrimitiveView('noul')" id="prim-tab-noul" class="badge badge-dark" style="cursor: pointer; padding: 4px 10px;">1. Neoul</button>
        <button onclick="switchPrimitiveView('choice')" id="prim-tab-choice" class="badge badge-dark" style="cursor: pointer; padding: 4px 10px;">2. Choice</button>
        <button onclick="switchPrimitiveView('score')" id="prim-tab-score" class="badge badge-dark" style="cursor: pointer; padding: 4px 10px;">3. Score</button>
      </div>
    </div>

    <!-- Section 1: Neoul Primitive Table -->
    <div id="section-primitive-noul" style="margin-bottom: 14px; border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius); padding: 10px 14px; background: rgba(255,255,255,0.015);">
      <div style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; border-left: 2px solid var(--nv-green); padding-left: 8px;" onclick="togglePrimitiveDropdown('noul')">
        <div>
          <span style="font-size: 12px; font-weight: 700;">SECTION: NEOUL (CONTINUOUS PROBABILITY)</span>
          <span style="font-size: 11px; color: var(--nv-text-mute); margin-left: 6px;">Continuous 0.0 to 1.0 likelihood scale</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="mono" id="noul-verdict-tag" style="color: var(--nv-green); font-size: 12px;">STATUS: MONITORING</span>
          <button type="button" class="badge badge-dark" id="btn-toggle-noul" style="cursor: pointer; padding: 2px 8px; font-size: 11px;">▾ In-Depth Details</button>
        </div>
      </div>
      <div id="wrap-primitive-noul" style="margin-top: 10px; display: block;">
        <table id="table-primitive-noul">
          <thead>
            <tr>
              <th style="width: 20%;">Signal / Evidence</th>
              <th style="width: 15%;">Observed Metric</th>
              <th style="width: 15%;">Decision Threshold</th>
              <th style="width: 15%;">Detection State</th>
              <th style="width: 35%;">Reasoning Justification</th>
            </tr>
          </thead>
          <tbody id="tbody-primitive-noul">
            <tr>
              <td>Failure Volume Window</td>
              <td id="noul-val-attempts" class="mono">0</td>
              <td class="mono">≥ 3 (Stuffing), ≥ 8 (Burst)</td>
              <td id="noul-status-attempts" class="mono"><span class="badge badge-green">NORMAL</span></td>
              <td id="noul-reason-attempts">Volume remains within expected human retry limits.</td>
            </tr>
            <tr>
              <td>Client Behavioral Telemetry</td>
              <td id="noul-val-telemetry" class="mono">-- px / -- ms</td>
              <td class="mono">0px cursor + &lt;500ms fill</td>
              <td id="noul-status-telemetry" class="mono"><span class="badge badge-green">HUMAN</span></td>
              <td id="noul-reason-telemetry">Interaction kinetics indicate natural mouse trajectory and typing intervals.</td>
            </tr>
            <tr>
              <td>Continuous Probability (Neoul)</td>
              <td id="noul-val-prob" class="mono" style="color: var(--nv-green); font-weight:700;">0.160</td>
              <td class="mono">&gt; 0.800 = Adversarial</td>
              <td id="noul-status-prob" class="mono"><span class="badge badge-green">BENIGN</span></td>
              <td id="noul-reason-prob">Belief probability below alert threshold; classified as routine user re-entry.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Section 2: Choice Primitive Table -->
    <div id="section-primitive-choice" style="margin-bottom: 14px; border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius); padding: 10px 14px; background: rgba(255,255,255,0.015);">
      <div style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; border-left: 2px solid var(--nv-green); padding-left: 8px;" onclick="togglePrimitiveDropdown('choice')">
        <div>
          <span style="font-size: 12px; font-weight: 700;">SECTION: CHOICE (CATEGORY CLASSIFICATION)</span>
          <span style="font-size: 11px; color: var(--nv-text-mute); margin-left: 6px;">Discrete adversary tactic selection</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="mono" id="choice-winner-tag" style="color: var(--nv-green); font-size: 12px;">SELECTED: BENIGN_LOGIN</span>
          <button type="button" class="badge badge-dark" id="btn-toggle-choice" style="cursor: pointer; padding: 2px 8px; font-size: 11px;">▾ In-Depth Details</button>
        </div>
      </div>
      <div id="wrap-primitive-choice" style="margin-top: 10px; display: block;">
        <table id="table-primitive-choice">
          <thead>
            <tr>
              <th style="width: 20%;">Candidate Category</th>
              <th style="width: 25%;">Evaluation Criteria</th>
              <th style="width: 15%;">Match Status</th>
              <th style="width: 12%;">Confidence</th>
              <th style="width: 28%;">Reasoning Explanation</th>
            </tr>
          </thead>
          <tbody id="tbody-primitive-choice">
            <tr>
              <td class="mono" style="font-weight:700;">sqli_attempt</td>
              <td>SQL syntax, ' OR 1=1', quotes, comments</td>
              <td id="choice-status-sqli" class="mono">NO MATCH</td>
              <td id="choice-conf-sqli" class="mono">--</td>
              <td id="choice-reason-sqli">No SQL meta-characters or tautologies found in recent buffer samples.</td>
            </tr>
            <tr>
              <td class="mono" style="font-weight:700;">password_spray</td>
              <td>Single password across ≥ 4 distinct users</td>
              <td id="choice-status-spray" class="mono">NO MATCH</td>
              <td id="choice-conf-spray" class="mono">--</td>
              <td id="choice-reason-spray">Single-user target distribution; horizontal spray criteria not satisfied.</td>
            </tr>
            <tr>
              <td class="mono" style="font-weight:700;">credential_stuffing</td>
              <td>Breach combo lists, leaked dictionary passwords</td>
              <td id="choice-status-stuffing" class="mono">NO MATCH</td>
              <td id="choice-conf-stuffing" class="mono">--</td>
              <td id="choice-reason-stuffing">Attempted strings do not match known leaked credential formats.</td>
            </tr>
            <tr>
              <td class="mono" style="font-weight:700;">brute_force</td>
              <td>Rapid multi-attempt flood targeting single victim</td>
              <td id="choice-status-brute" class="mono">NO MATCH</td>
              <td id="choice-conf-brute" class="mono">--</td>
              <td id="choice-reason-brute">Attempt frequency within expected human typing pace.</td>
            </tr>
            <tr style="background: rgba(118,185,0,0.06);">
              <td class="mono" style="font-weight:700; color:var(--nv-green);">benign_login</td>
              <td>1-2 typos of legitimate credentials</td>
              <td id="choice-status-benign" class="mono"><span class="badge badge-green">MATCHED</span></td>
              <td id="choice-conf-benign" class="mono">84.0%</td>
              <td id="choice-reason-benign">Typo pattern consistent with genuine user password retry.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Section 3: Score Primitive Table -->
    <div id="section-primitive-score" style="margin-bottom: 6px; border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius); padding: 10px 14px; background: rgba(255,255,255,0.015);">
      <div style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; border-left: 2px solid var(--nv-green); padding-left: 8px;" onclick="togglePrimitiveDropdown('score')">
        <div>
          <span style="font-size: 12px; font-weight: 700;">SECTION: SCORE (EXPLOIT RISK SEVERITY)</span>
          <span style="font-size: 11px; color: var(--nv-text-mute); margin-left: 6px;">Continuous 0.0 to 3.0 exploitability scale</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="mono" id="score-val-tag" style="color: var(--nv-green); font-size: 12px;">SCORE: 0.4 / 3.0 (HARMLESS)</span>
          <button type="button" class="badge badge-dark" id="btn-toggle-score" style="cursor: pointer; padding: 2px 8px; font-size: 11px;">▾ In-Depth Details</button>
        </div>
      </div>
      <div id="wrap-primitive-score" style="margin-top: 10px; display: block;">
        <table id="table-primitive-score">
          <thead>
            <tr>
              <th style="width: 18%;">Severity Tier</th>
              <th style="width: 14%;">Score Range</th>
              <th style="width: 28%;">Operational Criteria</th>
              <th style="width: 15%;">Active Status</th>
              <th style="width: 25%;">Decision Reasoning</th>
            </tr>
          </thead>
          <tbody id="tbody-primitive-score">
            <tr style="background: rgba(118,185,0,0.06);">
              <td><span class="badge badge-green">Level 0: Harmless</span></td>
              <td class="mono">0.0 - 0.9</td>
              <td>Single user typo, zero system risk</td>
              <td id="score-status-0" class="mono"><span class="badge badge-green">ACTIVE</span></td>
              <td id="score-reason-0">Zero exploit risk detected; user is legitimate.</td>
            </tr>
            <tr>
              <td><span class="badge badge-dark">Level 1: Suspicious</span></td>
              <td class="mono">1.0 - 1.9</td>
              <td>Low-volume probing, reconnaissance</td>
              <td id="score-status-1" class="mono">INACTIVE</td>
              <td id="score-reason-1">Rate-limiting advisory if volume escalates.</td>
            </tr>
            <tr>
              <td><span class="badge badge-dark">Level 2: Attack Flood</span></td>
              <td class="mono">2.0 - 2.5</td>
              <td>Coordinated flood, spray, or stuffing</td>
              <td id="score-status-2" class="mono">INACTIVE</td>
              <td id="score-reason-2">Automatic SOAR dynamic blocklist containment threshold.</td>
            </tr>
            <tr>
              <td><span class="badge badge-red">Level 3: Exploit</span></td>
              <td class="mono">2.6 - 3.0</td>
              <td>SQL injection, token theft, active breach</td>
              <td id="score-status-3" class="mono">INACTIVE</td>
              <td id="score-reason-3">Immediate IP revocation and SOC security alert dispatch.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- BLOCK 5: LIVE AUDIT STREAM & FILTERING -->
<div class="dashboard-block" id="block-audit" data-block-id="block-audit" draggable="true">
  <div class="block-bar">
    <div style="display: flex; align-items: center; gap: 8px;">
      <span class="block-handle" title="Drag to reorder block">⠿</span>
      <span class="mono block-tag">BLOCK <span class="block-idx">05</span> // LIVE AUDIT STREAM & FILTERING</span>
    </div>
    <div class="block-actions">
      <button onclick="shiftBlock('block-audit', 'up')" class="btn-block-shift btn-shift-up" title="Shift block up">▲ Up</button>
      <button onclick="shiftBlock('block-audit', 'down')" class="btn-block-shift btn-shift-down" title="Shift block down">▼ Down</button>
    </div>
  </div>

  <!-- Live Audit Stream Table with Pagination & Groupings -->
  <div class="nv-card" id="tour-audit-stream">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 10px;">
      <div>
        <h3>Live Audit Stream (Chronological & Grouped)</h3>
        <p style="color: var(--nv-text-stone); font-size: 12px; margin-top: 2px;">In-flight failure events recorded on port 3000</p>
      </div>
      <!-- Grouping Selector -->
      <div style="display: flex; align-items: center; gap: 6px;">
        <span class="mono" style="font-size: 11px; color: var(--nv-text-stone);">GROUP BY:</span>
        <button onclick="setGroupBy('none')" id="grp-none" class="badge badge-green" style="padding: 4px 10px; cursor: pointer;">Flat</button>
        <button onclick="setGroupBy('target')" id="grp-target" class="badge badge-dark" style="padding: 4px 10px; cursor: pointer;">Target User</button>
        <button onclick="setGroupBy('ip')" id="grp-ip" class="badge badge-dark" style="padding: 4px 10px; cursor: pointer;">IP Address</button>
        <button onclick="setGroupBy('pattern')" id="grp-pattern" class="badge badge-dark" style="padding: 4px 10px; cursor: pointer;">Pattern</button>
      </div>
    </div>

    <!-- Search & Timestamp Filter Toolbar -->
    <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap;">
      <div style="flex: 1; min-width: 260px;">
        <input type="text" id="log-search-filter" oninput="applyLogFilter(this.value)" placeholder="🔍 Search logs by IP, User, Payload, HTTP status, or Timestamp..." style="margin: 0; padding: 7px 12px; font-size: 12px; font-family: var(--font-mono); background: var(--nv-black); border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius); width: 100%; color: var(--nv-text);" />
      </div>
      <div style="display: flex; align-items: center; gap: 6px;">
        <span class="mono" style="font-size: 11px; color: var(--nv-text-stone);">TIMESTAMPS:</span>
        <button onclick="setTimeFilter('all')" id="time-filter-all" class="badge badge-green" style="padding: 4px 10px; cursor: pointer;">All Recorded</button>
        <button onclick="setTimeFilter('recent')" id="time-filter-recent" class="badge badge-dark" style="padding: 4px 10px; cursor: pointer;">Last 60s</button>
        <button onclick="clearSearchFilter()" class="badge badge-dark" style="padding: 4px 10px; cursor: pointer;">✕ Reset Filter</button>
      </div>
    </div>

    <table id="log-table">
      <thead>
        <tr>
          <th style="width: 18%;">Timestamp</th>
          <th style="width: 15%;">IP Address</th>
          <th style="width: 18%;">Target User</th>
          <th style="width: 34%;">Attempted Payload</th>
          <th style="width: 15%;">HTTP Status</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>

    <!-- Pagination Toolbar -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--nv-hairline);">
      <div style="display: flex; align-items: center; gap: 10px;">
        <span class="mono" style="font-size: 12px; color: var(--nv-text-stone);">Rows per page:</span>
        <select id="page-size-select" onchange="changePageSize(this.value)" style="background: var(--nv-black); color: var(--nv-text); border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius); padding: 4px 8px; font-family: var(--font-mono); font-size: 12px;">
          <option value="10">10</option>
          <option value="15" selected>15</option>
          <option value="25">25</option>
          <option value="50">50</option>
        </select>
        <span class="mono" style="font-size: 12px; color: var(--nv-text-mute);" id="pagination-info">Showing 0 of 0</span>
      </div>
      <div style="display: flex; gap: 8px;">
        <button onclick="prevPage()" id="btn-prev" class="badge badge-dark" style="cursor: pointer; padding: 6px 12px;">← Previous</button>
        <button onclick="nextPage()" id="btn-next" class="badge badge-dark" style="cursor: pointer; padding: 6px 12px;">Next →</button>
      </div>
    </div>
  </div>
</div>

<!-- BLOCK 6: ARCHIFY PIPELINE ARCHITECTURE -->
<div class="dashboard-block" id="block-archify" data-block-id="block-archify" draggable="true">
  <div class="block-bar">
    <div style="display: flex; align-items: center; gap: 8px;">
      <span class="block-handle" title="Drag to reorder block">⠿</span>
      <span class="mono block-tag">BLOCK <span class="block-idx">06</span> // ARCHIFY PIPELINE ARCHITECTURE</span>
    </div>
    <div class="block-actions">
      <button onclick="shiftBlock('block-archify', 'up')" class="btn-block-shift btn-shift-up" title="Shift block up">▲ Up</button>
      <button onclick="shiftBlock('block-archify', 'down')" class="btn-block-shift btn-shift-down" title="Shift block down">▼ Down</button>
    </div>
  </div>

  <!-- Simplified Archify Architecture & Data Flow Card (Inline) -->
  <div class="nv-card" id="archify-architecture" style="border: 1px solid var(--nv-green);">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
      <div>
        <div style="display: flex; align-items: center; gap: 10px;">
          <h3 style="color: var(--nv-green); font-size: 18px; margin: 0;">ARCHIFY // SYSTEM ARCHITECTURE & DATA FLOW</h3>
          <span class="badge badge-green">LIVE PIPELINE</span>
        </div>
        <p style="color: var(--nv-text-stone); font-size: 13px; margin-top: 4px;">
          End-to-End Threat Detection, Dual AI Reasoning, and Closed-Loop SOAR Active Mitigation
        </p>
      </div>
      <div style="display: flex; gap: 8px;">
        <button onclick="scrollToTop()" class="badge badge-dark" style="cursor: pointer; padding: 4px 10px;">↑ Back to Top</button>
      </div>
    </div>

    <!-- 4-Stage Architecture Pipeline Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-bottom: 18px;">
      
      <!-- Stage 1 -->
      <div style="background: var(--nv-surface-soft); padding: 16px; border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
          <span class="mono" style="font-size: 11px; font-weight: 700; color: var(--nv-green);">01 // INGRESS & PROBES</span>
          <span class="badge badge-dark" style="font-size: 10px;">ACTOR LAYER</span>
        </div>
        <h4 style="font-size: 14px; margin-bottom: 6px; color: var(--nv-text);">Playwright & Client Requests</h4>
        <p class="mono" style="font-size: 11px; color: var(--nv-text-mute); line-height: 1.6; margin-bottom: 8px;">
          Automated multi-vector test harness and real user HTTP client requests.
        </p>
        <div class="mono" style="font-size: 10px; color: var(--nv-text-stone); background: var(--nv-black); padding: 6px 8px; border-radius: 2px;">
          Routes: /api/login, /api/simulate/sqli, /api/simulate/burst, /api/simulate/mfa-bomb
        </div>
      </div>

      <!-- Stage 2 -->
      <div style="background: var(--nv-surface-soft); padding: 16px; border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
          <span class="mono" style="font-size: 11px; font-weight: 700; color: var(--nv-green);">02 // SECURITY ENCLAVE</span>
          <span class="badge badge-green" style="font-size: 10px;">EXPRESS :3000</span>
        </div>
        <h4 style="font-size: 14px; margin-bottom: 6px; color: var(--nv-text);">Gateway & Telemetry Enclave</h4>
        <p class="mono" style="font-size: 11px; color: var(--nv-text-mute); line-height: 1.6; margin-bottom: 8px;">
          Enforces dynamic IP blacklist filter at gate. Maintains rolling 20-attempt window buffer in memory.
        </p>
        <div class="mono" style="font-size: 10px; color: var(--nv-text-stone); background: var(--nv-black); padding: 6px 8px; border-radius: 2px;">
          Action: Instant 403 on blacklisted IPs. Emits clean failure logs to evaluator.
        </div>
      </div>

      <!-- Stage 3 -->
      <div style="background: var(--nv-surface-soft); padding: 16px; border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
          <span class="mono" style="font-size: 11px; font-weight: 700; color: var(--nv-green);">03 // DUAL AI REASONING</span>
          <span class="badge badge-dark" style="font-size: 10px;">PARALLEL ENGINES</span>
        </div>
        <h4 style="font-size: 14px; margin-bottom: 6px; color: var(--nv-text);">Jev SystemOne vs Local Laya</h4>
        <p class="mono" style="font-size: 11px; color: var(--nv-text-mute); line-height: 1.6; margin-bottom: 8px;">
          • Jev Cloud (:443): Full encoder reasoning (~240ms)<br/>
          • Laya Local (:8000): Ultra-fast edge stub (~33ms)
        </p>
        <div class="mono" style="font-size: 10px; color: var(--nv-text-stone); background: var(--nv-black); padding: 6px 8px; border-radius: 2px;">
          Contracts: is_attack (noul), attack_type (choice), severity (score)
        </div>
      </div>

      <!-- Stage 4 -->
      <div style="background: var(--nv-surface-soft); padding: 16px; border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
          <span class="mono" style="font-size: 11px; font-weight: 700; color: var(--nv-green);">04 // SOAR CONTAINMENT</span>
          <span class="badge badge-red" style="font-size: 10px;">ACTIVE DEFENSE</span>
        </div>
        <h4 style="font-size: 14px; margin-bottom: 6px; color: var(--nv-text);">Closed-Loop Auto-Mitigation</h4>
        <p class="mono" style="font-size: 11px; color: var(--nv-text-mute); line-height: 1.6; margin-bottom: 8px;">
          When attack confidence &gt; 90% and severity &gt;= 2.0, dynamic blacklist engages for 15 minutes.
        </p>
        <div class="mono" style="font-size: 10px; color: var(--nv-text-stone); background: var(--nv-black); padding: 6px 8px; border-radius: 2px;">
          Result: Subsequent attacker probes return HTTP 403 Forbidden automatically.
        </div>
      </div>

    </div>

    <!-- Archify Reasoning Primitives Summary -->
    <div style="background: var(--nv-surface-soft); padding: 14px 16px; border: 1px solid var(--nv-hairline); border-radius: var(--nv-radius);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <h4 style="color: var(--nv-green); font-size: 13px; margin: 0;">ARCHIFY MULTI-QUESTION REASONING CONTRACT</h4>
        <span class="mono" style="font-size: 11px; color: var(--nv-text-stone);">ENCODER OUTPUT MAPPINGS</span>
      </div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px;">
        <div>
          <span class="mono" style="color: var(--nv-green); font-weight: 700; font-size: 12px;">1. is_attack (type: 'noul')</span>
          <p class="mono" style="font-size: 11px; color: var(--nv-text-stone); margin-top: 4px; line-height: 1.5;">
            Continuous scalar [0.0 → 1.0]. Calculates the mathematical probability that intercepted attempts reflect malicious automation rather than benign user typos.
          </p>
        </div>
        <div>
          <span class="mono" style="color: var(--nv-green); font-weight: 700; font-size: 12px;">2. attack_type (type: 'choice')</span>
          <p class="mono" style="font-size: 11px; color: var(--nv-text-stone); margin-top: 4px; line-height: 1.5;">
            Encoder classification: benign_retry, brute_force, credential_stuffing, sqli, xss, or mfa_exhaustion. Dispatches targeted mitigation rules.
          </p>
        </div>
        <div>
          <span class="mono" style="color: var(--nv-green); font-weight: 700; font-size: 12px;">3. severity (type: 'score')</span>
          <p class="mono" style="font-size: 11px; color: var(--nv-text-stone); margin-top: 4px; line-height: 1.5;">
            Threat impact grading [0.0 → 3.0]. Dynamic exploit rating (0.0 Informational → 3.0 Critical Breach). Threshold &gt;= 2.0 triggers SOAR IP containment.
          </p>
        </div>
      </div>
    </div>
  </div>
</div>
</div>

<script>
let allLogs = [];
let currentPage = 1;
let pageSize = 15;
let currentGroupBy = 'none';
let searchFilterText = '';
let timeFilterMode = 'all';
let selectedEngine = 'both';

function selectEngine(engine){
  selectedEngine = engine;
  ['jev', 'laya', 'both'].forEach(eng => {
    const btn = document.getElementById('engine-sel-' + eng);
    if (btn) btn.className = (eng === engine) ? 'badge badge-green' : 'badge badge-dark';
  });
  if (allLogs.length > 0) {
    ev(selectedEngine);
  }
}

function scrollToArchify(){
  const el = document.getElementById('archify-architecture');
  if (el) {
    el.scrollIntoView({ behavior: 'smooth' });
    el.style.borderColor = 'var(--nv-green)';
    el.style.boxShadow = '0 0 20px rgba(118, 185, 0, 0.4)';
    setTimeout(() => { el.style.boxShadow = 'none'; }, 2200);
  }
}

function toggleArchify(show){
  scrollToArchify();
}

function scrollToTop(){
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

const DEFAULT_BLOCK_ORDER = [
  'block-controls',
  'block-triage',
  'block-benchmark',
  'block-primitives',
  'block-audit',
  'block-archify'
];

function getCurrentBlockOrder(){
  const container = document.getElementById('dashboard-blocks-container');
  if (!container) return DEFAULT_BLOCK_ORDER.slice();
  const blocks = Array.from(container.children).filter(function(el){
    return el.classList && el.classList.contains('dashboard-block');
  });
  return blocks.map(function(b){ return b.id; });
}

function updateBlockButtons(){
  const container = document.getElementById('dashboard-blocks-container');
  if (!container) return;
  const blocks = Array.from(container.children).filter(function(el){
    return el.classList && el.classList.contains('dashboard-block');
  });
  blocks.forEach(function(b, idx){
    const tag = b.querySelector('.block-idx');
    if (tag) {
      tag.textContent = (idx + 1 < 10 ? '0' : '') + (idx + 1);
    }
    const upBtn = b.querySelector('.btn-shift-up');
    const downBtn = b.querySelector('.btn-shift-down');
    if (upBtn) upBtn.disabled = (idx === 0);
    if (downBtn) downBtn.disabled = (idx === blocks.length - 1);
  });
}

function shiftBlock(blockId, direction){
  const container = document.getElementById('dashboard-blocks-container');
  const block = document.getElementById(blockId);
  if (!container || !block) return;

  if (direction === 'up') {
    const prev = block.previousElementSibling;
    if (prev && prev.classList.contains('dashboard-block')) {
      container.insertBefore(block, prev);
    }
  } else if (direction === 'down') {
    const next = block.nextElementSibling;
    if (next && next.classList.contains('dashboard-block')) {
      container.insertBefore(next, block);
    }
  }

  block.style.boxShadow = '0 0 20px rgba(118, 185, 0, 0.45)';
  block.style.borderColor = 'var(--nv-green)';
  setTimeout(function(){
    block.style.boxShadow = 'none';
    block.style.borderColor = 'transparent';
  }, 1000);

  updateBlockButtons();
  saveBlockOrder();
}

function saveBlockOrder(){
  const order = getCurrentBlockOrder();
  try {
    localStorage.setItem('nv_dash_block_order', JSON.stringify(order));
  } catch (e) {}
}

function applyBlockOrder(order){
  const container = document.getElementById('dashboard-blocks-container');
  if (!container || !Array.isArray(order)) return;
  order.forEach(function(id){
    const el = document.getElementById(id);
    if (el && el.parentNode === container) {
      container.appendChild(el);
    }
  });
  updateBlockButtons();
}

function resetBlockOrder(){
  try {
    localStorage.removeItem('nv_dash_block_order');
  } catch (e) {}
  applyBlockOrder(DEFAULT_BLOCK_ORDER);
}

function initDragAndDrop(){
  const container = document.getElementById('dashboard-blocks-container');
  if (!container) return;

  let draggedBlock = null;

  container.addEventListener('dragstart', function(e){
    const block = e.target.closest('.dashboard-block');
    if (!block) return;
    draggedBlock = block;
    block.classList.add('dragging');
    if (e.dataTransfer) {
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', block.id);
    }
  });

  container.addEventListener('dragend', function(e){
    if (draggedBlock) {
      draggedBlock.classList.remove('dragging');
      draggedBlock = null;
    }
    const blocks = container.querySelectorAll('.dashboard-block');
    blocks.forEach(function(b){ b.classList.remove('drag-over'); });
    updateBlockButtons();
    saveBlockOrder();
  });

  container.addEventListener('dragover', function(e){
    e.preventDefault();
    const targetBlock = e.target.closest('.dashboard-block');
    if (!targetBlock || targetBlock === draggedBlock) return;

    const blocks = container.querySelectorAll('.dashboard-block');
    blocks.forEach(function(b){
      if (b !== targetBlock) b.classList.remove('drag-over');
    });
    targetBlock.classList.add('drag-over');
  });

  container.addEventListener('dragleave', function(e){
    const targetBlock = e.target.closest('.dashboard-block');
    if (targetBlock) targetBlock.classList.remove('drag-over');
  });

  container.addEventListener('drop', function(e){
    e.preventDefault();
    const targetBlock = e.target.closest('.dashboard-block');
    if (!targetBlock || targetBlock === draggedBlock) return;
    targetBlock.classList.remove('drag-over');

    const blocks = Array.from(container.children).filter(function(el){
      return el.classList.contains('dashboard-block');
    });
    const draggedIdx = blocks.indexOf(draggedBlock);
    const targetIdx = blocks.indexOf(targetBlock);

    if (draggedIdx < targetIdx) {
      container.insertBefore(draggedBlock, targetBlock.nextSibling);
    } else {
      container.insertBefore(draggedBlock, targetBlock);
    }

    updateBlockButtons();
    saveBlockOrder();
  });
}

function setGroupBy(mode){
  currentGroupBy = mode;
  ['none', 'target', 'ip', 'pattern'].forEach(m => {
    const btn = document.getElementById('grp-' + m);
    if (m === mode) { btn.className = 'badge badge-green'; }
    else { btn.className = 'badge badge-dark'; }
  });
  renderLogs();
}

function applyLogFilter(txt){
  searchFilterText = (txt || '').toLowerCase().trim();
  currentPage = 1;
  renderLogs();
}

function setTimeFilter(mode){
  timeFilterMode = mode;
  ['all', 'recent'].forEach(m => {
    const btn = document.getElementById('time-filter-' + m);
    if (btn) btn.className = (m === mode) ? 'badge badge-green' : 'badge badge-dark';
  });
  currentPage = 1;
  renderLogs();
}

function clearSearchFilter(){
  const inp = document.getElementById('log-search-filter');
  if (inp) inp.value = '';
  searchFilterText = '';
  timeFilterMode = 'all';
  ['all', 'recent'].forEach(m => {
    const btn = document.getElementById('time-filter-' + m);
    if (btn) btn.className = (m === 'all') ? 'badge badge-green' : 'badge badge-dark';
  });
  currentPage = 1;
  renderLogs();
}

function changePageSize(sz){
  pageSize = Number(sz) || 15;
  currentPage = 1;
  renderLogs();
}
function prevPage(){
  if (currentPage > 1) { currentPage--; renderLogs(); }
}
function nextPage(){
  const maxPage = Math.ceil(allLogs.length / pageSize) || 1;
  if (currentPage < maxPage) { currentPage++; renderLogs(); }
}

async function logs(){
  try {
    const r = await fetch('/api/logs?limit=200');
    allLogs = await r.json();
    document.getElementById('nav-log-count').innerText = allLogs.length + ' logs';
    renderLogs();
  } catch(e){}
}

function renderLogs(){
  const tbody = document.querySelector('#log-table tbody');
  const nowMs = Date.now();
  
  // Apply search & timestamp filtering
  const filtered = allLogs.filter(l => {
    if (timeFilterMode === 'recent') {
      const itemTs = l.timestamp || 0;
      if (itemTs && (nowMs - itemTs > 60000)) return false;
    }
    if (!searchFilterText) return true;
    const combined = ((l.time||'') + ' ' + (l.isoTime||'') + ' ' + (l.ip||'') + ' ' + (l.username||'') + ' ' + (l.attempted||'') + ' ' + (l.status||'') + ' ' + (l.mechanism||'')).toLowerCase();
    return combined.includes(searchFilterText);
  });

  const total = filtered.length;
  const maxPage = Math.max(1, Math.ceil(total / pageSize));
  if (currentPage > maxPage) currentPage = maxPage;
  
  const filterSuffix = searchFilterText ? ' [Filtered from ' + allLogs.length + ']' : '';
  document.getElementById('pagination-info').innerText = 'Showing Page ' + currentPage + ' of ' + maxPage + ' (' + total + ' total rows' + filterSuffix + ')';
  document.getElementById('btn-prev').disabled = currentPage <= 1;
  document.getElementById('btn-next').disabled = currentPage >= maxPage;

  if (currentGroupBy === 'none') {
    const start = (currentPage - 1) * pageSize;
    const pageItems = filtered.slice(start, start + pageSize);
    tbody.innerHTML = pageItems.length ? pageItems.map(l => formatRow(l)).join('') : '<tr><td colspan="5" class="mono" style="text-align:center; padding: 20px; color:var(--nv-text-stone);">No matching audit logs recorded</td></tr>';
  } else {
    // Grouping
    const groups = {};
    filtered.forEach(l => {
      let key = l.username;
      if (currentGroupBy === 'ip') key = l.ip;
      else if (currentGroupBy === 'pattern') {
        if (/(' OR 1=1|--|union)/i.test(l.attempted)) key = 'SQL Injection Vector';
        else if (/<script|javascript:/i.test(l.attempted)) key = 'XSS Script Injection';
        else if (l.attempted.length > 12) key = 'Long / Complex Guess';
        else key = 'Generic Credential Guess';
      }
      if (!groups[key]) groups[key] = [];
      groups[key].push(l);
    });

    let html = '';
    const entries = Object.entries(groups);
    if (!entries.length) {
      html = '<tr><td colspan="5" class="mono" style="text-align:center; padding: 20px; color:var(--nv-text-stone);">No matching audit logs recorded</td></tr>';
    } else {
      for (const [grpName, items] of entries) {
        html += '<tr style="background: rgba(118,185,0,0.08); font-weight:700;"><td colspan="5" style="color:var(--nv-green); padding: 8px 14px;">▸ ' + escapeHtml(grpName) + ' (' + items.length + ' events)</td></tr>';
        html += items.slice(0, 5).map(l => formatRow(l)).join('');
        if (items.length > 5) {
          html += '<tr><td colspan="5" class="mono" style="color:var(--nv-text-stone); font-size:11px; text-align:center;">... and ' + (items.length - 5) + ' more events in this group</td></tr>';
        }
      }
    }
    tbody.innerHTML = html;
  }
}

function formatRow(l){
  const isSpecial = /(' OR 1=1|<script|union)/i.test(l.attempted);
  const attemptHtml = isSpecial 
    ? '<span class="badge badge-red">' + escapeHtml(l.attempted) + '</span>'
    : escapeHtml(l.attempted);
  const isoStr = l.isoTime ? l.isoTime.slice(11, 23) : '';
  const timeCell = '<div class="mono" style="font-size:12px; color:#ffffff; font-weight:600;">' + escapeHtml(l.time) + '</div>' + 
                   (isoStr ? '<div class="mono" style="font-size:10px; color:var(--nv-text-stone);">' + isoStr + ' UTC</div>' : '');
  let statusBadge = '';
  if (l.status === '200') {
    statusBadge = '<span class="badge badge-green">200 OK (NORMAL USER)</span>';
  } else if (l.status === '401 (FLAGGED)' || l.flagged) {
    statusBadge = '<span class="badge badge-red">401 (ATTACK FLAGGED)</span>';
  } else if (l.status === '401') {
    statusBadge = '<span class="badge badge-dark">401 FAIL (RETRY)</span>';
  } else {
    statusBadge = '<span class="badge badge-red">' + escapeHtml(l.status) + '</span>';
  }
  return '<tr class="log-entry"><td>' + timeCell + '</td><td class="mono">' + escapeHtml(l.ip) + '</td><td>' + escapeHtml(l.username) + '</td><td class="mono">' + attemptHtml + '</td><td>' + statusBadge + '</td></tr>';
}

function escapeHtml(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
setInterval(logs, 1500); logs();
setInterval(checkSoar, 2000); checkSoar();

async function checkSoar(){
  try {
    const res = await fetch('/api/soar/status');
    const data = await res.json();
    const badge = document.getElementById('soar-status-badge');
    if (!badge) return;
    if (data.count > 0 && data.activeBlocks.length > 0) {
      const top = data.activeBlocks[0];
      badge.className = 'badge badge-red';
      badge.innerText = 'IP ' + top.ip + ' Blacklisted (TTL: 15m)';
    } else {
      badge.className = 'badge badge-green';
      badge.innerText = 'Status: Monitoring';
    }
  } catch(e){}
}

async function clearSoar(){
  await fetch('/api/soar/unblock', { method: 'POST' });
  await checkSoar();
}

async function sim(kind){
  if (kind === 'single') await fetch('/api/simulate-single', { method: 'POST' });
  else if (kind === 'burst') await fetch('/api/simulate-burst', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ n: 200 }) });
  else if (kind === 'spray') await fetch('/api/simulate/spray', { method: 'POST' });
  else if (kind === 'stuffing') await fetch('/api/simulate/stuffing', { method: 'POST' });
  else if (kind === 'sqli') await fetch('/api/simulate/sqli', { method: 'POST' });
  else if (kind === 'apikey') await fetch('/api/simulate/apikey-scan', { method: 'POST' });
  else if (kind === 'mfa') await fetch('/api/simulate/mfa-bomb', { method: 'POST' });
  await logs();
  await ev(selectedEngine);
}
async function mcp(){
  document.getElementById('mcp-hint').innerText = 'MCP: browser_snapshot -> browser_fill #login-pass x200 -> browser_click Log In. Generating burst…';
  await fetch('/api/simulate-burst', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ n: 200 }) });
  await logs();
  await ev(selectedEngine);
}
async function clearLogs(){
  await fetch('/api/clear-buffer', { method: 'POST' });
  await logs();
  document.getElementById('eval-desc').innerText = 'Description: waiting…';
  document.getElementById('eval-conf').innerText = 'Confidence: --%';
  document.getElementById('eval-status-indicator').innerText = 'READY FOR TRIAGE';
  ['jev', 'laya'].forEach(x => {
    const d = document.getElementById('eval-desc-' + x); if (d) d.innerText = '--';
    const c = document.getElementById('eval-conf-' + x); if (c) c.innerText = '--%';
    const l = document.getElementById('eval-lat-' + x); if (l) l.innerText = '--';
    const cd = document.getElementById('card-desc-' + x); if (cd) cd.innerText = 'Waiting for evaluation...';
    const cl = document.getElementById('card-lat-' + x); if (cl) cl.innerText = '-- ms';
    const cm = document.getElementById('card-meter-' + x); if (cm) cm.style.width = '0%';
  });
}
async function ev(e){
  const banner = document.getElementById('eval-banner-card');
  document.getElementById('eval-desc').innerText = 'Description: running ' + e + '…';
  document.getElementById('eval-status-indicator').innerText = 'INFERENCE RUNNING...';
  
  try {
    const r = await fetch('/api/evaluate?engine=' + e, { method: 'POST' });
    const d = await r.json();
    document.getElementById('eval-status-indicator').innerText = 'EVALUATION COMPLETE';

    const show = (p, x) => {
      document.getElementById('eval-desc-' + x).innerText = p.description;
      document.getElementById('eval-conf-' + x).innerText = p.confidence + '%';
      document.getElementById('eval-lat-' + x).innerText = p.latency_ms + 'ms';
      
      const cardDesc = document.getElementById('card-desc-' + x);
      const cardLat = document.getElementById('card-lat-' + x);
      const cardMeter = document.getElementById('card-meter-' + x);
      if (cardDesc) cardDesc.innerText = p.description;
      if (cardLat) cardLat.innerText = p.latency_ms + ' ms';
      if (cardMeter) {
        cardMeter.style.width = Math.min(Math.max(p.confidence, 15), 100) + '%';
        cardMeter.style.background = p.is_attack > 0.8 ? 'var(--nv-error)' : 'var(--nv-green)';
      }
    };
    if (d.jev) {
      show(d.jev, 'jev');
      const bJev = document.getElementById('bench-lat-jev');
      if (bJev) bJev.innerText = d.jev.latency_ms + ' ms';
    }
    if (d.laya) {
      show(d.laya, 'laya');
      const bLaya = document.getElementById('bench-lat-laya');
      if (bLaya) bLaya.innerText = d.laya.latency_ms + ' ms';
    }
    const first = d.jev || d.laya;
    if (first) {
      document.getElementById('eval-desc').innerText = 'Description: ' + first.description;
      document.getElementById('eval-conf').innerText = 'Confidence: ' + first.confidence + '%';
    }
    updateReasoningPrimitives(d);
    await checkSoar();
  } catch(err) {
    document.getElementById('eval-status-indicator').innerText = 'ERROR';
  }
}

function switchPrimitiveView(view){
  ['noul', 'choice', 'score'].forEach(p => {
    const el = document.getElementById('section-primitive-' + p);
    if (el) el.style.display = (view === 'all' || view === p) ? 'block' : 'none';
  });
  ['all', 'noul', 'choice', 'score'].forEach(t => {
    const btn = document.getElementById('prim-tab-' + t);
    if (btn) btn.className = (t === view) ? 'badge badge-green' : 'badge badge-dark';
  });
}

function togglePrimitiveDropdown(sec){
  const el = document.getElementById('wrap-primitive-' + sec);
  const btn = document.getElementById('btn-toggle-' + sec);
  if (!el) return;
  const isClosed = el.style.display === 'none';
  el.style.display = isClosed ? 'block' : 'none';
  if (btn) btn.innerHTML = isClosed ? '▾ In-Depth Details' : '▸ In-Depth Details';
}

function toggleAllPrimitives(expand){
  ['noul', 'choice', 'score'].forEach(sec => {
    const el = document.getElementById('wrap-primitive-' + sec);
    const btn = document.getElementById('btn-toggle-' + sec);
    if (el) el.style.display = expand ? 'block' : 'none';
    if (btn) btn.innerHTML = expand ? '▾ In-Depth Details' : '▸ In-Depth Details';
  });
}

function updateReasoningPrimitives(d){
  if (!d) return;
  const v = d.jev || d.laya;
  if (!v) return;
  const st = d.state || {};
  const isAtk = (v.is_attack > 0.8);
  const atkType = v.attack_type || 'benign_retry';
  const threatCat = v.threat_category || (atkType === 'sqli' ? 'sqli_attempt' : atkType);
  const prob = (typeof v.is_attack === 'number') ? v.is_attack : (isAtk ? 0.98 : 0.16);
  const sev = typeof v.severity === 'number' ? v.severity : (isAtk ? 2.5 : 0.4);

  // 1. Neoul
  const noulTag = document.getElementById('noul-verdict-tag');
  if (noulTag) {
    noulTag.innerText = isAtk ? 'STATUS: ATTACK DETECTED (p = ' + prob.toFixed(3) + ')' : 'STATUS: MONITORING (p = ' + prob.toFixed(3) + ')';
    noulTag.style.color = isAtk ? 'var(--nv-error)' : 'var(--nv-green)';
  }
  const nAtt = document.getElementById('noul-val-attempts');
  if (nAtt) nAtt.innerText = (st.failed_attempts || 0) + ' in 60s';
  const nStatAtt = document.getElementById('noul-status-attempts');
  if (nStatAtt) {
    if ((st.failed_attempts || 0) >= 8) nStatAtt.innerHTML = '<span class="badge badge-red">FLOOD</span>';
    else if ((st.failed_attempts || 0) >= 3) nStatAtt.innerHTML = '<span class="badge badge-yellow">ELEVATED</span>';
    else nStatAtt.innerHTML = '<span class="badge badge-green">NORMAL</span>';
  }
  const nReasAtt = document.getElementById('noul-reason-attempts');
  if (nReasAtt) {
    if ((st.failed_attempts || 0) >= 8) nReasAtt.innerText = 'Volume exceeds burst flood threshold (≥8). Machine-speed density.';
    else if ((st.failed_attempts || 0) >= 3) nReasAtt.innerText = 'Failure count exceeds single-user threshold (≥3). Recon / spray pattern.';
    else nReasAtt.innerText = 'Volume remains within expected human retry limits (≤2).';
  }

  const tel = st.telemetry_summary;
  const nTel = document.getElementById('noul-val-telemetry');
  if (nTel) {
    if (tel && tel.samples_analyzed > 0) nTel.innerText = tel.avg_mouse_distance_px + 'px / ' + tel.avg_form_duration_ms + 'ms';
    else nTel.innerText = '0px / Headless';
  }
  const nStatTel = document.getElementById('noul-status-telemetry');
  if (nStatTel) {
    if (tel && tel.is_synthetic_bot) nStatTel.innerHTML = '<span class="badge badge-red">SYNTHETIC BOT</span>';
    else if (tel && tel.samples_analyzed > 0) nStatTel.innerHTML = '<span class="badge badge-green">HUMAN</span>';
    else nStatTel.innerHTML = '<span class="badge badge-dark">HEADLESS SCRIPT</span>';
  }
  const nReasTel = document.getElementById('noul-reason-telemetry');
  if (nReasTel) {
    if (tel && tel.is_synthetic_bot) nReasTel.innerText = '0px cursor travel with instantaneous form fill detects automation.';
    else if (tel && tel.samples_analyzed > 0) nReasTel.innerText = 'Natural kinetic mouse trajectory and human keystroke intervals.';
    else nReasTel.innerText = 'Direct programmatic invocation lacking browser interaction telemetry.';
  }

  const nProb = document.getElementById('noul-val-prob');
  if (nProb) {
    nProb.innerText = prob.toFixed(3);
    nProb.style.color = isAtk ? 'var(--nv-error)' : 'var(--nv-green)';
  }
  const nStatProb = document.getElementById('noul-status-prob');
  if (nStatProb) {
    nStatProb.innerHTML = isAtk ? '<span class="badge badge-red">ATTACK</span>' : '<span class="badge badge-green">BENIGN</span>';
  }
  const nReasProb = document.getElementById('noul-reason-prob');
  if (nReasProb) {
    nReasProb.innerText = isAtk ? 'Calculated probability ' + prob.toFixed(3) + ' exceeds 0.800 decision boundary; confirmed threat.' : 'Belief probability ' + prob.toFixed(3) + ' below 0.800 threshold; classified as normal retry.';
  }

  // 2. Choice
  const choiceTag = document.getElementById('choice-winner-tag');
  if (choiceTag) {
    choiceTag.innerText = 'SELECTED: ' + (threatCat || atkType).toUpperCase();
    choiceTag.style.color = isAtk ? 'var(--nv-error)' : 'var(--nv-green)';
  }
  const cats = [
    { id: 'sqli', test: (atkType === 'sqli' || threatCat === 'sqli_attempt'), reas: 'SQL metacharacters, OR 1=1 tautology, or UNION injection matched in buffer.' },
    { id: 'spray', test: (atkType === 'password_spray' || threatCat === 'password_spray'), reas: 'Single password tested across ' + (st.unique_users_count || 'multiple') + ' distinct usernames.' },
    { id: 'stuffing', test: (atkType === 'credential_stuffing' || threatCat === 'credential_stuffing'), reas: 'Breach credential combos matched known dump format.' },
    { id: 'brute', test: (atkType === 'brute_force' || threatCat === 'brute_force'), reas: 'High volume rapid flood (' + (st.failed_attempts || 0) + ' attempts) against victim.' },
    { id: 'benign', test: (!isAtk || atkType === 'benign_retry' || threatCat === 'benign_login'), reas: 'Isolated single-user typo consistent with genuine user authentication.' }
  ];
  cats.forEach(c => {
    const stEl = document.getElementById('choice-status-' + c.id);
    const cfEl = document.getElementById('choice-conf-' + c.id);
    const reEl = document.getElementById('choice-reason-' + c.id);
    if (stEl) stEl.innerHTML = c.test ? (c.id === 'benign' ? '<span class="badge badge-green">MATCHED</span>' : '<span class="badge badge-red">MATCHED</span>') : 'NO MATCH';
    if (cfEl) cfEl.innerText = c.test ? v.confidence + '%' : '--';
    if (reEl && c.test) reEl.innerText = c.reas;
    const row = stEl ? stEl.closest('tr') : null;
    if (row) row.style.background = c.test ? (c.id === 'benign' ? 'rgba(118,185,0,0.06)' : 'rgba(229,32,32,0.08)') : 'transparent';
  });

  // 3. Score
  const scoreTag = document.getElementById('score-val-tag');
  const sevLabel = sev >= 2.6 ? 'EXPLOIT' : (sev >= 2.0 ? 'ATTACK FLOOD' : (sev >= 1.0 ? 'SUSPICIOUS' : 'HARMLESS'));
  if (scoreTag) {
    scoreTag.innerText = 'SCORE: ' + sev.toFixed(1) + ' / 3.0 (' + sevLabel + ')';
    scoreTag.style.color = sev >= 2.0 ? 'var(--nv-error)' : (sev >= 1.0 ? 'var(--nv-yellow, #e6a700)' : 'var(--nv-green)');
  }
  const activeLevel = sev >= 2.6 ? 3 : (sev >= 2.0 ? 2 : (sev >= 1.0 ? 1 : 0));
  [0, 1, 2, 3].forEach(lvl => {
    const stEl = document.getElementById('score-status-' + lvl);
    const reEl = document.getElementById('score-reason-' + lvl);
    const isActive = (lvl === activeLevel);
    if (stEl) {
      if (isActive) {
        if (lvl === 0) stEl.innerHTML = '<span class="badge badge-green">ACTIVE</span>';
        else if (lvl === 1) stEl.innerHTML = '<span class="badge badge-yellow">ACTIVE</span>';
        else stEl.innerHTML = '<span class="badge badge-red">ACTIVE</span>';
      } else {
        stEl.innerText = 'INACTIVE';
      }
    }
    const row = stEl ? stEl.closest('tr') : null;
    if (row) row.style.background = isActive ? (lvl === 0 ? 'rgba(118,185,0,0.06)' : 'rgba(229,32,32,0.08)') : 'transparent';
  });
}

function startTour(force){
  if (typeof window.driver === 'undefined') return;
  if (navigator.webdriver && !force) return;
  const hasSeen = localStorage.getItem('has_seen_onboarding');
  if (hasSeen && !force) return;

  const driverObj = window.driver.js.driver({
    showProgress: true,
    animate: true,
    steps: [
      {
        element: '#tour-brand',
        popover: {
          title: 'NVIDIA Cyber Defense',
          description: 'Welcome to the Dual-Engine Security Simulation & Triage Command Center.',
          side: 'bottom'
        }
      },
      {
        element: '#tour-generators',
        popover: {
          title: 'Simulation Generators',
          description: 'Inject 1 single benign retry, burst flood 200 attempts, or trigger the Playwright MCP agent.',
          side: 'bottom'
        }
      },
      {
        element: '#tour-eval-dispatch',
        popover: {
          title: 'Dual Engine Inference',
          description: 'Evaluate the top 20 windowed audit attempts simultaneously against Jev Cloud and local Laya.',
          side: 'left'
        }
      },
      {
        element: '#tour-dual-engine',
        popover: {
          title: 'Side-by-Side Model Matrix',
          description: 'Compare classification verdicts, attack severity (0-3), confidence metrics, and millisecond latency.',
          side: 'top'
        }
      },
      {
        element: '#tour-audit-stream',
        popover: {
          title: 'Audit Stream, Groupings & Pagination',
          description: 'Explore live intercepted attempts. Switch grouping modes (by Target, IP, or Pattern) and paginate.',
          side: 'top'
        }
      },
      {
        element: '#archify-architecture',
        popover: {
          title: 'Archify Architecture Explorer',
          description: 'Live interactive pipeline diagram showing data flow from client ingress through Express gateway, dual AI triage, and SOAR mitigation.',
          side: 'top'
        }
      }
    ],
    onDestroyStarted: () => {
      localStorage.setItem('has_seen_onboarding', 'true');
      driverObj.destroy();
    }
  });

  driverObj.drive();
}

window.addEventListener('DOMContentLoaded', () => {
  try {
    const saved = localStorage.getItem('nv_dash_block_order');
    if (saved) {
      applyBlockOrder(JSON.parse(saved));
    } else {
      updateBlockButtons();
    }
  } catch (e) {
    updateBlockButtons();
  }
  initDragAndDrop();
  setTimeout(() => startTour(false), 800);
});
</script></body></html>`));

app.get('/health', (req, res) => res.json({ ok: true, logs: auditLogs.length, hasKey: !!API_KEY }));
app.listen(APP_PORT, () => console.log(`App on http://localhost:${APP_PORT}`));
