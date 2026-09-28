# Backend Architecture & API Contracts

## Service Overview

- **Main App**: Node.js + Express on `http://localhost:3000`
- **Laya Stub**: Node.js + Express on `http://localhost:8000`
- **Jev Cloud**: `https://api.typesafe.ai/v1/systemone` (configured via `TYPESAFE_API_KEY` in `.env`)
- **Fallback Engine**: In-memory deterministic heuristic engine for offline or unauthenticated operation.
- **SOAR Active Defense**: Automated inline IP containment with dynamic 15-minute TTL blocklist.

---

## Endpoints (`server.js`)

### 1. Multi-Mechanism Authentication APIs (with SOAR Protection)

#### A. Password-Based
* `POST /api/auth/password/signup` (Alias: `POST /api/signup`)
  - Middleware: `soarGuard`
  - Body: `{ username: string, password: string, hint?: string }`
  - Response: `{ success: true, message: string }`
  - State: In-memory `users` map (`username -> { password, hint }`). No log generated on signup.

* `POST /api/auth/password/login` (Alias: `POST /api/login`)
  - Middleware: `soarGuard` (returns `403 Forbidden` if client IP is blacklisted)
  - Body: `{ username: string, password: string, telemetry?: { keystrokeDeltas: number[], mouseDistanceMoved: number, totalFormTimeMs: number } }`
  - Response (200 - Legitimate Normal User): `{ success: true, role: "normal_user", message: "Authenticated as Normal User", redirect: "/user-dashboard?user=..." }`
  - Response (401 - Normal User Retry, < 5 failures): `{ success: false, flagged: false, error: "Invalid credentials (attempt X of 5)", failures: X, limit: 5, hint: string }`
  - Response (401 - Brute Force Attack Flagged, >= 5 failures): `{ success: false, flagged: true, error: "Brute Force Attack Detected: Exceeded limit of 5 attempts. Account flagged.", failures: X, limit: 5, hint: string }`
  - Response (403 - SOAR Block): `{ error: "Forbidden: IP Blacklisted by SOAR Active Defense", ip: string, reason: string, confidence: number, expiresInSeconds: number, status: "blocked" }`
  - Logging:
    - On 200: Prepends entry with `{ status: '200', mechanism: 'password', role: 'normal_user', classification: 'Normal User (Legitimate)', is_attack: false }`.
    - On 401 (< 5): Prepends entry with `{ status: '401', mechanism: 'password', classification: 'Normal User Retry (X/5)', flagged: false, is_attack: false }`.
    - On 401 (>= 5): Prepends entry with `{ status: '401 (FLAGGED)', mechanism: 'password', classification: 'Brute Force Attack (X failed attempts)', flagged: true, is_attack: true, confidence: 0.98 }`.

#### B. Machine API Key Authentication
* `POST /api/auth/apikey/generate`
  - Body: `{ username: string }`
  - Response (200): `{ success: true, username: string, apiKey: "nv_sec_..." }`
  - State: Stores key in `apiKeys` Map with timestamp.

* `POST /api/auth/apikey/verify`
  - Middleware: `soarGuard`
  - Headers: `x-api-key: nv_sec_...` (or Body: `{ apiKey: string }`)
  - Response (200): `{ success: true, authenticated: true, username: string, role: "service_account" }`
  - Response (401): `{ success: false, error: "Invalid or revoked API key" }`
  - Logging: Prepend audit entry with `mechanism: 'api_key'` on invalid key.

#### C. Step-Up MFA / OTP Authentication
* `POST /api/auth/mfa/send-otp`
  - Body: `{ username: string }`
  - Response (200): `{ success: true, message: "OTP dispatched", codePreview: "123456" }`
  - State: In-memory 6-digit code with 5-minute TTL.

* `POST /api/auth/mfa/verify-otp`
  - Middleware: `soarGuard`
  - Body: `{ username: string, code: string }`
  - Response (200): `{ success: true, message: "MFA verified", session: "mfa_token_..." }`
  - Response (401): `{ success: false, error: "Invalid or expired OTP" }`
  - Logging: Prepend audit entry with `mechanism: 'otp'` on mismatch.

---

### 2. Closed-Loop SOAR Active Defense Endpoints

* `GET /api/soar/status`
  - Response: `{ count: number, activeBlocks: [ { ip, blockedAt, expiresAt, reason, confidence, engine, remainingSec } ] }`

* `POST /api/soar/block`
  - Body: `{ ip: string, reason?: string, ttlMs?: number }`
  - Response: `{ success: true, ip: string, expiresAt: number, ttlMs: number }`

* `POST /api/soar/unblock`
  - Body: `{ ip?: string }` (if IP omitted, clears entire blocklist)
  - Response: `{ success: true, cleared: string }`

* `POST /api/soar/clear`
  - Response: `{ success: true, cleared: "all" }`

---

### 3. Live Audit Logs & Threat Simulation Endpoints

* `GET /api/logs?limit=200`
  - Query: `limit` (default: 200)
  - Response: Array of log entries `[ { time, ip, username, attempted, status, mechanism, telemetry } ]`.

* `POST /api/clear-buffer`
  - Response: `{ success: true, cleared: true }`
  - Clears in-memory `auditLogs` for benchmark isolation.

* `POST /api/simulate-single`
  - Generates 1 failed attempt entry for target `Utkarsh` (triggers `benign_retry`).

* `POST /api/simulate-burst`
  - Body: `{ n?: number, target?: string }` (default `n=200`, `target='Utkarsh'`; `n=0` clears buffer)
  - Rapid flood of brute force attempts against a single victim.

* `POST /api/simulate/spray`
  - Body: `{ password?: string, count?: number }`
  - Simulates horizontal password spraying using 1 password against corporate user targets.

* `POST /api/simulate/stuffing`
  - Body: `{ count?: number }`
  - Simulates slow-and-low credential stuffing using leaked credential pairs from public breach lists.

* `POST /api/simulate/sqli`
  - Body: `{ target?: string, count?: number }`
  - Injects SQL authentication bypass probes (`' OR 1=1 LIMIT 1--`, `' UNION SELECT ...`).

* `POST /api/simulate/apikey-scan`
  - Body: `{ count?: number }`
  - Emulates an automated token scanner fuzzing forged API keys (`nv_sec_fuzz_*`).

* `POST /api/simulate/mfa-bomb`
  - Body: `{ target?: string, count?: number }`
  - Emulates rapid MFA exhaustion bombardment cycling 6-digit OTP codes.

---

### 4. AI Security Evaluation & Multi-Question Classification

* `POST /api/evaluate?engine=jev|laya|both`
  - Analyzes top 20 windowed audit entries (`failed_attempts`, `unique_users_count`, `unique_ips_count`, `auth_mechanisms`, `samples`, `telemetry_summary`).
  - Evaluates multi-question SystemOne payload:
    ```json
    {
      "questions": {
        "is_threat": { "type": "noul", "instructions": "Is this request anomalous or adversarial?" },
        "is_attack": { "type": "noul", "instructions": "Does state indicate attack?" },
        "threat_category": {
          "type": "choice",
          "options": ["benign_login", "brute_force", "sqli_attempt", "credential_stuffing"]
        },
        "attack_type": { "type": "choice" },
        "severity": { "type": "score" }
      }
    }
    ```
  - **SOAR Active Defense Hook**: When confidence >= 90% and attack detected, automatically blacklists offending IP for 15 minutes.
  - Returns:
    ```json
    {
      "state": {
        "failed_attempts": 10,
        "window_seconds": 60,
        "ip": "192.168.1.105",
        "telemetry_summary": {
          "is_synthetic_bot": true,
          "samples_analyzed": 10,
          "avg_mouse_distance_px": 0,
          "avg_form_duration_ms": 320
        }
      },
      "jev": { "engine": "jev", "attack_type": "brute_force", "threat_category": "brute_force", "is_attack": 0.968, "severity": 2.5, "confidence": 96.8, "latency_ms": 230 },
      "laya": { "engine": "laya", "attack_type": "brute_force", "threat_category": "brute_force", "is_attack": 0.968, "severity": 2.5, "confidence": 96.8, "latency_ms": 33 },
      "soar": {
        "mitigatedIp": "192.168.1.105",
        "activeBlocksCount": 1,
        "activeBlocks": [ ... ]
      }
    }
    ```

* `GET /health`
  - Returns: `{ ok: true, logs: number, hasKey: boolean }`

---

## Laya Stub (`http://localhost:8000`)

* `POST /v1/systemone`
  - Mirrors Jev SystemOne multi-question contract in a single forward pass:
    - Answers `is_threat` (`noul`), `is_attack` (`noul`), `threat_category` (`choice`), `attack_type` (`choice`), and `severity` (`score`).
* `GET /health`
  - Returns: `{ ok: true, stub: "laya" }`

---

## 3. Decision Reasoning Primitives Schema & UI Mapping

The security dashboard integrates three dedicated reasoning tables explaining the audit evidence and threshold checks behind AI decisions:

1. **Section `neoul` (Continuous Probability Likelihood)**:
   - Evaluates:
     - `failed_attempts` within the 60s audit window against burst thresholds ($\ge 3$ spray, $\ge 8$ flood).
     - Client Behavioral Telemetry (`avg_mouse_distance_px` and `avg_form_duration_ms`).
     - Continuous belief probability `is_attack` / `is_threat` against decision threshold ($>0.800$).
   - Output element: `#table-primitive-noul`.

2. **Section `choice` (Adversary Tactic Selection)**:
   - Compares candidate threat categories: `sqli_attempt`, `password_spray`, `credential_stuffing`, `brute_force`, `benign_login`.
   - Displays criteria match status (`MATCHED` vs `NO MATCH`), confidence %, and explanatory reasoning.
   - Output element: `#table-primitive-choice`.

3. **Section `score` (Exploit Risk Severity)**:
   - Evaluates severity score across tiers:
     - **Level 0 (0.0 - 0.9)**: Harmless user typo.
     - **Level 1 (1.0 - 1.9)**: Suspicious reconnaissance / probing.
     - **Level 2 (2.0 - 2.5)**: Attack flood / password spray (triggers dynamic blocklist if confidence $\ge 90\%$).
     - **Level 3 (2.6 - 3.0)**: High exploit risk (SQLi, token compromise).
   - Output element: `#table-primitive-score`.

---

## 4. Live Audit Stream & Search Filtering

All audit events generated by login attempts or simulation endpoints are stamped via `pushLog()`:
- `time`: Local human-readable clock string (`HH:MM:SS`).
- `timestamp`: Unix epoch millisecond timestamp (`Date.now()`).
- `isoTime`: Standard ISO 8601 UTC string (`YYYY-MM-DDTHH:mm:ss.sssZ`).

The frontend `#tour-audit-stream` provides:
- Live text filtering across IP, user, payload, status, and timestamp substrings (`#log-search-filter`).
- Timestamp range selection: `All Recorded` vs `Last 60s` (`#time-filter-recent`).
- Dual-line timestamp formatting: primary clock display with secondary ISO UTC offset.


