# NVIDIA Cyber Command

An attack simulation and automated defense system that compares remote cloud AI with a local edge model on live credential attacks.

Most security dashboards tell you that you were attacked half an hour after it happened. This system cuts the delay. It runs incoming requests through client telemetry, scores the traffic with two different AI models, and automatically blocks attacking IP addresses in less than one millisecond.

![Security Command Center](images/security-dashboard.png)

---

## System architecture

```
               [ Client Browser / Attack Script ]
                               │
            ┌──────────────────┴──────────────────┐
            │ Ingress Layer (/login, /signup)     │
            │ • Biometric Telemetry (mouse, keys) │
            │ • Password eye toggle & auth tabs   │
            └──────────────────┬──────────────────┘
                               │
            ┌──────────────────▼──────────────────┐
            │ Layer 1: Ingress Attempt Gate       │
            │ • Check credentials vs user store   │
            │ • < 5 fails: Benign retry (401)     │
            │ • >= 5 fails: Brute force flag      │
            └──────────────────┬──────────────────┘
                               │
            ┌──────────────────▼──────────────────┐
            │ Layer 2: Sliding Audit Window       │
            │ • Rolling 20-event memory buffer    │
            │ • In-memory IP/user state tracking  │
            └──────────────────┬──────────────────┘
                               │
         ┌─────────────────────┴─────────────────────┐
         ▼                                           ▼
┌───────────────────────────────┐   ┌───────────────────────────────┐
│ Layer 3A: Jev SystemOne Cloud │   │ Layer 3B: Laya Local Engine   │
│ • HTTPS endpoint              │   │ • Localhost port 8000         │
│ • Latency: ~240ms             │   │ • Latency: ~33ms (7x faster)  │
│ • Cross-user correlation      │   │ • Zero data egress            │
└───────────────┬───────────────┘   └───────────────┬───────────────┘
                │                                   │
                └─────────────────┬─────────────────┘
                                  │
            ┌─────────────────────▼─────────────────────┐
            │ Layer 4: Mathematical Decision Primitives │
            │ • neoul: Continuous threat probability    │
            │ • choice: Categorical tactic taxonomy     │
            │ • score: Exploit severity (0.0 to 3.0)    │
            └─────────────────────┬─────────────────────┘
                                  │
            ┌─────────────────────▼─────────────────────┐
            │ Layer 5: SOAR Closed-Loop Mitigation      │
            │ • Threat confidence >= 90%                │
            │ • Add IP to dynamic 15-minute blocklist   │
            │ • soarGuard returns immediate 403 status  │
            └───────────────────────────────────────────┘
```

---

## What SOAR stands for

**SOAR** stands for **Security Orchestration, Automation, and Response**.

Traditional security dashboards only alert a human engineer. SOAR lets software block the attacker automatically.

* **Security Orchestration:** Connects the Express login gateway, the AI evaluation models, and the network blocklist into one automated pipeline.
* **Automation:** Triggers detection playbooks immediately when rapid failures or attack payloads appear, without waiting for human clicks.
* **Response:** Cuts off the attacker. When threat confidence reaches 90% or higher, the server blacklists the IP for 15 minutes and returns `403 Forbidden` on every subsequent request.

Mitigation time drops from 30 minutes of human review down to less than one millisecond.

---

## How the layers work

### Layer 1. Client telemetry and bot detection

The login form records client biometrics before sending credentials to the server.

* `keystrokeDeltas`: Measures time between key presses in milliseconds. Real humans type with uneven delays.
* `mouseDistanceMoved`: Calculates total pixel travel of the mouse pointer.
* `totalFormTimeMs`: Tracks time spent on the page before submit.

When a script sends requests via curl or Playwright without simulating mouse movement, the distance stays 0px and form duration stays under 500ms. The backend flags this as `is_synthetic_bot: true`.

![Authentication Gateway](images/auth-gateway.png)

### Layer 2. Authentication rules and brute force threshold

The login and signup pages are completely separate routes:

* `/signup`: Lets a user set up an account, a password, and a recovery hint. Once submitted, it forwards the user to `/login`.
* `/login`: Contains password login, machine API key verification, and MFA OTP inputs. Both password inputs have an SVG eye button to view or hide plaintext passwords.

The server enforces an attempt limit:

* Correct password: Resets failure counts, records a `200` status in the audit table, and opens `/user-dashboard` with a `ROLE: NORMAL USER (LEGITIMATE)` badge.
* Fewer than 5 mistakes: Treated as human error. Shows an `Invalid credentials` message and reveals the recovery hint on attempt 3.
* 5 or more mistakes: The account gets flagged as an active brute force attack. The UI shows a red warning and the audit log records a `401 (ATTACK FLAGGED)` entry.

![Legitimate User Dashboard](images/user-dashboard.png)

### Layer 3. Dual model comparison

The platform benchmarks two different AI setups on the exact same traffic window:

1. **Jev SystemOne (Cloud).** Calls `https://api.typesafe.ai/v1/systemone` over HTTPS. It has deep reasoning over multi-step spray patterns, but network round-trips take around 240ms.
2. **Laya Stub (Local Edge).** Runs on `http://localhost:8000`. It processes requests locally in about 33ms, which is 7 times faster than the cloud call. No customer data leaves the machine.

If the remote Jev API key is missing, the server falls back to an internal heuristic engine. Demos and tests never fail due to an unreachable third-party API.

![Dual Engine Triage and Verdict](images/dual-engine-triage.png)

### Layer 4. Mathematical decision tables

Instead of free-form text output, the models respond with three typed fields:

![Decision Reasoning Primitives](images/reasoning-primitives.png)

* **neoul (continuous probability).** A floating point number between 0.0 and 1.0. A value above 0.800 marks the traffic as an active attack.
* **choice (categorical classification).** Selects one attack label from `sqli_attempt`, `password_spray`, `credential_stuffing`, `brute_force`, or `benign_login`.
* **score (exploit risk).** Rates danger on a scale from 0.0 to 3.0. Level 0 is harmless, Level 1 is suspicious reconnaissance, Level 2 is an attack flood, and Level 3 is a direct exploit like SQL injection.

### Layer 5. Closed-loop SOAR mitigation

When an evaluation returns an attack confidence of 90% or higher, the system takes containment action:

1. The offending IP is added to the in-memory blocklist with a 15-minute time-to-live.
2. The `soarGuard` middleware checks every request before it hits auth routes. Blocked IPs get an immediate `403 Forbidden` response.
3. The dashboard badge switches to red: `IP <ip> Blacklisted (TTL: 15m)`.
4. An operator can click the Unblock All button at any time to clear the blocklist manually.

---

## Benchmark summary

| Metric | Jev SystemOne (Cloud) | Laya (Local Edge) | Note |
| :--- | :--- | :--- | :--- |
| Latency | ~240ms | ~33ms | Local model is 7x faster |
| Data privacy | Leaves network via TLS | Stays on localhost | Edge has zero data egress |
| Cost | Per-token API cost | Free local compute | Edge runs on host hardware |
| Reasoning | Handles complex spray chains | Typed classification | Cloud handles wider context |

---

## Supported attack simulations

The dashboard includes buttons to test different attack patterns:

| Attack | Pattern | Severity | Typical category |
| :--- | :--- | :--- | :--- |
| 1 User | Single typo from a normal user | 0.4 / 3.0 | benign_login |
| Brute Force | 200 rapid guesses targeting one account | 2.5 / 3.0 | brute_force |
| Password Spray | 1 common password tried across 10 corporate accounts | 2.4 / 3.0 | credential_stuffing |
| Credential Stuffing | Leaked username and password pairs | 2.4 / 3.0 | credential_stuffing |
| SQLi Bypass | Injection strings like `' OR '1'='1 --` and `UNION SELECT` | 2.9 / 3.0 | sqli_attempt |
| API Key Scan | High-frequency cycling of forged `nv_sec_...` tokens | 2.4 / 3.0 | credential_stuffing |
| MFA Bombing | Flooding 6-digit OTP codes against an account | 2.5 / 3.0 | brute_force |

---

## Local machine setup

### Prerequisites

* Node.js v18 or newer
* npm

### Step 1. Clone and install dependencies

```bash
git clone https://github.com/your-username/JEV_AI_TESTING.git
cd JEV_AI_TESTING
npm install
```

### Step 2. Configure environment (optional)

Create a `.env` file in the project root:

```env
TYPESAFE_API_KEY=your_key_here
DEMO_FAKE_IP=198.51.100.42
```

* `TYPESAFE_API_KEY`: Connects to Jev SystemOne cloud engine. If left empty, the server automatically uses the local heuristic engine. Everything keeps working.
* `DEMO_FAKE_IP`: Masks incoming and simulation client IPs in the surveillance log for safe demo recording and privacy. Defaults to `198.51.100.42`.

### Step 3. Start the server

```bash
node server.js
```

You should see two lines in your terminal:

```
Laya stub on http://localhost:8000
App on http://localhost:3000
```

### Step 4. Open in your browser

* Signup page: `http://localhost:3000/signup`
* Login page: `http://localhost:3000/login`
* Security dashboard: `http://localhost:3000/security-dashboard`

---

## Automated tests

The codebase includes 14 end-to-end Playwright tests covering registration, login, hint recovery, telemetry capture, and SOAR blocking.

First time setup requires downloading the Chromium browser engine:

```bash
npx playwright install chromium
```

Run the full suite in headless mode:

```bash
npx playwright test
```

Run tests with a visible browser window:

```bash
npx playwright test --headed
```

All 14 tests run in about 22 seconds and pass consistently.

---

## Author

Built by Utkarsh Gupta.