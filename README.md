# NVIDIA // CYBER COMMAND
### Dual-Engine AI Threat Surveillance & Closed-Loop SOAR Defense Platform

A high-performance security simulation and autonomous triage platform comparing **Cloud AI (Jev SystemOne)** versus **Local Edge AI (Laya)** on live adversarial traffic. Built with the **NVIDIA Alpha Design System** (`#76b900` Green, strict 2px radius, monospace data grids).

---

## ⚡ Architecture Overview

```
                                      [ INGRESS GATEWAY ]
                             /signup (Enroll) | /login (Auth)
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
             [ Human Interaction ]                           [ Synthetic Bot / Attack ]
          • Mouse kinetics > 0px                          • 0px mouse distance
          • Normal typing deltas                          • Sub-second execution (<500ms)
          • Below limit (<5 attempts)                     • High frequency / attack vectors
                      │                                               │
                      ▼                                               ▼
            200 OK (NORMAL USER)                            401 (ATTACK FLAGGED)
           ROLE: NORMAL USER                                          │
                                                                      ▼
                                                          [ DUAL-ENGINE AI TRIAGE ]
                                                      ┌───────────────┴───────────────┐
                                                      ▼                               ▼
                                             [ JEV CLOUD AI ]                [ LAYA EDGE STUB ]
                                          Remote REST API (:443)           Local on-prem (:8000)
                                          Latency: ~240ms                 Latency: ~33ms
                                          Deep reasoning                  Zero egress / 100% private
                                                      └───────────────┬───────────────┘
                                                                      │
                                                          [ REASONING PRIMITIVES ]
                                                          • neoul: continuous prob
                                                          • choice: attack tactic
                                                          • score: exploit risk (0-3)
                                                                      │
                                                                      ▼
                                                      [ CLOSED-LOOP SOAR MITIGATION ]
                                                          Confidence ≥ 90%
                                                                      │
                                                                      ▼
                                                       Dynamic Blocklist (TTL: 15m)
                                                      Subsequent: 403 Forbidden
```

---

## 🚀 Key Features

### 1. Multi-Mechanism Authentication Enclaves
* **Dedicated Separate Pages:**
  * [`/signup`](http://localhost:3000/signup) — Credential Enrollment Gateway with auto-redirect to login.
  * [`/login`](http://localhost:3000/login) (and `/`) — Authentication Gateway with cross-links.
* **3 Authentication Mechanisms:**
  * **Password Auth:** User credentials with encrypted hint recovery.
  * **Machine API Key:** Cryptographic `nv_sec_...` service tokens.
  * **Step-Up MFA / OTP:** Time-limited 6-digit challenge verification.
* **Legitimate User vs. Adversary Threshold:**
  * **Normal Users:** Log in with correct credentials $\to$ `200 OK (NORMAL USER)` $\to$ redirected to `/user-dashboard` with `ROLE: NORMAL USER (LEGITIMATE)` badge.
  * **Benign Retries ($< 5$):** Classified as `Normal User Retry (X/5)` with hint revealed after 3 attempts.
  * **Brute Force ($\ge 5$):** Flagged as `Brute Force Attack (X attempts)` with `401 (FLAGGED)` and highlighted red in the audit stream.

### 2. Client-Side Behavioral Telemetry (Bot Detection)
* Client-side JavaScript captures `keystrokeDeltas`, `mouseDistanceMoved`, and `totalFormTimeMs`.
* Instantly distinguishes programmatic automation bots (Playwright/Puppeteer/curl with 0px mouse travel) from human operators.

### 3. Dual-Engine Model Comparison (Jev vs Laya)
* **Jev SystemOne (Cloud):** Connects to remote TypeSafe SystemOne endpoint with bearer token authorization.
* **Laya Local Stub (Edge):** Runs locally on port `8000` executing sub-50ms inference with zero data egress.
* **Live Model Benchmark Widget:** Interactive card comparing real-time inference latency, deployment topology, zero-trust data egress, and cost per 10k evaluations.

### 4. Decision Reasoning Primitives
Every AI decision is mapped into three explicit mathematical types:
* **`neoul` (Continuous Probability $0.0 - 1.0$):** Anomaly assessment against a $>0.800$ threat threshold.
* **`choice` (Adversary Tactic Selection):** Categorical selection across `sqli_attempt`, `password_spray`, `credential_stuffing`, `brute_force`, and `benign_login`.
* **`score` (Exploit Risk Severity $0.0 - 3.0$):** Hierarchical risk rating from Level 0 (Harmless) to Level 3 (Active Exploit).

### 5. Closed-Loop SOAR Active Defense
* **Automated Containment:** When triage confidence reaches $\ge 90\%$ on an active attack, the offending IP is dynamically blacklisted for 15 minutes.
* **Active Defense Enforcement:** `soarGuard` middleware intercepts subsequent ingress from blacklisted IPs with immediate `403 Forbidden`.
* **One-Click Unblock:** Top navigation status badge displays `IP <ip> Blacklisted (TTL: 15m)` with manual `[🛡 Unblock All]` operator override.

### 6. Interactive Cyber Command Dashboard
* **Dynamic Movable Blocks:** 6 modular blocks with draggable handles (`⠿`), `[▲ Up]` / `[▼ Down]` buttons, index tracking, `localStorage` persistence, and top nav `[⟲ Reset Layout]`.
* **In-Depth Dropdown Accordions:** Collapsible tables for forensic inspection with global `[▾ Expand All]` / `[▴ Collapse All]`.
* **Audit Stream Search & Filter:** Instant real-time search across IP, username, payload, status, or timestamps.
* **Archify Inline Architecture:** 4-stage pipeline visualization (`#archify-architecture`) accessible via smooth-scroll button.
* **Driver.js Onboarding Tour:** Guided interactive walkthrough of platform capabilities.

---

## 🛠 Local Setup & Running

### Prerequisites
* [Node.js](https://nodejs.org/) v18 or higher
* npm or bun

### 1. Clone & Install
```bash
git clone <repo-url>
cd JEV_AI_TESTING
npm install
```

### 2. Environment Configuration (Optional)
Copy or create `.env`:
```env
TYPESAFE_API_KEY=your_optional_api_key_here
```
> *Note: If no API key is provided, the platform automatically uses the deterministic heuristic fallback engine with zero downtime.*

### 3. Run Server
```bash
node server.js
```
The console will confirm:
```
Laya stub on http://localhost:8000
App on http://localhost:3000
```

### 4. Open in Browser
* **Registration Gateway:** [http://localhost:3000/signup](http://localhost:3000/signup)
* **Authentication Gateway:** [http://localhost:3000/login](http://localhost:3000/login) (or [http://localhost:3000/](http://localhost:3000/))
* **Security Command Center:** [http://localhost:3000/security-dashboard](http://localhost:3000/security-dashboard)

---

## ☁️ Deployment Guide (Render)

This repository is optimized for **1-click deployment on Render** (or any Node.js host supporting persistent processes):

1. **Push your repository to GitHub.**
2. **Log into [Render.com](https://render.com/)** and select **New Web Service**.
3. **Connect your GitHub repository.**
4. **Configure Service Settings:**
   * **Environment:** `Node`
   * **Build Command:** `npm install`
   * **Start Command:** `node server.js`
   * **Auto-Deploy:** `Yes`
5. **Environment Variables (Optional):**
   * Add `TYPESAFE_API_KEY` (if using remote Jev Cloud).
   * Note: Render automatically assigns `process.env.PORT` which `server.js` listens on dynamically.
6. Click **Create Web Service**. Your live demo URL will be available in minutes!

---

## 🧪 Automated Testing (Playwright)

The project includes an end-to-end verification test suite covering auth flows, multi-tab simulation, red-teaming vectors, and SOAR mitigation.

### Run All Tests
```bash
npx playwright test
```

### Run Tests in Headed Mode (Visual Demo)
```bash
npx playwright test --headed
```

### Test Suite Inventory (14 Tests, 100% Green)
| Spec File | Tests | Coverage |
| :--- | :--- | :--- |
| `tests/end-to-end-architecture.spec.ts` | 9 | SOAR blocklist, Red-Teaming matrix, Behavioral telemetry, Benchmark widget, Hint recovery, Reasoning primitives, Engine controls, Movable blocks, Normal User vs Brute Force |
| `tests/advanced-vectors.spec.ts` | 2 | Multi-auth APIs (Password, Key, MFA), Spray/Stuffing/SQLi/API scan simulations, Archify pipeline, pagination |
| `tests/multi-chrome.spec.ts` | 1 | Multi-tab parallel workflow (Tab 1 Action Worker vs Tab 2 Inspector) |
| `tests/simulation.spec.ts` | 2 | Flow A: Registration $\to$ Login $\to$ Personal Dashboard; Flow B: Failed retries + 200 burst + AI comparison |

---

## 📡 API Reference

### Authentication Endpoints
* `POST /api/auth/password/signup` — Register username, password, hint.
* `POST /api/auth/password/login` — Authenticate user with telemetry payload.
* `POST /api/auth/apikey/generate` — Generate machine API secret key.
* `POST /api/auth/apikey/verify` — Verify machine API key.
* `POST /api/auth/mfa/send-otp` — Dispatch 6-digit verification PIN.
* `POST /api/auth/mfa/verify-otp` — Validate 6-digit challenge code.

### Simulation Endpoints
* `POST /api/simulate-single` — Inject single benign typo attempt.
* `POST /api/simulate-burst` — Inject rapid burst flood (up to 500 attempts).
* `POST /api/simulate/spray` — Password spray against 10 corporate accounts.
* `POST /api/simulate/stuffing` — Slow-and-low credential stuffing with leaked pairs.
* `POST /api/simulate/sqli` — SQL injection bypass attempt (`' OR 1=1 LIMIT 1--`).
* `POST /api/simulate/apikey-scan` — High-frequency API key fuzzer scan.
* `POST /api/simulate/mfa-bomb` — Rapid 6-digit OTP code exhaustion attack.

### SOAR & AI Evaluation Endpoints
* `POST /api/evaluate?engine={jev|laya|both}` — Trigger dual-engine triage on current sliding window.
* `GET /api/soar/status` — Get active containment blocklist.
* `POST /api/soar/block` — Manually contain offending IP (custom TTL).
* `POST /api/soar/unblock` — Clear blacklist for single IP or all.
* `POST /api/clear-buffer` — Flush audit log stream and reset failure counters.

---

## 🎨 Design System Specifications
* **Primary Color:** NVIDIA Green (`#76b900`), Hover (`#88cc00`)
* **Surfaces:** Pure Black (`#000000`), Dark Canvas (`#0a0a0a`), Card Elevated (`#111111`)
* **Geometry:** Strict 2px border radius across all cards, inputs, and buttons
* **Typography:** `Poppins` (Headings & Body), `JetBrains Mono` / `Courier New` (Technical Data)
#   t e s t i n g _ a r e n a _ j e v _ v s _ l a y a  
 