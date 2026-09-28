<div align="center">

```
   _  ___    ______  _____ ___   _____ ____ _  __  ____  ____  ___  _  __
  / |/ / |  / /  _/ / _  // _ | / ___// __ `/ |/ / / __ \/ __ \/ _ \/ |/ /
 /    /| | / // /  / // // __ |/ /__ / /_/ /    / / /_/ / /_/ / // /    / 
/_/|_/ |___/___/  /____//_/ |_|\___/ \__,_/_/|_/  \____/ .___/\___/_/|_/  
                                                      /_/                 
                CYBER COMMAND // ENCLAVE DEFENSE ENGINE
```

# NVIDIA // CYBER COMMAND
### Autonomous Dual-Engine AI Threat Triage & Closed-Loop SOAR Active Defense

[![Node.js](https://img.shields.io/badge/Node.js-v18+-76b900?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Playwright Tests](https://img.shields.io/badge/Playwright-14%2F14%20Passing-76b900?style=for-the-badge&logo=playwright&logoColor=white)](https://playwright.dev/)
[![SOAR](https://img.shields.io/badge/SOAR%20Defense-Active%20Mitigation-76b900?style=for-the-badge&logo=shield&logoColor=white)](#-closed-loop-soar-active-defense)
[![Design](https://img.shields.io/badge/Design%20System-NVIDIA%20Alpha-000000?style=for-the-badge&logo=nvidia&logoColor=76b900)](DESIGN.md)
[![License](https://img.shields.io/badge/License-MIT-111111?style=for-the-badge)](LICENSE)

<br/>

> **"Traditional SIEM dashboards watch you get attacked and page a human 20 minutes later.  
> Cyber Command executes closed-loop machine mitigation in $<1\text{ms}$."**

<br/>

[Live Features](#-core-capabilities) •
[Architecture](#-system-architecture) •
[Dual AI Duel](#-cloud-vs-edge-ai-benchmark) •
[Attack Matrix](#-red-teaming-matrix) •
[Quickstart](#-quickstart) •
[Render Deploy](#-1-click-render-deployment)

</div>

---

## ⚡ Executive Summary

**Cyber Command** is a live enterprise security intelligence and triage platform benchmarking **Cloud AI (Jev SystemOne)** against **Local Edge AI (Laya)** on live adversary traffic.

Equipped with **client behavioral biometrics** (keystroke dynamics + cursor kinetics) and **closed-loop SOAR automation**, it distinguishes legitimate humans from automated bots, verifies benign retries vs brute force floods, and instantly contains confirmed threats via dynamic 15-minute kernel blocklists.

---

## 🏛 System Architecture

```
                                  ┌──────────────────────────┐
                                  │   CLIENT INGRESS LAYER   │
                                  │   /signup  │  /login     │
                                  └─────────────┬────────────┘
                                                │
                                      [ BEHAVIORAL PROBE ]
                         ┌──────────────────────┴──────────────────────┐
                         ▼                                             ▼
                 [ HUMAN OPERATOR ]                          [ SYNTHETIC BOTNET ]
             • Mouse distance > 0px                       • Mouse distance = 0px
             • Variable typing cadence                    • Sub-second post (<500ms)
             • Benign typos (<5 fails)                    • Spray / Stuffing / SQLi
                         │                                             │
                         ▼                                             ▼
               200 OK (NORMAL USER)                          401 (ATTACK FLAGGED)
             ROLE: NORMAL USER (VERIFIED)                              │
                                                                       ▼
                                                           [ SLIDING AUDIT WINDOW ]
                                                          (20 Attempts / 60s Window)
                                                                       │
                                              ┌────────────────────────┴────────────────────────┐
                                              ▼                                                 ▼
                                     [ JEV SYSTEMONE ]                                  [ LAYA EDGE STUB ]
                                   Remote Cloud REST API                              Local On-Prem (:8000)
                                   Latency: ~240ms                                    Latency: ~33ms (7x faster)
                                   Deep reasoning engine                              Zero data egress / 100% private
                                              └────────────────────────┬────────────────────────┘
                                                                       │
                                                           [ REASONING PRIMITIVES ]
                                                           • neoul:  Anomalous P(Threat) [0..1]
                                                           • choice: Adversary Tactic Classification
                                                           • score:  Exploit Severity Rating [0..3]
                                                                       │
                                                                       ▼
                                                       [ CLOSED-LOOP SOAR MITIGATION ]
                                                         Threshold: Confidence ≥ 90%
                                                                       │
                                                                       ▼
                                                         DYNAMIC IP BLOCKLIST (TTL: 15m)
                                                          Next Hit: 403 FORBIDDEN
```

---

## 🛡 Core Capabilities

### 1. Smart Authentication Enclaves & Eye Visibility Toggle
* **Dedicated Separate Pages:**
  * [`/signup`](http://localhost:3000/signup) — Credential Enrollment Gateway with auto-redirect to login upon creation.
  * [`/login`](http://localhost:3000/login) (and `/`) — Authentication Gateway with cross-navigation and tab selectors.
* **Interactive SVG Eye Button:** Built-in password visibility toggle (`👁` reveal $\leftrightarrow$ `🔒` hide) on both portals with NVIDIA Green hover transitions.
* **3 Authentication Mechanisms:**
  * **Password Auth:** User credentials with encrypted recovery hints.
  * **Machine API Key:** Cryptographic `nv_sec_...` service tokens.
  * **Step-Up MFA / OTP:** 6-digit challenge code verification with 5-minute TTL.

### 2. Normal User vs. Brute Force Classification
* **Legitimate Normal User:** Correct password $\to$ resets failure counter $\to$ returns `200 OK` $\to$ opens `/user-dashboard` with `ROLE: NORMAL USER (LEGITIMATE)` badge.
* **Benign Retries ($<5$):** Human typos classified as `Normal User Retry (X/5)`. After 3 failed attempts, `#hint-msg` exposes the recovery hint.
* **Brute Force ($\ge 5$):** Exceeding limit flags account as `Brute Force Attack (X attempts)` with `401 (FLAGGED)` and triggers red surveillance badges.

### 3. Client-Side Behavioral Telemetry (Bot Detection)
* Real-time listeners capture `keystrokeDeltas`, `mouseDistanceMoved`, and `totalFormTimeMs`.
* Instantly identifies automated scrapers (Playwright/Puppeteer/curl scripts with 0px mouse movement) and flags them as `is_synthetic_bot: true`.

### 4. Decision Reasoning Primitives
Every security decision is structured into three formal mathematical types:
* **`neoul` (Continuous Probability $0.0 - 1.0$):** Continuous threat likelihood evaluated against a $>0.800$ decision threshold.
* **`choice` (Discrete Tactic Selection):** Categorical selection across candidate attack vectors.
* **`score` (Exploit Risk Severity $0.0 - 3.0$):** Tiered exploit risk rating from Level 0 (Harmless) to Level 3 (Exploit).

### 5. Closed-Loop SOAR Active Defense
* **Automated Containment:** When triage confidence reaches $\ge 90\%$, backend dynamically blacklists the offending IP for 15 minutes.
* **Active Defense Enforcement:** `soarGuard` middleware intercepts subsequent traffic with immediate `403 Forbidden`.
* **Operator Override:** One-click `[🛡 Unblock All]` on the dashboard flushes the blocklist and restores access.

### 6. Interactive Command Dashboard
* **Dynamic Movable Blocks:** 6 modular blocks with draggable grab handles (`⠿`), `[▲ Up]` / `[▼ Down]` shift controls, index badges, and `localStorage` layout persistence.
* **Collapsible Forensic Accordions:** Interactive section dropdowns for deep mathematical primitive inspection.
* **Audit Stream Search & Filter:** Instant live filtering by IP, username, payload, status, or timestamps.
* **Archify Architecture Pipeline:** Inline 4-stage interactive visualization (`#archify-architecture`).
* **Driver.js Onboarding Tour:** Guided platform walkthrough for technical demos.

---

## ⚔️ Cloud vs. Edge AI Benchmark

| Architectural Dimension | ☁️ Jev SystemOne (Cloud) | ⚡ Laya Stub (Local Edge) | Winner |
| :--- | :--- | :--- | :--- |
| **Inference Latency** | $\sim 240\text{ms}$ (Network dependent) | $\sim 33\text{ms}$ (Local forward pass) | **Laya ($7\times$ faster)** |
| **Deployment Topology** | Remote SaaS REST API (`:443`) | In-process / Localhost container (`:8000`) | **Laya (Air-gapped ready)** |
| **Data Boundary** | External TLS Egress | Zero data egress (100% On-Premises) | **Laya (Zero-Trust)** |
| **Operational Cost** | \$0.002 per request tokenized | \$0.000 marginal hardware compute | **Laya (100% Free)** |
| **Analytical Depth** | Multi-hop reasoning over complex spray patterns | Fast typed heuristics & decision encoder | **Jev (Deep Forensics)** |

---

## 🎯 Red-Teaming Matrix

| Vector Code | Adversary Pattern | Example Payload | Severity Score | Classification |
| :--- | :--- | :--- | :--- | :--- |
| `benign_retry` | Human typo / mistyped character | `Password#2025` | `0.4 / 3.0` | `benign_login` |
| `brute_force` | Rapid credential guessing on single user | `admin123`, `qwerty` | `2.5 / 3.0` | `brute_force` |
| `password_spray` | 1 password tested horizontally across users | `Spring2026!` across 10 accounts | `2.4 / 3.0` | `credential_stuffing` |
| `credential_stuffing`| Leaked combination pairs from breach list | `sarah:summer2024` | `2.4 / 3.0` | `credential_stuffing` |
| `sqli_attempt` | SQL Injection authentication bypass | `' OR '1'='1 --`, `UNION SELECT` | `2.9 / 3.0` | `sqli_attempt` |
| `xss` | Cross-site scripting DOM injection probe | `<script>alert(1)</script>` | `2.6 / 3.0` | `sqli_attempt` |
| `api_key_enumeration`| High-frequency API key scanning / fuzzing | `nv_sec_fuzz_002_cafebabe` | `2.4 / 3.0` | `credential_stuffing` |
| `mfa_exhaustion` | Rapid cycling of 6-digit OTP codes | `OTP:123456`, `OTP:999999` | `2.5 / 3.0` | `brute_force` |

---

## ⚡ Quickstart

### Prerequisites
* [Node.js](https://nodejs.org/) v18+
* npm or bun

### 1. Clone & Install
```bash
git clone https://github.com/your-username/JEV_AI_TESTING.git
cd JEV_AI_TESTING
npm install
```

### 2. Environment Configuration (Optional)
Create `.env` in the root directory:
```env
TYPESAFE_API_KEY=your_optional_jev_api_key_here
```
> [!NOTE]
> If `TYPESAFE_API_KEY` is omitted, the platform automatically runs on the **deterministic heuristic engine** with zero downtime.

### 3. Launch the Server
```bash
node server.js
```
Console output:
```
Laya stub on http://localhost:8000
App on http://localhost:3000
```

### 4. Access URLs
* **Registration Gateway:** [http://localhost:3000/signup](http://localhost:3000/signup)
* **Authentication Gateway:** [http://localhost:3000/login](http://localhost:3000/login) (or [http://localhost:3000/](http://localhost:3000/))
* **Security Command Center:** [http://localhost:3000/security-dashboard](http://localhost:3000/security-dashboard)

---

## ☁️ 1-Click Render Deployment

The server dynamically binds to `process.env.PORT` and runs both the gateway and internal Laya stub seamlessly in a single persistent container:

1. **Push your code to GitHub.**
2. In [Render Dashboard](https://dashboard.render.com/), click **New Web Service** $\to$ Connect your repository.
3. Configure the service:
   * **Runtime:** `Node`
   * **Build Command:** `npm install`
   * **Start Command:** `node server.js`
   * **Auto-Deploy:** `Yes`
4. Add Environment Variable (Optional): `TYPESAFE_API_KEY`.
5. Click **Create Web Service**. Your live demo will be online in under 2 minutes!

---

## 🧪 Automated Testing (Playwright)

Every capability is covered by end-to-end Playwright tests asserting single-user registration, multi-tab parallel attacks, recovery hints, and SOAR dynamic containment.

```bash
# Run full test suite (headless)
npx playwright test

# Run visual headed demo
npx playwright test --headed
```

### Test Suite Status (14/14 Tests Passing, 100% Green)
```
  ok   1 tests\advanced-vectors.spec.ts:6:7   › Multi-Auth APIs: Password, Key, MFA
  ok   2 tests\advanced-vectors.spec.ts:56:7  › Simulation Endpoints: Spray, Stuffing, SQLi
  ok   3 tests\end-to-end-architecture.spec.ts › 1. Closed-Loop SOAR Active Defense
  ok   4 tests\end-to-end-architecture.spec.ts › 2. Multi-Vector Red-Teaming Matrix
  ok   5 tests\end-to-end-architecture.spec.ts › 3. Client Behavioral Telemetry (Bots)
  ok   6 tests\end-to-end-architecture.spec.ts › 4. Live Model Benchmark Widget
  ok   7 tests\end-to-end-architecture.spec.ts › 5. Automated Recovery via Hint Assertion
  ok   8 tests\end-to-end-architecture.spec.ts › 6. Decision Reasoning Primitives
  ok   9 tests\end-to-end-architecture.spec.ts › 7. Live System Controls & Search Filters
  ok  10 tests\end-to-end-architecture.spec.ts › 8. Dynamic Movable Dashboard Blocks
  ok  11 tests\end-to-end-architecture.spec.ts › 9. Normal User vs Brute Force Flagging
  ok  12 tests\multi-chrome.spec.ts:4:7       › Multi-Chrome Parallel Workflow (Dual Tabs)
  ok  13 tests\simulation.spec.ts:8:7         › Flow A: Signup + Login -> Personal Dashboard
  ok  14 tests\simulation.spec.ts:22:7        › Flow B: Failed retries + 200 burst + AI duel

  14 passed (24.2s)
```

---

## 🎨 Design System Specifications

Built according to the **NVIDIA EMEA Design Specification** ([DESIGN.md](DESIGN.md)):
* **Color Palette:**
  * NVIDIA Green Accent: `#76b900`
  * Pure Canvas Black: `#000000` / Elevated Card: `#111111`
  * Hairline Rules: `#222222` / Border Radius: `2px` across all elements
* **Typography:** `Poppins` (Headings & Body), `JetBrains Mono` (Technical Metrics)
* **Surface Modes:** Deep black canvas for hero surveillance chapters, high-contrast monospace tables for audit telemetry.

---

## 👤 Author & Credits

**Utkarsh Gupta**  
*Curious Full-Stack Developer & AI Systems Builder*  
Exploring adversarial security, high-throughput model inference, and edge automation.

---

<div align="center">
  <sub>Built with Node.js, Express, Playwright, and NVIDIA Alpha Design System.</sub>
</div>