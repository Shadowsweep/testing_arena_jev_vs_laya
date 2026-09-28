# Project Memory & Session History

## [2026-09-28] Dedicated Login & Signup Pages, Legitimate Normal User Auth & Brute Force Limit Flagging

### What Was Done
1. **Dedicated Login & Signup Pages Separation**:
   - Decoupled registration and authentication cards into dedicated, distinct routes:
     - `/signup`: Dedicated Enclave Registration Gateway (`#reg-user`, `#reg-pass`, `#reg-hint`, `Sign Up` button, cross-link to `/login`). Automatically redirects to `/login?registered=<user>` upon successful account creation.
     - `/login` (and `/` mapping to `/login`): Dedicated Enclave Authentication Gateway with Enclave Login card (`#login-user`, `#login-pass`, `Log In` button, `#msg`, `#hint-msg`, cross-link to `/signup`, plus API Key and MFA tabs). Pre-populates username and displays success banner if redirected from `/signup`.
2. **Legitimate Normal User Authentication vs Brute Force Attack Flagging**:
   - Added in-memory per-user and per-IP failure tracking with threshold `BRUTE_FORCE_LIMIT = 5`.
   - **Legitimate Normal User Login (Correct Credentials)**:
     - Resets failure counters for user and IP.
     - Logs audit event as status `200` with `classification: 'Normal User (Legitimate)'`, `role: 'normal_user'`, zero threat score (`is_attack: false`, `confidence: 0`).
     - Redirects user to `/user-dashboard` displaying the prominent NVIDIA Green badge `ROLE: NORMAL USER (LEGITIMATE)` and benign status.
   - **Failed Login Attempts Below Threshold (< 5 Attempts)**:
     - Classified as `Normal User Retry (X/5)`.
     - Logs status `401` with `is_attack: false` / `0.16` and `flagged: false`.
     - Displays `Invalid credentials (attempt X of 5)` and security hint for benign user recovery if attempt >= 3.
   - **Failed Login Attempts Exceeding Threshold (>= 5 Attempts)**:
     - Flagged as `Brute Force Attack (X failed attempts)` with status `401 (FLAGGED)`.
     - Returns `flagged: true`, `is_attack: true`, and `confidence: 0.98`.
     - Renders warning in UI (`⚠ Brute Force Attack Detected: Exceeded limit of 5 attempts. Account flagged.`).
     - In `/security-dashboard` audit log table, rendered with dedicated red badge `<span class="badge badge-red">401 (ATTACK FLAGGED)</span>`.
3. **Automated Verification**:
   - Updated `tests/simulation.spec.ts` (Flow A) to sign up at `/signup`.
   - Updated `tests/multi-chrome.spec.ts` (Tab 1) to sign up at `/signup`.
   - Updated `tests/end-to-end-architecture.spec.ts` (Test 5) to sign up at `/signup`.
   - Added Test 9 to `tests/end-to-end-architecture.spec.ts` asserting:
     - Registration on `/signup`
     - Successful normal login on `/login` and verification of `ROLE: NORMAL USER (LEGITIMATE)` on `/user-dashboard`
     - Audit table rendering `200 OK (NORMAL USER)`
     - 4 failed retries returning `attempt X of 5`
     - 5th failed attempt flagged as `Brute Force Attack Detected`
     - Audit table rendering `401 (ATTACK FLAGGED)`
   - All 14 Playwright tests pass: 14/14 passed in 21.5s.

### Files Changed
- `server.js`: Added failure tracking maps, updated `handleLogin`, separated `/signup` and `app.get(['/login', '/'])` routes, updated `/user-dashboard` with `ROLE: NORMAL USER (LEGITIMATE)` badge, updated `formatRow` with `200 OK (NORMAL USER)` and `401 (ATTACK FLAGGED)` status badges.
- `tests/simulation.spec.ts`: Updated Flow A registration to `/signup`.
- `tests/multi-chrome.spec.ts`: Updated Tab 1 registration to `/signup`.
- `tests/end-to-end-architecture.spec.ts`: Updated Test 5 to `/signup` and added Test 9.
- `BACKEND.md`: Updated password login and page route specifications.
- `EVALUATION.md`: Updated status table.
- `HANDOFF.md`: Updated project status and test inventory.
- `README.md`: Created comprehensive documentation with architecture flow, key capabilities, Render deployment instructions, and test inventory.

---

## [2026-09-28] Closed-Loop SOAR Active Defense, Behavioral Telemetry, Benchmark Widget & Red-Teaming Matrix

### What Was Done
1. **Closed-Loop Automated Mitigation (SOAR Action)**:
   - Added active defense containment hook: when Laya or Jev returns attack confidence >= 90%, backend dynamically blacklists the offending IP with a 15-minute TTL.
   - Enforced `soarGuard` middleware across `/api/auth/*`, `/api/login`, `/api/signup`: blacklisted IPs receive immediate `403 Forbidden` (`Forbidden: IP Blacklisted by SOAR Active Defense`).
   - Integrated dynamic SOAR badge on `/security-dashboard`: switches from `Status: Monitoring` to `IP <ip> Blacklisted (TTL: 15m)` with manual `[🛡 Unblock All]` button and SOAR APIs (`/api/soar/*`).
2. **Multi-Vector Red-Teaming Matrix & Multi-Question Classification**:
   - Added SQL Injection bypass probes (`' OR '1'='1`, `admin' --`) and slow-and-low credential stuffing profiles across 20 user targets.
   - Upgraded SystemOne payload and Laya stub to answer multi-question classification in a single forward pass: continuous threat likelihood (`is_threat`: `noul`) and specific category (`threat_category`: `choice` mapping to `sqli_attempt`, `credential_stuffing`, `brute_force`, `benign_login`).
3. **Client-Side Behavioral Telemetry (Bot Detection)**:
   - Instrumented `/` login form with event listeners capturing `keystrokeDeltas`, `mouseDistanceMoved`, and `totalFormTimeMs`.
   - Aggregated telemetry in `buildState()`: flags `is_synthetic_bot: true` when mouse distance is 0px and form is filled under 500ms.
4. **Live Architecture Benchmark Widget (Laya vs Jev)**:
   - Built inline comparison widget on `/security-dashboard` evaluating Inference Latency (~33ms vs ~240ms), Deployment Topology, Data Boundary (100% on-premises vs TLS egress), and Cost per 10k evals.
   - Dynamically updates with real measured latencies upon inference dispatch.
5. **Automated Recovery via Hint Assertion**:
   - Automated end-to-end recovery test: attempts 3 incorrect passwords to trigger hint UI, extracts hint text from `#hint-msg` DOM, and successfully recovers user into `/user-dashboard`.
6. **Automated Verification**:
   - Created `tests/end-to-end-architecture.spec.ts` asserting all 5 capabilities.
   - Ran complete repository test suite: 10/10 tests passed (100% green).

### Files Changed / Created
- `server.js`: SOAR dynamic blocklist, `soarGuard`, client telemetry tracking, multi-question classification, SOAR status badge, and Live Benchmark Widget.
- `BACKEND.md`: Documented SOAR management endpoints, telemetry fields, and multi-question schema.
- `EVALUATION.md`: Updated status table with SOAR active defense, client telemetry, and benchmark widget.
- `Flow.md`: Updated system data flow diagram with SOAR dynamic blocklist and telemetry pipeline.
- `tests/end-to-end-architecture.spec.ts`: End-to-end test suite for SOAR, Red-Teaming, Telemetry, Benchmark, and Hint Recovery.
- `memory.md`: Logged session achievements and verification results.
- `HANDOFF.md`: Updated session state and handoff instructions.

### Verification
- `npx playwright test`: 11 passed in 16.5s.
  - `tests/end-to-end-architecture.spec.ts`: 6/6 passed (SOAR block, Red-teaming, Telemetry, Benchmark widget, Hint recovery, Reasoning primitive tables & tab filters).
  - `tests/advanced-vectors.spec.ts`: 2/2 passed (Multi-auth APIs, simulation endpoints, Archify modal, pagination).
  - `tests/multi-chrome.spec.ts`: 1/1 passed (Dual-tab concurrent workflow).
  - `tests/simulation.spec.ts`: 2/2 passed (Flow A signup/login, Flow B burst + compare).

## [2026-09-28] Compact UI Footprint & Decision Reasoning Primitives (Neoul, Choice, Score)

### What Was Done
1. **Compact UI & Reduced Vertical Sprawl**:
   - Decreased visual padding across cards, tables, navigation headers, and container margins (`.nv-card`: 16px 20px, table cells: 7px-8px 12px, nav: 10px 24px, container: 1.25rem).
2. **Three Decision Reasoning Primitive Tables**:
   - Added `#tour-reasoning-primitives` card with view filter toggles (`[All Sections]`, `[1. Neoul]`, `[2. Choice]`, `[3. Score]`) controlled by `switchPrimitiveView(view)`.
   - **Section 1: `neoul` (Continuous Probability)**: Displays Failure Volume Window, Client Behavioral Telemetry, and Continuous Probability vs 0.800 decision threshold, with live status badges and reasoning justifications.
   - **Section 2: `choice` (Adversary Tactic Selection)**: Multi-row classification matrix across candidate vectors (`sqli_attempt`, `password_spray`, `credential_stuffing`, `brute_force`, `benign_login`) evaluating criteria, match status, confidence %, and reasoning explanations.
   - **Section 3: `score` (Exploit Risk Severity)**: Severity tier hierarchy from Level 0 (0.0-0.9 Harmless) through Level 3 (2.6-3.0 High Exploit Risk) displaying operational criteria, active status, and SOAR mitigation reasoning.
3. **Dynamic Frontend Telemetry Hook**:
   - Implemented `updateReasoningPrimitives(d)` in `server.js` client script to update observed metrics, match status badges, confidence, and reasons when dual engine triage runs.
4. **Automated Verification**:
   - Added test 6 to `tests/end-to-end-architecture.spec.ts` asserting primitive section visibility, tab filter toggling, and live dynamic table updates upon SQLi attack simulation.
   - All 11 tests across 4 spec files pass with zero errors.

### Files Changed
- `server.js`: Compact styling, HTML markup for `#tour-reasoning-primitives`, `switchPrimitiveView(view)`, and `updateReasoningPrimitives(d)`.
- `tests/end-to-end-architecture.spec.ts`: Added test 6 for reasoning primitives and filter toggles.
- `BACKEND.md`: Documented reasoning primitive tables and payload mapping.
- `EVALUATION.md`: Documented Neoul, Choice, and Score reasoning primitives.
- `Flow.md`: Added reasoning primitive breakdown to architecture flow.
- `HANDOFF.md`: Updated active features and test verification status.
- `memory.md`: Documented changes and test execution.

## [2026-09-28] Live System Controls: Top Engine Selector, Instant Auto-Eval, Accordion Dropdowns & Audit Search Filters

### What Was Done
1. **Live Engine Selector & Auto-Evaluating Simulation**:
   - Added top inference engine selector (`#engine-sel-jev`, `#engine-sel-laya`, `#engine-sel-both`) in the command toolbar.
   - Wired `sim(kind)` to automatically execute `ev(selectedEngine)` immediately after injecting attacks. E.g., clicking "1 User" with Jev active immediately runs Jev evaluation at live speed.
2. **Right-Corner Clear Buffer**:
   - Positioned dedicated `[🗑 Clear Buffer]` button (`#btn-clear-buffer-corner`) in the top-right corner of the toolbar, resetting logs, status indicators, and meter bars.
3. **In-Depth Collapsible Accordion Dropdowns**:
   - Upgraded all 3 reasoning primitive sections (`neoul`, `choice`, `score`) into collapsible dropdown accordions (`wrap-primitive-noul`, `wrap-primitive-choice`, `wrap-primitive-score`).
   - Added section toggle buttons (`#btn-toggle-noul`, `#btn-toggle-choice`, `#btn-toggle-score`) and global `[▾ Expand All]` / `[▴ Collapse All]` buttons.
4. **Live Audit Stream Search Filtering & Timestamps**:
   - Added live search filter input (`#log-search-filter`) searching IP, username, payload, HTTP status, and timestamp.
   - Added timestamp filtering (`All Recorded` vs `Last 60s`).
   - Integrated full timestamp recording (`time`, `timestamp`, `isoTime`) via centralized `pushLog` helper.
5. **Automated Verification**:
   - Added test 7 in `tests/end-to-end-architecture.spec.ts` asserting engine selection, auto-eval, accordion collapse/expand, search filtering, and clear buffer.
   - Ran `npx playwright test`: 12/12 tests passed (100% green).

### Files Changed
- `server.js`: Engine selection bar, auto-eval `sim()`, corner clear button, accordion dropdown wrappers, search filter, and `pushLog` timestamp generator.
- `tests/end-to-end-architecture.spec.ts`: Added test 7 asserting live system controls.
- `BACKEND.md`: Documented search filter, timestamp fields, and auto-eval engine selection.
- `EVALUATION.md`: Updated status table.
- `Flow.md`: Updated flowchart with live engine selector and search filter.
- `HANDOFF.md`: Updated feature list and quick links.
- `memory.md`: Documented session changes and verification.

## [2026-09-28] Simplified Inline Archify Architecture & Modal Removal

### What Was Done
1. **Removed Archify Modal Overlay**:
   - Stripped `#archify-modal` floating popup, backdrop blur overlay, and `#archify-close` button from `server.js`.
2. **Simplified Inline Architecture Card (`#archify-architecture`)**:
   - Replaced floating modal with a dedicated, inline dashboard card embedded directly in `/security-dashboard` UI.
   - Structured 4-stage pipeline:
     1. `01 // INGRESS & PROBES`: Playwright automation and client requests (`/api/login`, `/api/simulate/*`).
     2. `02 // SECURITY ENCLAVE`: Express gateway (:3000) with dynamic IP blacklist filter and rolling 20-attempt window.
     3. `03 // DUAL AI REASONING`: Parallel triage comparing Jev Cloud (:443, ~240ms) vs Local Laya (:8000, ~33ms) outputting `noul`, `choice`, `score`.
     4. `04 // SOAR CONTAINMENT`: Closed-loop active defense auto-quarantine for offending IPs on confidence > 90%.
   - Added Archify Reasoning Primitives summary breakdown directly below pipeline stages.
3. **Smooth Scroll Top Nav Integration**:
   - Configured top navigation `[🏛 Archify Architecture]` button (`#archify-btn`) to trigger `scrollToArchify()` with smooth scroll and green glow pulse animation.
   - Updated Driver.js step target to point directly to `#archify-architecture`.
4. **Automated Verification**:
   - Updated `tests/advanced-vectors.spec.ts` to assert `#archify-architecture` presence and text.
   - Ran `npx playwright test`: 12/12 passed (100% green, 17.4s).

### Files Changed
- `server.js`: Removed `#archify-modal` CSS & HTML, rendered `#archify-architecture` inline card, added `scrollToArchify()` helper.
- `tests/advanced-vectors.spec.ts`: Asserted inline `#archify-architecture` visibility and text.
- `EVALUATION.md`: Updated status table with Archify Architecture UI.
- `HANDOFF.md`: Updated architecture section and quick links.
- `memory.md`: Documented changes and test execution.

## [2026-09-28] Dynamic Movable Dashboard Blocks & HTML5 Drag-and-Drop Reordering

### What Was Done
1. **Dynamic Modular Dashboard Blocks**:
   - Structured all 6 major sections into draggable `.dashboard-block` components inside `#dashboard-blocks-container`:
     - `block-controls`: Simulation & Inference Controls
     - `block-triage`: Dual Engine Triage & Verdict Banner
     - `block-benchmark`: Live Architecture Benchmark Widget
     - `block-primitives`: Decision Reasoning Primitives (Neoul, Choice, Score)
     - `block-audit`: Live Audit Stream & Filters
     - `block-archify`: Archify Architecture Pipeline
2. **Shift Up/Down Buttons & Auto-Index Numbering**:
   - Built a sleek NVIDIA `.block-bar` atop every card with grab handle (`⠿`), dynamic index badge (`BLOCK 01` through `BLOCK 06`), and `[▲ Up]` / `[▼ Down]` buttons.
   - Bound buttons to `shiftBlock(id, direction)` with green pulse highlight and boundary checks (disables `▲` for top block, disables `▼` for bottom block).
3. **HTML5 Drag-and-Drop & Persistence**:
   - Integrated native drag-and-drop (`initDragAndDrop()`) with visual green dashed insertion indicator (`.drag-over`).
   - Saved custom layout order to `localStorage.getItem('nv_dash_block_order')` and auto-restored on page load.
   - Added `[⟲ Reset Layout]` button (`#btn-reset-layout`) in the top navigation bar to restore default sequence at any time.
4. **Automated Verification**:
   - Added test 8 in `tests/end-to-end-architecture.spec.ts` asserting block visibility, up/down DOM reordering, dynamic index updates, and layout reset.
   - Ran complete Playwright suite: 13/13 passed (100% green, 25.6s).

### Files Changed
- `server.js`: Added block styles, block control bars, `#dashboard-blocks-container`, `shiftBlock()`, `initDragAndDrop()`, `resetBlockOrder()`, and top nav reset button.
- `tests/end-to-end-architecture.spec.ts`: Added test 8 verifying block shifting and layout reset.
- `EVALUATION.md`: Added Movable Dashboard Blocks to feature status table.
- `HANDOFF.md`: Documented dynamic movable blocks feature and test status.
- `memory.md`: Documented changes and verification results.



