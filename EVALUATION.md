# Evaluation Status & AI Triage Matrix

## Status Table

| Feature / Subsystem | Status | Latency Target | Implementation Notes | Regression Advice |
| :--- | :--- | :--- | :--- | :--- |
| **Password Auth APIs** | ✅ Working | <10ms | `/api/auth/password/signup`, `/login`. Stores hint, returns on 401. | Verify `#hint-msg` updates on invalid password. |
| **API Key Auth APIs** | ✅ Working | <10ms | `/api/auth/apikey/generate`, `/verify`. Returns `nv_sec_...` key. | Ensure `x-api-key` header lookup precedence. |
| **MFA / OTP Auth APIs** | ✅ Working | <10ms | `/api/auth/mfa/send-otp`, `/verify-otp`. 6-digit code with TTL. | Keep 5-minute expiry in memory. |
| **SOAR Active Defense** | ✅ Working | <1ms | Auto-blacklists offending IP when confidence >= 90% (TTL: 15m). | Verifies subsequent requests receive immediate `403 Forbidden`. |
| **Client Behavioral Telemetry** | ✅ Working | Client-side | Captures keystroke latencies, mouse distance, form duration. | Flags `is_synthetic_bot: true` when mouse distance is 0px. |
| **Live Benchmark Widget** | ✅ Working | Instant | Inline comparison card showing latency, cost, and egress boundaries. | Updates live with real measured latencies on eval dispatch. |
| **Hint Recovery Flow** | ✅ Working | Instant | Extracts security hint from DOM and recovers user into dashboard. | Assert hint extraction matches registered recovery answer. |
| **Audit Log Collector** | ✅ Working | <5ms | `auditLogs.unshift()`, masks password, records auth mechanism. | Keep unshift so newest logs appear first. |
| **Simulate Classic Burst** | ✅ Working | <50ms | Rapid generator for up to 500 burst items. | Keep loop synchronous in memory for speed. |
| **Simulate Password Spray**| ✅ Working | <10ms | Tests 1 password across 10 corporate user accounts. | Ensure `unique_users_count` is captured in state. |
| **Simulate Credential Stuffing**| ✅ Working | <10ms | Injects leaked username/password credential pairs. | Check breach pattern matcher in heuristic. |
| **Simulate SQL Injection** | ✅ Working | <10ms | Injects SQL metacharacters (`' OR 1=1 LIMIT 1--`, union select). | Verify SQLi takes highest severity score (2.9). |
| **Simulate API Key Scan**  | ✅ Working | <10ms | Fuzzes invalid `nv_sec_fuzz_*` tokens with service_bot. | Verify `api_key` mechanism flag in state. |
| **Simulate MFA Bombing**   | ✅ Working | <10ms | Floods 6-digit PIN guesses against target account. | Verify `otp` mechanism classification. |
| **Jev Cloud Integration**  | ⚠️ Partial | ~230ms | Connects to `https://api.typesafe.ai/v1/systemone` via `TYPESAFE_API_KEY`. | Falls back gracefully to heuristic if offline. |
| **Laya Local Stub**        | ✅ Working | ~33ms | Express stub on port 8000 matching SystemOne contract. | Ensure port 8000 is open and not conflicted. |
| **Heuristic Fallback**     | ✅ Working | <1ms | Regex + volume heuristic matching SystemOne schema. | Preserves score/confidence ranges (>80% on attack). |
| **Security Dashboard UI**  | ✅ Working | Instant | NVIDIA Green styling, Driver.js tour, pagination, grouping. | Ensure `navigator.webdriver` check suppresses tour in tests. |
| **Reasoning Primitives**   | ✅ Working | Instant | 3 tables (`neoul`, `choice`, `score`) with dropdown accordion toggles. | Verified in tests 6 & 7 of `end-to-end-architecture.spec.ts`. |
| **Live Engine Selection**  | ✅ Working | Instant | Top selector (`Jev`, `Laya`, `Both`) with auto-evaluating attack simulation. | Verified in test 7 of `end-to-end-architecture.spec.ts`. |
| **Audit Stream Search**    | ✅ Working | Instant | Real-time text filter and timestamp range filtering across audit logs. | Verified in test 7 of `end-to-end-architecture.spec.ts`. |
| **Archify Architecture UI**| ✅ Working | Instant | Inline 4-stage pipeline card `#archify-architecture` with smooth scroll button. | Verified in `tests/advanced-vectors.spec.ts`. |
| **Movable Dashboard Blocks**| ✅ Working | Instant | 6 modular draggable blocks with `[▲ Up]` / `[▼ Down]` buttons, index tracking, localStorage persistence, and layout reset. | Verified in test 8 of `end-to-end-architecture.spec.ts`. |
| **Dedicated Auth Enclaves**| ✅ Working | Instant | Separate `/signup` (Credential Enrollment) and `/login` (Auth Gateway) pages. | Verified in test 5 and 9 of `end-to-end-architecture.spec.ts`. |
| **Normal User vs Brute Force**| ✅ Working | <5ms | Legitimate users get `200 OK (NORMAL USER)` and `ROLE: NORMAL USER (LEGITIMATE)` badge; 5+ failures flag `Brute Force Attack` in red. | Verified in test 9 of `end-to-end-architecture.spec.ts`. |

---

## Supported Attack Comparison Vectors

1. **`benign_retry` / `benign_login`**: 1-2 failed login attempts without malicious syntax or elevated volume.
2. **`brute_force`**: High frequency of failed login attempts targeting a single account in short window.
3. **`password_spray`**: A single common or leaked password attempted horizontally across many distinct user accounts.
4. **`credential_stuffing`**: Testing known breached username:password combinations from past data leaks.
5. **`sqli` / `sqli_attempt`**: SQL injection syntax attempting authentication bypass or DB schema extraction (`'`, `--`, `OR 1=1 LIMIT 1--`, `UNION SELECT`).
6. **`xss`**: Cross-site scripting injection strings (`<script>`, `onerror=`, `javascript:`, SVG tags).
7. **`api_key_enumeration`**: Automated fuzzer scanning or token guessing targeting machine API endpoints (`nv_sec_fuzz_*`, bearer tokens).
8. **`mfa_exhaustion`**: Repeated rapid cycling of 6-digit OTP codes or MFA verification requests (bombing/fatigue).

---

## Archify Multi-Question Contract Primitives

- **`is_threat` / `is_attack` (type: `noul`)**: Continuous confidence value in `0.0 .. 1.0` indicating likelihood of anomalous or adversarial assault.
- **`threat_category` / `attack_type` (type: `choice`)**: Categorical classification mapping to `["benign_login", "brute_force", "sqli_attempt", "credential_stuffing", "password_spray", "api_key_enumeration", "mfa_exhaustion"]`.
- **`severity` (type: `score`)**: Risk score from `0.0` (benign) to `3.0` (active exploit risk).
