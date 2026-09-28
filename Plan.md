# Live Simulation Plan — Playwright + Jev AI + Laya (Login / Hint / Brute-Force Triage)

> Goal: 1-page live demo proving where Jev/Laya add value in testing: **1 legit user vs 200-login burst**, triaged side-by-side.
> Stack: Node+Express app on `3000`, Playwright TS (`--headed`), Jev cloud `https://api.typesafe.ai/v1/systemone`, Laya-stub on `8000` (same schema).
> Key: `TYPESAFE_API_KEY` pasted after plan (server-side `.env` only). Until then deterministic fallback so demo never blocks.

## 1. Why this is a good plan (and the better twist)

* Login+hint is the smallest flow that shows all 3 Jev primitives: `noul` (is_attack?), `choice` (attack_type), `score` (severity 0-3).
* Your idea (1 login → log, button → 200 logins → logs) is right. Better twist adopted here: **single "Compare Jev vs Laya" button** that sends the *same* log window to *both* engines and renders latency + verdict + confidence side-by-side. That is the whole sell: same input, two judges, live numbers.
* Code owns auth + rate-limit. AI only **labels** the log window after the fact. Never gate login on AI.

## 2. Architecture

```
[Browser: / (signup+login)] --POST /api/signup|login--> [Express:3000 + auditLogs[]]
        | Playwright (Actor: 1 legit + 200 burst)                |
        v                                                        v
[Security Dashboard:3000/security-dashboard] <--GET /api/logs--+
  [Simulate 1 User] [Simulate 200 Burst] [Playwright MCP]
  [Compare: Jev vs Laya] --> POST /api/evaluate?engine=both
    -> Jev cloud (jev-latest)  vs  Laya-stub localhost:8000 (same /v1/systemone shape)
  --> Description + Confidence + Latency table + Live Audit rows
[User Dashboard: /user-dashboard?user=] shows "Welcome, <name>" on correct login
```

## 3. App contract (`server.js`, 1 file)

* `POST /api/signup {username,password,hint}` → `users.set()`. No log row.
* `POST /api/login {username,password}` → `200 {redirect}` on match; else `401 {hint}` + `auditLogs.unshift({time,ip,username,maskedAttempt,status:'401'})`. Mask attempt to 20 chars. Hint returned only on fail.
* `GET /api/logs?limit=200` → last N rows (for dashboard poll every 1.5s + Jev state builder).
* `POST /api/simulate-burst {n=200, target='Utkarsh'}` → server-side loop generating N failed rows in <1s (fast; Playwright bulk would take minutes). Playwright still does ~6 real browser attempts for realism, then calls this for volume.
* `POST /api/evaluate?engine=jev|laya|both` → builds one `state` object from `auditLogs.slice(0,20)`, fans out to engine(s), returns `{jev:{...}, laya:{...}}` with `description, attack_type, severity, confidence, latency_ms`.
* Pages: `GET /` (forms `#reg-user,#reg-pass,#reg-hint,#login-user,#login-pass,#hint-msg`), `GET /user-dashboard?user=` (`[data-testid=user-welcome]`), `GET /security-dashboard` (buttons + `#eval-desc-jev,#eval-conf-jev,#eval-lat-jev` + same for laya + `#compare-table` + `#log-table tbody`).

## 4. Correct Jev/Laya schema (all 3 types, one call)

Prior snippets were wrong (`options`, `scale`). Use this for **both** engines:

```json
{
  "model": "jev-latest",
  "state": {"failed_attempts": 200, "window_seconds": 60, "ip": "192.168.1.105", "target_user": "Utkarsh", "samples": ["admin123","password","' OR '1'='1","qwerty","bruno"]},
  "questions": {
    "is_attack": {"type": "noul", "instructions": "Does `samples` with `failed_attempts` in `window_seconds` indicate brute-force, credential-stuffing, or injection?", "criteria": {"true": "Coordinated guesses/injection", "false": "Normal typo or single retry"}},
    "attack_type": {"type": "choice", "instructions": "Which best describes `samples`?", "criteria": {"benign_retry": "1-2 typos", "brute_force": "Many rapid generic guesses", "credential_stuffing": "Leaked-list style", "sqli": "SQL metachars, OR 1=1", "xss": "Script tags / event handlers"}},
    "severity": {"type": "score", "instructions": "Rate exploit risk of `samples` given `failed_attempts`", "criteria": ["Harmless typo", "Suspicious burst, no payload", "Clear attack pattern with injection", "Active exploitation / leak likely"]}
  }
}
```

Parse: `answers.is_attack.noul` (0-1, no confidence) + `answers.attack_type.choice/confidence` + `answers.severity.score/confidence`. Rule: `is_attack>0.8` = attack, `0.45-0.65` = review banner, `severity>=2` = red. Description = `"{attack_type} (severity {score:.1f}/3) via {ENGINE}"`.

## 5. Playwright (`simulation.spec.ts`)

* Flow A (1 user): signup `Utkarsh/Strong#2026/Bruno` → login → `expect(url).toMatch(/user-dashboard/)` + welcome text. Verifies 1 log-free success + hint path.
* Flow B (burst): 6 real `page.fill+click` fails (assert `#hint-msg` shows Bruno) → `POST /api/simulate-burst {n:200}` → goto `/security-dashboard` → `expect(rows).toHaveCount(206)` → click `Compare Jev vs Laya` → assert both desc contain `/brute|stuffing|attack/i`, both conf >80, latency cells numeric. `Playwright MCP` button = same burst but triggered via agent (`browser_snapshot` → loop) instead of script.
* Run: `node server.js & npx playwright test simulation.spec.ts --headed`.

## 6. Dashboard compare view (the demo moment)

1. Click `Simulate 1 User` → 1 row, compare → both say `benign_retry, conf ~84%, sev ~0.4`.
2. Click `Simulate 200 Burst` → table floods, compare → both flip to `brute_force/credential_stuffing, conf ~96%, sev ~2.5` with `jev ~230ms vs laya-stub ~35ms`.
3. Talking point: regex would miss `' OR '1'='1` variants; generative LLM would take 2s + hallucinate; encoder-only gives typed JSON in ms, immune to prompt-injection (no open text out).

## 7. Runbook

```
npm init -y; npm i express @playwright/test; npx playwright install chromium
# .env: TYPESAFE_API_KEY=<paste later>
node server.js            # 3000 app, 8000 laya-stub
npx playwright test --headed
```

Pass = A shows name, B shows 200+ rows + both engines agree + fallback works with no key.

## 8. Skipped (add when)

Real `laya-serve` GPU server, sqlite persistence, CSIC-2010/PayloadsAllTheThings corpus, MCP agent loop, per-payload calls. Add only when side-by-side accuracy measured low on your logs.
