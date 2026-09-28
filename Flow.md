# System Data Flow & Architecture

```mermaid
flowchart TD
    subgraph Client ["Client Browser / Playwright"]
        User["User / Security Actor / Test Spec"]
        TelemetryCollector["Client Interaction Telemetry (Keystrokes, Mouse Distance, Form Duration)"]
        SecDash["Security Dashboard (:3000/security-dashboard)"]
        UserDash["User Dashboard (:3000/user-dashboard)"]
    end

    subgraph Server ["Express App Server (:3000)"]
        SOARGuard{"SOAR Active Defense Guard (Dynamic Blocklist Check)"}
        
        subgraph AuthGateway ["Multi-Mechanism Auth Gateway"]
            PwRoute["Password Auth (/api/auth/password/*)"]
            ApiKeyRoute["Machine API Key (/api/auth/apikey/*)"]
            MfaRoute["Step-Up MFA OTP (/api/auth/mfa/*)"]
        end
        
        subgraph SimEngine ["Threat Simulation Generators"]
            BurstSim["Classic Brute Force (/api/simulate-burst)"]
            SpraySim["Password Spraying (/api/simulate/spray)"]
            StuffingSim["Credential Stuffing (/api/simulate/stuffing)"]
            SqliSim["SQL Injection Probes (/api/simulate/sqli)"]
            KeyScanSim["API Key Fuzzer (/api/simulate/apikey-scan)"]
            MfaBombSim["MFA Fatigue Bombing (/api/simulate/mfa-bomb)"]
        end

        UserStore[("User Map & Hint Vault")]
        KeyStore[("API Key Registry")]
        OtpStore[("MFA 6-digit TTL Cache")]
        AuditStore[("Rolling Audit Log Buffer + Telemetry")]
        IPBlocklist[("Dynamic IP Blacklist (15m TTL)")]
        
        EvalRoute["Evaluation Dispatcher (/api/evaluate)"]
        SOARAction["SOAR Containment Engine (Confidence >= 90%)"]
        HeuristicEngine["Deterministic Heuristic Fallback Engine"]
    end

    subgraph Engines ["Decision Engines"]
        JevCloud["Jev Cloud (https://api.typesafe.ai/v1/systemone)"]
        LayaStub["Laya Stub Service (:8000/v1/systemone)"]
    end

    User -->|Auth Request + Telemetry| SOARGuard
    SOARGuard -->|IP Blacklisted| 403Forbidden["403 Forbidden"]
    SOARGuard -->|Permitted| AuthGateway

    AuthGateway -->|Success| UserDash
    AuthGateway -->|Failed Attempt + Telemetry| AuditStore

    User -->|Simulate Attack Vectors| SimEngine
    SimEngine -->|Append Synthesized Attacks| AuditStore

    SecDash -->|Poll logs + Paginate / Group| AuditStore
    SecDash -->|POST /api/evaluate?engine=both| EvalRoute

    EvalRoute -->|Window top 20 events + metadata| AuditStore
    EvalRoute -->|Query if KEY present| JevCloud
    EvalRoute -->|Local HTTP SystemOne post| LayaStub
    EvalRoute -.->|Offline / No key fallback| HeuristicEngine

    EvalRoute -->|Attack Conf >= 90%| SOARAction
    SOARAction -->|Add Offending IP (15m TTL)| IPBlocklist

    EvalRoute -->|Return side-by-side JSON comparison| SecDash
    SecDash -->|Updates| LiveBenchmark["Live Model Benchmark Widget (~33ms vs ~240ms)"]
    SecDash -->|Updates| SOARBadge["Dynamic SOAR Status Badge (Monitoring / Blacklisted)"]
    SecDash -->|Dynamically Renders| Primitives["3 Collapsible Reasoning Tables: 1. Neoul (p>0.8) | 2. Choice (5 categories) | 3. Score (0-3 severity)"]
    SecDash -->|Real-Time Text & Range Filter| AuditSearch["Search Filter & Timestamps (IP, User, Payload, 60s window)"]
```

## Security & Architectural Principles
1. **Closed-Loop SOAR Active Defense:** Passive classification is converted into inline containment. Once an engine returns >= 90% confidence for an ongoing attack, the offending IP is dynamically contained with a 15-minute TTL, blocking subsequent requests with immediate `403 Forbidden`.
2. **Client-Side Behavioral Telemetry:** Login forms capture keystroke intervals, total completion latency, and 2D cursor distance, detecting synthetic bot engines that fill forms instantaneously without mouse trajectories.
3. **Multi-Question Classification:** Evaluates both detection (`is_threat`: continuous `noul` scale 0..1) and precise categorization (`threat_category`: categorical choice `sqli_attempt`, `credential_stuffing`, `brute_force`, `benign_login`) in a single forward pass.
4. **Decision Reasoning Primitives (Neoul, Choice, Score):** Transparent explainability broken down into continuous anomaly probability (`neoul`), candidate attack vector matching (`choice`), and exploit risk severity grading (`score`).
5. **Live Model Benchmark Analysis:** Side-by-side comparison tracks real-world operational tradeoffs: local in-process Laya daemon (~33ms, 100% on-premises, $0 cost) vs cloud managed Jev SystemOne (~240ms, TLS payload egress, per-call billing).
6. **Zero-Delay Heuristic Fallback:** Offline or unauthenticated test environments execute with zero delay (<1ms) using local heuristics mirroring SystemOne typed decision contracts (`noul`, `choice`, `score`).

