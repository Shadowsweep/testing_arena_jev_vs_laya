# Agent Rules — Memory, Handoff, and Documentation Discipline

Hii , i am Utkarsh Gupta , a curious full-stack developer who loves exploring how things work, turning ideas into working products, and constantly experimenting with code, AI, and new technologies.

These rules are mandatory for every session and every task in this repository.

## 1. After every successful task

- Update [`memory.md`](memory.md) with a dated entry describing what was done, which files changed, and how it was verified (typecheck, lint, tests, build).

- Update [`HANDOFF.md`](HANDOFF.md) so the next session can continue without re-discovering the work. Replace stale "fixed" claims for the touched feature instead of appending duplicates.

## 2. When Backend or Architecture changes

- Backend API/service/model changes → update [`BACKEND.md`](BACKEND.md) (and [`DATABASE.md`](DATABASE.md) if the schema or migrations changed).

- Security Dashboard / Evaluation / AI triage changes → update [`EVALUATION.md`](EVALUATION.md) (status table: working / not working, implementation notes, regression advice).

- Structural or data-flow changes → update the relevant files under [`Architecture/`](Architecture/) and [`Flow.md`](Flow.md).

- New user-facing feature → document it in [`README.md`](README.md) if it changes how the product is used.

## 3. Context/limit below 10% — checkpoint immediately

When the remaining session limit drops below 10%, stop starting new work and immediately:

1. Write the current status of the code to [`memory.md`](memory.md) and [`HANDOFF.md`](HANDOFF.md): what is done and verified, what is in progress, what is broken, and the exact next step.

2. Never leave uncommitted, undocumented work behind. A half-finished feature must be described honestly as unfinished.

## 4. Report honestly

- If a feature is not working, say so explicitly — in the conversation, in `memory.md`, and in the status tables (`❌ Not working` / `⚠️ Partial`). Never mark anything ✅ that was not verified by running it.

- If verification was skipped or could not run, state that instead of implying success.

## 5. Authentication and loading states must never be unbounded

- Login, home-to-dashboard redirects, session verification, and authentication-related loading gates must either complete or present an actionable retry/error state within a fixed deadline. Never leave users on a permanent `Rendering`, blank, or loading screen.

- Do not interpret an auth transport/database timeout as a signed-out user. Preserve the current page and offer **Retry session** plus an explicit fresh-sign-in path; redirect to `/login` only after a completed session check confirms there is no session.

- Every change touching auth, redirects, the home page, or loading gates must add or run browser coverage for: valid-session login/home redirect, dashboard reload with a valid session, and stalled session/profile recovery.

## 6. Self-Correcting Rules Engine

These rules improve over time based on actual project feedback and discoveries.

1. When the user corrects you or you make a mistake, immediately append a new rule to this section.
2. Rules are numbered sequentially and written as clear, imperative instructions.
3. Format: `N. [CATEGORY] Never/Always do X — because Y.`
4. Categories: `[STYLE]`, `[CODE]`, `[ARCH]`, `[TOOL]`, `[DATA]`, `[UX]`, `[PROCESS]`, `[DOCS]`, `[OTHER]`.
5. Before starting any task, apply all relevant rules.
6. If two rules conflict, the higher-numbered (newer) rule wins.
7. Never delete old rules. If a rule becomes obsolete, append a new rule that supersedes it.

### When to add a rule

- User explicitly corrects your output.
- User rejects a file, approach, or pattern.
- You hit a bug caused by a wrong assumption about the codebase.
- User states a preference such as "always use X" or "never do Y".
- A project-specific discovery creates a reusable engineering rule.

### Rule format example

```text
14. [CODE] Always use `bun` instead of `npm` — user preference and `bun` is installed globally.
15. [STYLE] Never add emojis to commit messages — project convention.
16. [ARCH] Keep API routes inside `src/server/routes/` — existing codebase pattern.
```

## 7. Learned Rules

1. [ARCH] Inspect the existing code and architecture before making implementation decisions.

2. [CODE] Fix the root cause instead of adding a workaround when the underlying state or logic is incorrect.

3. [PROCESS] Prefer the smallest safe change that solves the requested problem.

4. [PERF] Measure a bottleneck before optimizing or claiming that something is slow.

5. [TEST] Verify important changes with relevant tests or checks before declaring them complete.

6. [DOCS] Keep [`memory.md`](memory.md) and [`HANDOFF.md`](HANDOFF.md) synchronized with completed and unfinished work so future sessions can continue without rediscovery.

7. [DOCS] Update architecture and feature documentation when backend, data-flow, security triage, or user-facing behavior changes.

8. [SECURITY] Never treat an authentication timeout as proof that a user is signed out; require a completed session check before redirecting to login.

9. [TEST] Authentication/loading changes must cover successful session flow, dashboard reload, and stalled session/profile recovery.

10. [AI/FALLBACK] Always keep deterministic heuristic fallbacks for Jev and Laya — ensuring demos and test suites execute reliably without blocking on remote API keys or network downtime.

11. [TEST] Automated Playwright tests must assert end-to-end flows for both single user registration/login and bulk security bursts with live model comparison.
