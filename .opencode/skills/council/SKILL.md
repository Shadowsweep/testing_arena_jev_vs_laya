---
name: council
description: Convenes a full software engineering council (Manager, Backend, Frontend, QA, Security, DevOps, and Critic) to deliberate and deliver production-ready software solutions.
---

# Advanced Engineering Council Protocol

When the user runs `/council <task>`:

Execute the deliberation pipeline through `@manager`:

1. **Phase 1: Feature Architecture & Domain Design**
   - Query `@backend-lead`: Database tables/collections, API route definitions, background jobs.
   - Query `@frontend-lead`: State store design, client component tree, data fetching, optimistic UI.

2. **Phase 2: Reliability, Security & Infrastructure Review**
   - Provide Phase 1 specs to:
     - `@tester-lead`: Unit and E2E coverage plan, edge case vectors, contract mock schemas.
     - `@security-lead`: Threat surface review, authentication token security, rate limiting, input sanitization.
     - `@devops-lead`: Containerization spec, build strategy, environment secrets, deployment pipeline.

3. **Phase 3: Adversarial Challenge**
   - Pass all findings to `@critic`:
     - Attack friction points between Backend and Frontend.
     - Highlight untested failure conditions or overly complex DevOps setups.

4. **Phase 4: Manager Synthesis & Final Verdict**
   - `@manager` evaluates all arguments, eliminates redundant fluff, and formats the authoritative consensus.
   - Present the finalized blueprint directly to the user.
