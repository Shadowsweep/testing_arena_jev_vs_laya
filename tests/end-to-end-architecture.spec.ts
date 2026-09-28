import { test, expect } from '@playwright/test';

test.describe('End-to-End Security Architecture & SOAR Active Defense', () => {
  const baseUrl = 'http://localhost:3000';

  test.beforeEach(async ({ request }) => {
    // Reset buffer and unblock any previously blacklisted IPs
    await request.post(`${baseUrl}/api/clear-buffer`);
    await request.post(`${baseUrl}/api/soar/unblock`);
  });

  test('1. Closed-Loop Automated Mitigation (SOAR Action) with Dynamic Blocklist', async ({ request, page }) => {
    const maliciousIp = '192.168.1.105';

    // Send a burst of failed attempts pretending to come from maliciousIp
    for (let i = 0; i < 10; i++) {
      await request.post(`${baseUrl}/api/auth/password/login`, {
        headers: { 'x-forwarded-for': maliciousIp },
        data: { username: 'admin', password: `guess_${i}` }
      });
    }

    // Trigger AI Triage Evaluation
    const evalRes = await request.post(`${baseUrl}/api/evaluate`);
    expect(evalRes.ok()).toBeTruthy();
    const evalData = await evalRes.json();

    // Verify AI confidence > 90% and attack detected
    expect(evalData.state.ip).toBe(maliciousIp);
    const maxConf = Math.max(evalData.jev?.confidence || 0, evalData.laya?.confidence || 0);
    expect(maxConf).toBeGreaterThanOrEqual(90);

    // Verify SOAR Active Defense auto-contained the IP
    expect(evalData.soar?.mitigatedIp).toBe(maliciousIp);

    // Playwright sends another request from that IP and verifies immediate 403 Forbidden
    const blockedRes = await request.post(`${baseUrl}/api/auth/password/login`, {
      headers: { 'x-forwarded-for': maliciousIp },
      data: { username: 'admin', password: 'ValidPassword!123' }
    });
    expect(blockedRes.status()).toBe(403);
    const blockedJson = await blockedRes.json();
    expect(blockedJson.error).toContain('Forbidden: IP Blacklisted by SOAR Active Defense');
    expect(blockedJson.ip).toBe(maliciousIp);

    // Verify Security UI badge changes from Monitoring to Blacklisted
    await page.goto('/security-dashboard');
    const badge = page.locator('#soar-status-badge');
    await expect(badge).toBeVisible();
    await expect(badge).toContainText(`IP ${maliciousIp} Blacklisted (TTL: 15m)`);

    // Verify manual unblock restores monitoring state
    await page.click('#soar-unblock-btn');
    await expect(badge).toHaveText('Status: Monitoring');
  });

  test('2. Multi-Vector Red-Teaming Matrix & Multi-Question Classification', async ({ request, page }) => {
    // A. SQL Injection (SQLi) Bypass Probe into login form
    await page.goto('/');
    await page.fill('#login-user', "' OR '1'='1");
    await page.fill('#login-pass', "admin' --");
    await page.click('button:has-text("Log In")');
    await expect(page.locator('#msg')).toContainText('Invalid credentials');

    // Multi-Question Classification in a single forward pass
    const evalSqli = await request.post(`${baseUrl}/api/evaluate`);
    const sqliData = await evalSqli.json();
    expect(sqliData.laya?.is_threat).toBeGreaterThan(0.8);
    expect(sqliData.laya?.threat_category).toMatch(/sqli|sqli_attempt/i);
    expect(sqliData.laya?.severity).toBeGreaterThan(2.0);

    // B. Credential Stuffing (slow-and-low across 20 user targets)
    await request.post(`${baseUrl}/api/clear-buffer`);
    const stuffingRes = await request.post(`${baseUrl}/api/simulate/stuffing`, { data: { count: 20 } });
    expect(stuffingRes.ok()).toBeTruthy();

    const evalStuffing = await request.post(`${baseUrl}/api/evaluate`);
    const stuffingData = await evalStuffing.json();
    expect(stuffingData.laya?.threat_category).toMatch(/credential_stuffing|stuffing/i);
    expect(stuffingData.laya?.is_threat).toBeGreaterThan(0.8);
  });

  test('3. Client-Side Behavioral Telemetry (Bot Detection)', async ({ request, page }) => {
    // Fill login form via page and submit
    await page.goto('/');
    await page.fill('#login-user', 'ScriptBot');
    await page.fill('#login-pass', 'RapidAutoPass#1');
    await page.click('button:has-text("Log In")');

    // Inspect recent audit state for telemetry capture
    const evalRes = await request.post(`${baseUrl}/api/evaluate`);
    const evalJson = await evalRes.json();
    expect(evalJson.state.telemetry_summary).toBeDefined();
    // Bot characteristics: 0 mouse distance moved, sub-second execution
    expect(evalJson.state.telemetry_summary.avg_mouse_distance_px).toBe(0);
    expect(evalJson.state.telemetry_summary.is_synthetic_bot).toBe(true);
  });

  test('4. Live Model Benchmark Widget (Laya vs Jev)', async ({ page }) => {
    await page.goto('/security-dashboard');
    const benchWidget = page.locator('#tour-benchmark-widget');
    await expect(benchWidget).toBeVisible();

    // Verify benchmark architectural dimensions are rendered
    await expect(benchWidget).toContainText('Inference Latency');
    await expect(benchWidget).toContainText('Deployment Topology');
    await expect(benchWidget).toContainText('Data Egress & Boundary');
    await expect(benchWidget).toContainText('Cost per 10,000 Evals');

    // Trigger dual model evaluation
    await page.click('button:has-text("Compare Jev vs Laya")');

    // Verify live latency updates in the benchmark card
    await expect(page.locator('#bench-lat-laya')).toContainText(/ms/, { timeout: 15000 });
    await expect(page.locator('#bench-lat-jev')).toContainText(/ms/, { timeout: 15000 });
  });

  test('5. Automated Recovery via Hint Assertion', async ({ page }) => {
    const testUser = 'RecoveryHero';
    const testPass = 'VaultSecret#2026';
    const secretHint = 'Pet name is Bruno';

    // 1. Sign up new account
    await page.goto('/signup');
    await page.fill('#reg-user', testUser);
    await page.fill('#reg-pass', testPass);
    await page.fill('#reg-hint', secretHint);
    page.once('dialog', (d) => d.accept());
    await page.click('button:has-text("Sign Up")');

    // 2. Attempt 3 incorrect passwords to trigger hint UI
    for (const badGuess of ['wrong1', 'badPassword#9', 'incorrectGuess']) {
      await page.fill('#login-user', testUser);
      await page.fill('#login-pass', badGuess);
      await page.click('button:has-text("Log In")');
      await expect(page.locator('#msg')).toContainText('Invalid credentials');
    }

    // 3. Extract the hint from the DOM
    const hintText = await page.locator('#hint-msg').innerText();
    expect(hintText).toContain('Bruno');

    // 4. Use the recovered hint to submit the correct password
    await page.fill('#login-user', testUser);
    await page.fill('#login-pass', testPass);
    await page.click('button:has-text("Log In")');

    // 5. Confirm user transitions successfully into the personal dashboard
    await expect(page).toHaveURL(/user-dashboard/);
    await expect(page.locator('[data-testid="user-welcome"]')).toHaveText(`Welcome to your Dashboard, ${testUser}!`);
  });

  test('6. Decision Reasoning Primitives: Neoul, Choice, Score Tables and Filter Toggles', async ({ page }) => {
    await page.goto('/security-dashboard');

    // 1. Verify all 3 primitive sections exist and are visible
    const primitivesCard = page.locator('#tour-reasoning-primitives');
    await expect(primitivesCard).toBeVisible();

    const noulSection = page.locator('#section-primitive-noul');
    const choiceSection = page.locator('#section-primitive-choice');
    const scoreSection = page.locator('#section-primitive-score');

    await expect(noulSection).toBeVisible();
    await expect(choiceSection).toBeVisible();
    await expect(scoreSection).toBeVisible();

    // 2. Test view switching
    // Click 1. Neoul
    await page.click('#prim-tab-noul');
    await expect(noulSection).toBeVisible();
    await expect(choiceSection).toBeHidden();
    await expect(scoreSection).toBeHidden();

    // Click 2. Choice
    await page.click('#prim-tab-choice');
    await expect(noulSection).toBeHidden();
    await expect(choiceSection).toBeVisible();
    await expect(scoreSection).toBeHidden();

    // Click 3. Score
    await page.click('#prim-tab-score');
    await expect(noulSection).toBeHidden();
    await expect(choiceSection).toBeHidden();
    await expect(scoreSection).toBeVisible();

    // Click All Sections
    await page.click('#prim-tab-all');
    await expect(noulSection).toBeVisible();
    await expect(choiceSection).toBeVisible();
    await expect(scoreSection).toBeVisible();

    // 3. Trigger SQLi attack simulation and evaluate
    await page.click('button:has-text("SQLi Bypass")');
    await page.click('button:has-text("Compare Jev vs Laya")');

    // 4. Verify tables update dynamically with reasoning
    await expect(page.locator('#noul-verdict-tag')).toContainText(/ATTACK DETECTED/, { timeout: 15000 });
    await expect(page.locator('#choice-winner-tag')).toContainText(/SQLI/, { timeout: 15000 });
    await expect(page.locator('#choice-status-sqli')).toContainText('MATCHED');
    await expect(page.locator('#choice-reason-sqli')).toContainText(/SQL metacharacters/i);
    await expect(page.locator('#score-status-3')).toContainText('ACTIVE');
    await expect(page.locator('#score-val-tag')).toContainText(/3\.0/);
  });

  test('7. Live System Controls: Engine Selectors, Auto-Eval Simulation, In-Depth Accordion Dropdowns & Search Filters', async ({ page }) => {
    await page.goto('/security-dashboard');

    // 1. Verify Top Engine Selector Buttons & Clear Buffer Corner
    const selJev = page.locator('#engine-sel-jev');
    const selLaya = page.locator('#engine-sel-laya');
    const selBoth = page.locator('#engine-sel-both');
    const clearBtn = page.locator('#btn-clear-buffer-corner');

    await expect(selJev).toBeVisible();
    await expect(selLaya).toBeVisible();
    await expect(selBoth).toBeVisible();
    await expect(clearBtn).toBeVisible();

    // 2. Select Jev AI engine and trigger "1 User" (sim auto-evaluates instantly!)
    await selJev.click();
    await expect(selJev).toHaveClass(/badge-green/);

    await page.click('button:has-text("1 User")');
    await expect(page.locator('#eval-status-indicator')).toContainText('EVALUATION COMPLETE', { timeout: 15000 });
    await expect(page.locator('#eval-desc')).toContainText(/benign/i);

    // 3. Test In-Depth Dropdown Accordion Collapsible toggles
    const wrapNoul = page.locator('#wrap-primitive-noul');
    const btnToggleNoul = page.locator('#btn-toggle-noul');
    await expect(wrapNoul).toBeVisible();

    // Collapse
    await btnToggleNoul.click();
    await expect(wrapNoul).toBeHidden();
    await expect(btnToggleNoul).toContainText('In-Depth Details');

    // Re-expand
    await btnToggleNoul.click();
    await expect(wrapNoul).toBeVisible();

    // 4. Test Audit Log Search Filter & Timestamp formatting
    const searchFilter = page.locator('#log-search-filter');
    await expect(searchFilter).toBeVisible();

    // Check timestamp column
    const timeCell = page.locator('#log-table tbody tr.log-entry td').first();
    await expect(timeCell).toBeVisible();

    // Filter by specific user
    await searchFilter.fill('Utkarsh');
    await expect(page.locator('#pagination-info')).toContainText('Filtered');
    await expect(page.locator('#log-table tbody')).toContainText('Utkarsh');

    // Filter by nonexistent string
    await searchFilter.fill('nonexistent_gibberish_query_xyz');
    await expect(page.locator('#log-table tbody')).toContainText('No matching audit logs recorded');

    // Reset filter
    await page.click('button:has-text("Reset Filter")');
    await expect(searchFilter).toHaveValue('');

    // 5. Test Clear Buffer from Right Corner
    await clearBtn.click();
    await expect(page.locator('#nav-log-count')).toContainText('0 logs');
    await expect(page.locator('#eval-status-indicator')).toContainText('READY FOR TRIAGE');
  });

  test('8. Dynamic Movable Dashboard Blocks: Shift Up/Down Reordering & Layout Reset', async ({ page }) => {
    await page.goto('/security-dashboard');
    await page.waitForLoadState('networkidle');

    const container = page.locator('#dashboard-blocks-container');
    await expect(container).toBeVisible();

    // Verify all 6 blocks exist
    const blockControls = page.locator('#block-controls');
    const blockTriage = page.locator('#block-triage');
    const blockBenchmark = page.locator('#block-benchmark');
    const blockPrimitives = page.locator('#block-primitives');
    const blockAudit = page.locator('#block-audit');
    const blockArchify = page.locator('#block-archify');

    await expect(blockControls).toBeVisible();
    await expect(blockTriage).toBeVisible();
    await expect(blockBenchmark).toBeVisible();
    await expect(blockPrimitives).toBeVisible();
    await expect(blockAudit).toBeVisible();
    await expect(blockArchify).toBeVisible();

    // Block 1 up-button should initially be disabled
    const topUpBtn = blockControls.locator('.btn-shift-up');
    await expect(topUpBtn).toBeDisabled();

    // Shift Block 1 down
    const topDownBtn = blockControls.locator('.btn-shift-down');
    await expect(topDownBtn).toBeEnabled();
    await topDownBtn.click();

    // Now #block-triage is first, and #block-controls is second
    const firstChild = container.locator('> .dashboard-block').nth(0);
    const secondChild = container.locator('> .dashboard-block').nth(1);
    await expect(firstChild).toHaveId('block-triage');
    await expect(secondChild).toHaveId('block-controls');
    await expect(secondChild.locator('.block-idx')).toHaveText('02');

    // Shift Block Controls back up
    await blockControls.locator('.btn-shift-up').click();
    await expect(container.locator('> .dashboard-block').nth(0)).toHaveId('block-controls');
    await expect(container.locator('> .dashboard-block').nth(1)).toHaveId('block-triage');

    // Test Reset Layout button in top nav
    const resetBtn = page.locator('#btn-reset-layout');
    await expect(resetBtn).toBeVisible();
    await resetBtn.click();
    await expect(container.locator('> .dashboard-block').nth(0)).toHaveId('block-controls');
  });

  test('9. Legitimate Normal User Login vs Brute Force Flagging at 5 Attempts', async ({ page, request }) => {
    const normalUser = 'LegitUser';
    const normalPass = 'CorrectPassword#2026';
    const hint = 'SecretKey';

    // 1. Register legitimate user via dedicated /signup page
    await page.goto('/signup');
    await page.fill('#reg-user', normalUser);
    await page.fill('#reg-pass', normalPass);
    await page.fill('#reg-hint', hint);
    page.once('dialog', (d) => d.accept());
    await page.click('button:has-text("Sign Up")');

    // 2. Normal Login with correct password -> redirects to dashboard as Normal User
    await page.fill('#login-user', normalUser);
    await page.fill('#login-pass', normalPass);
    await page.click('button:has-text("Log In")');
    await expect(page).toHaveURL(/user-dashboard/);
    await expect(page.locator('[data-testid="role-badge"]')).toContainText('ROLE: NORMAL USER (LEGITIMATE)');

    // 3. Verify audit log entry on /security-dashboard is logged as status 200 normal user
    await page.goto('/security-dashboard');
    const normalRow = page.locator('#log-table tbody tr', { hasText: normalUser }).first();
    await expect(normalRow).toBeVisible();
    await expect(normalRow).toContainText('200 OK (NORMAL USER)');

    // 4. Test failed attempts below limit (< 5): classified as Normal User Retry
    await page.goto('/login');
    for (let i = 1; i <= 4; i++) {
      await page.fill('#login-user', normalUser);
      await page.fill('#login-pass', `wrong_pass_${i}`);
      await page.click('button:has-text("Log In")');
      await expect(page.locator('#msg')).toContainText(`attempt ${i} of 5`);
    }

    // 5. 5th failed attempt reaches limit -> FLAGGED as Brute Force Attack
    await page.fill('#login-user', normalUser);
    await page.fill('#login-pass', 'wrong_pass_5');
    await page.click('button:has-text("Log In")');
    await expect(page.locator('#msg')).toContainText('Brute Force Attack Detected');

    // 6. Verify security dashboard audit table flags the attack
    await page.goto('/security-dashboard');
    const flaggedRow = page.locator('#log-table tbody tr', { hasText: '401 (ATTACK FLAGGED)' }).first();
    await expect(flaggedRow).toBeVisible();
  });
});
