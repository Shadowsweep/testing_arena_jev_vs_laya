import { test, expect } from '@playwright/test';

test.describe('Advanced Auth Mechanisms & Threat Vectors', () => {
  const baseUrl = 'http://localhost:3000';

  test('Multi-Auth APIs: Password, Machine API Key, MFA OTP', async ({ request }) => {
    // 1. Password Signup & Login
    const pwSignup = await request.post(`${baseUrl}/api/auth/password/signup`, {
      data: { username: 'SecDevOps', password: 'VaultPassword!2026', hint: 'SafeVault' }
    });
    expect(pwSignup.ok()).toBeTruthy();
    const signupData = await pwSignup.json();
    expect(signupData.success).toBe(true);

    const pwLogin = await request.post(`${baseUrl}/api/auth/password/login`, {
      data: { username: 'SecDevOps', password: 'VaultPassword!2026' }
    });
    expect(pwLogin.ok()).toBeTruthy();
    const loginData = await pwLogin.json();
    expect(loginData.success).toBe(true);
    expect(loginData.redirect).toContain('/user-dashboard');

    // 2. Machine API Key Generation & Verification
    const keyGen = await request.post(`${baseUrl}/api/auth/apikey/generate`, {
      data: { username: 'CICD-Worker-01' }
    });
    expect(keyGen.ok()).toBeTruthy();
    const keyData = await keyGen.json();
    expect(keyData.apiKey).toMatch(/^nv_sec_/);

    const keyVerify = await request.post(`${baseUrl}/api/auth/apikey/verify`, {
      headers: { 'x-api-key': keyData.apiKey }
    });
    expect(keyVerify.ok()).toBeTruthy();
    const keyVerifyData = await keyVerify.json();
    expect(keyVerifyData.success).toBe(true);
    expect(keyVerifyData.role).toBe('service_account');

    // 3. Step-up MFA OTP Flow
    const otpSend = await request.post(`${baseUrl}/api/auth/mfa/send-otp`, {
      data: { username: 'SecDevOps' }
    });
    expect(otpSend.ok()).toBeTruthy();
    const otpSendData = await otpSend.json();
    expect(otpSendData.codePreview).toBeDefined();

    const otpVerify = await request.post(`${baseUrl}/api/auth/mfa/verify-otp`, {
      data: { username: 'SecDevOps', code: otpSendData.codePreview }
    });
    expect(otpVerify.ok()).toBeTruthy();
    const otpVerifyData = await otpVerify.json();
    expect(otpVerifyData.success).toBe(true);
    expect(otpVerifyData.message).toBe('MFA verified');
  });

  test('Advanced Simulation Endpoints: Spray, Stuffing, SQLi, API Scan, MFA Bomb', async ({ request, page }) => {
    // Clear buffer first
    await request.post(`${baseUrl}/api/clear-buffer`);

    // 1. Password Spray
    const sprayRes = await request.post(`${baseUrl}/api/simulate/spray`, { data: { count: 30 } });
    expect(sprayRes.ok()).toBeTruthy();
    const sprayData = await sprayRes.json();
    expect(sprayData.attack_type).toBe('password_spray');

    // Evaluate
    const evalSpray = await request.post(`${baseUrl}/api/evaluate`);
    const evalSprayData = await evalSpray.json();
    expect(evalSprayData.jev.attack_type).toBe('password_spray');
    expect(evalSprayData.jev.is_attack).toBeGreaterThan(0.8);

    // 2. SQL Injection
    await request.post(`${baseUrl}/api/clear-buffer`);
    const sqliRes = await request.post(`${baseUrl}/api/simulate/sqli`, { data: { count: 15 } });
    expect(sqliRes.ok()).toBeTruthy();
    const evalSqli = await request.post(`${baseUrl}/api/evaluate`);
    const evalSqliData = await evalSqli.json();
    expect(evalSqliData.jev.attack_type).toBe('sqli');

    // 3. API Key Enumeration
    await request.post(`${baseUrl}/api/clear-buffer`);
    const scanRes = await request.post(`${baseUrl}/api/simulate/apikey-scan`, { data: { count: 25 } });
    expect(scanRes.ok()).toBeTruthy();
    const evalScan = await request.post(`${baseUrl}/api/evaluate`);
    const evalScanData = await evalScan.json();
    expect(evalScanData.jev.attack_type).toBe('api_key_enumeration');

    // 4. MFA Exhaustion Bombing
    await request.post(`${baseUrl}/api/clear-buffer`);
    const mfaRes = await request.post(`${baseUrl}/api/simulate/mfa-bomb`, { data: { count: 20 } });
    expect(mfaRes.ok()).toBeTruthy();
    const evalMfa = await request.post(`${baseUrl}/api/evaluate`);
    const evalMfaData = await evalMfa.json();
    expect(evalMfaData.jev.attack_type).toBe('mfa_exhaustion');

    // 5. Check UI for Archify Inline Architecture, Pagination, and Vector toolbar
    await page.goto('/security-dashboard');
    await expect(page.locator('#archify-btn')).toBeVisible();
    await page.click('#archify-btn');
    await expect(page.locator('#archify-architecture')).toBeVisible();
    await expect(page.locator('#archify-architecture')).toContainText('ARCHIFY // SYSTEM ARCHITECTURE');

    // Check pagination & grouping controls
    await expect(page.locator('#page-size-select')).toBeVisible();
    await expect(page.locator('#grp-target')).toBeVisible();
    await expect(page.locator('#grp-ip')).toBeVisible();
  });
});
