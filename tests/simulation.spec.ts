import { test, expect } from '@playwright/test';

test.describe('Auth sim: 1 user vs 200 burst, Jev vs Laya', () => {
  const user = 'Utkarsh';
  const pass = 'StrongPassword#2026';
  const hint = 'Bruno';

  test('Flow A: signup + login -> personal dashboard', async ({ page }) => {
    await page.goto('/signup');
    await page.fill('#reg-user', user);
    await page.fill('#reg-pass', pass);
    await page.fill('#reg-hint', hint);
    page.once('dialog', (d) => d.accept());
    await page.click('button:has-text("Sign Up")');
    await page.fill('#login-user', user);
    await page.fill('#login-pass', pass);
    await page.click('button:has-text("Log In")');
    await expect(page).toHaveURL(/user-dashboard/);
    await expect(page.locator('[data-testid="user-welcome"]')).toHaveText(`Welcome to your Dashboard, ${user}!`);
  });

  test('Flow B: 6 real fails + 200 burst -> compare Jev vs Laya', async ({ page }) => {
    await page.goto('/');
    for (const guess of ['admin123', 'password', '12345678', 'bruno', "' OR '1'='1", 'qwerty']) {
      await page.fill('#login-user', user);
      await page.fill('#login-pass', guess);
      await page.click('button:has-text("Log In")');
      await expect(page.locator('#hint-msg')).toContainText(hint);
    }
    await page.request.post('http://localhost:3000/api/simulate-burst', { data: { n: 200, target: user } });
    await page.goto('/security-dashboard');
    await expect(page.locator('#log-table tbody tr').first()).toBeVisible();
    await page.click('button:has-text("Compare Jev vs Laya")');
    await expect(page.locator('#eval-desc-jev')).toContainText(/brute|stuffing|sqli|xss|attack/i, { timeout: 20000 });
    await expect(page.locator('#eval-desc-laya')).toContainText(/brute|stuffing|sqli|xss|attack/i);
    for (const id of ['#eval-conf-jev', '#eval-conf-laya']) {
      const v = parseFloat(((await page.locator(id).innerText()).replace(/[^0-9.]/g, '')));
      expect(v).toBeGreaterThan(80);
    }
    for (const id of ['#eval-lat-jev', '#eval-lat-laya']) {
      await expect(page.locator(id)).toContainText(/ms/);
    }
  });
});
