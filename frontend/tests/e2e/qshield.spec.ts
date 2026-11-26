import { test, expect } from '@playwright/test';

test.describe('Q-SHIELD End-to-End Console Workflows', () => {
  test('Landing Page -> Interactive Login -> Dashboard Telemetry -> Scenario Lab -> Logout', async ({ page }) => {
    // 1. Visit landing page
    await page.goto('/');
    await expect(page).toHaveTitle(/Q-SHIELD/i);
    await expect(page.locator('h1')).toContainText(/Post-Quantum Zero-Trust Control Plane/i);

    // Verify readiness probe loads
    await expect(page.locator('text=ML-KEM-768 · ML-DSA-65 · AES-256-GCM · HKDF-SHA-256')).toBeVisible({ timeout: 10000 });

    // 2. Navigate to Login Page
    await page.click('text=Launch Interactive Demo Login');
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator('h1')).toContainText(/Q-SHIELD Synthetic Demo Sign-In/i);

    // Click "Use" on the exact persona card row for Security Operator
    const secopsRow = page.locator('div', { hasText: 'Security Operator (Revocations, Keys, Alerts)' }).filter({ has: page.locator('button:has-text("Use")') }).last();
    await secopsRow.locator('button:has-text("Use")').click();

    // 3. Verify successful entry into Security Dashboard
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.locator('h1')).toContainText(/Security Control-Plane Overview/i);
    await expect(page.locator('text=Simulated Nodes')).toBeVisible({ timeout: 10000 });

    // 4. Navigate to Scenarios Lab
    await page.click('a[href="/scenarios"]');
    await expect(page).toHaveURL(/\/scenarios/);
    await expect(page.locator('h1')).toContainText(/Deterministic Security Scenarios/i, { timeout: 10000 });
    await expect(page.locator('text=normal_protected_read')).toBeVisible({ timeout: 10000 });

    // Run single scenario: normal_protected_read
    const runBtn = page.locator('tr', { hasText: 'normal_protected_read' }).locator('button:has-text("Run Scenario")');
    await runBtn.click();
    await expect(page.locator('text=completed successfully')).toBeVisible({ timeout: 15000 });

    // 5. Navigate to Vault & Policy
    await page.click('a[href="/vault"]');
    await expect(page).toHaveURL(/\/vault/);
    await expect(page.locator('h1')).toContainText(/Protected Vault & Zero-Trust Policy Engine/i);

    // 6. Sign out cleanly
    await page.click('button:has-text("Sign out")');
    await expect(page).toHaveURL(/\/login/);
  });
});
