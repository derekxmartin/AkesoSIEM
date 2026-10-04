import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests/regression',
  outputDir: './build/test-results/regression',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',
  timeout: 30000,
  expect: { timeout: 3000 },
  use: {
    baseURL: 'http://127.0.0.1:4179',
    browserName: 'chromium',
    channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
    viewport: { width: 1440, height: 1000 },
    serviceWorkers: 'block',
  },
  webServer: {
    command: 'node tests/regression/serve.mjs',
    url: 'http://127.0.0.1:4179',
    reuseExistingServer: false,
  },
})
