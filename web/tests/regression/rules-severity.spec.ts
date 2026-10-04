import { test, expect, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'

const rulesResponse = JSON.parse(readFileSync(new URL('../fixtures/rules-api.json', import.meta.url), 'utf8'))

type Alert = Record<string, any>
const labels = ['informational', 'low', 'medium', 'high', 'critical']
const title = (value: string) => value[0].toUpperCase() + value.slice(1)

function alert(id: string, fields: Alert): Alert {
  // Shape returned by internal/alert/APIHandler: ECS document plus hit metadata.
  return {
    _id: id,
    _index: 'akeso-alerts-test',
    '@timestamp': '2026-10-03T12:00:00Z',
    source: { ip: '192.0.2.10' },
    ...fields,
    event: { outcome: 'new', ...fields.event },
    rule: { name: id, description: 'Isolated regression alert', ...fields.rule },
  }
}

async function isolate(page: Page, { rules = rulesResponse, alerts = [], detail, rulesStatus = 200 }: {
  rules?: any, alerts?: Alert[], detail?: Alert, rulesStatus?: number
} = {}) {
  const writes: { path: string, body: any }[] = []
  const unexpected: string[] = []
  const errors: string[] = []
  page.on('pageerror', err => errors.push(err.message))
  await page.addInitScript(() => localStorage.setItem('akeso-refresh-token', 'isolated-test-token'))
  await page.route('**/*', async route => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.origin !== 'http://127.0.0.1:4179') {
      unexpected.push(request.url())
      return route.abort()
    }
    if (!url.pathname.startsWith('/api/')) return route.continue()
    const path = url.pathname.replace('/api/v1', '')
    let body: any
    let status = 200
    if (path === '/auth/refresh') body = { access_token: 'test-token', expires_in: 3600 }
    else if (path === '/auth/profile') body = { username: 'regression', role: 'admin' }
    else if (path === '/rules') { body = rules; status = rulesStatus }
    else if (path === '/alerts') body = { alerts, total: alerts.length, from: 0, size: 1000 }
    else if (request.method() === 'GET' && path === `/alerts/${detail?._id}`) body = detail
    else if (path === '/cases' || (path.startsWith('/alerts/') && request.method() === 'PATCH')) {
      writes.push({ path, body: request.postDataJSON() })
      body = { status: 'updated' }
    } else {
      unexpected.push(`${request.method()} ${path}`)
      status = 501
      body = { error: 'Unmocked API request' }
    }
    await route.fulfill({ status, json: body })
  })
  return { writes, unexpected, errors }
}

test('all 107 real API rule IDs survive grouping and clearing filters', async ({ page }) => {
  expect(rulesResponse.total).toBe(107)
  const ids = rulesResponse.rules.map(r => r.id).sort()
  expect(new Set(ids).size).toBe(107)
  const state = await isolate(page)
  await page.goto('/rules')
  await expect(page.getByRole('button', { name: /^Execution \(/ })).toBeVisible()
  const visibleIDs = () => page.locator('[data-rule-id]').evaluateAll(rows =>
    [...new Set(rows.map(row => row.getAttribute('data-rule-id')))].sort())
  expect(await visibleIDs()).toEqual(ids)
  await expect(page.getByText('107/107 enabled', { exact: true })).toBeVisible()
  const severity = page.getByRole('combobox').nth(0)
  await severity.selectOption('critical')
  expect(await visibleIDs()).toEqual(rulesResponse.rules.filter(r => r.severity === 'critical').map(r => r.id).sort())
  await page.getByRole('button', { name: 'Clear', exact: true }).click()
  expect(await visibleIDs()).toEqual(ids)
  // Every occurrence is rendered, not merely present in hidden/collapsed groups.
  expect(await page.locator('[data-rule-id]').evaluateAll(rows => rows.every(row => row.getClientRects().length > 0))).toBe(true)
  const memberships = await page.locator('[data-tactic-id]').evaluateAll(groups => groups.map(group => ({
    id: group.getAttribute('data-tactic-id'),
    count: group.querySelectorAll('[data-rule-id]').length,
    header: group.querySelector('button')?.textContent,
  })))
  for (const group of memberships) expect(group.header).toContain(`(${group.count} rule`)
  expect(state.errors).toEqual([])
  expect(state.unexpected).toEqual([])
})

test('unknown, missing and multiple tactics preserve unique counts and disabled controls', async ({ page }) => {
  const base = rulesResponse.rules[0]
  const rules = [
    { ...base, id: 'unknown', name: 'Unknown tactic rule', tactic: 'future_tactic', tactics: ['future_tactic'] },
    { ...base, id: 'missing', name: 'Missing tactic rule', tactic: undefined, tactics: undefined },
    { ...base, id: 'null', name: 'Null tactic rule', tactic: null, tactics: null },
    { ...base, id: 'empty', name: 'Empty tactic rule', tactic: '', tactics: [] },
    { ...base, id: 'multi', name: 'Multi tactic rule', tactic: 'credential_access', tactics: ['execution', 'credential_access', 'execution'] },
    { ...base, id: 'mixed', name: 'Mixed tactic rule', tactic: 'execution', tactics: ['execution', 'future_tactic'] },
    { ...base, id: 'legacy', name: 'Legacy label rule', tactic: 'Credential Access', tactics: undefined },
  ]
  const state = await isolate(page, { rules: { total: 8, rules: [...rules, rules[4]] } })
  await page.goto('/rules')
  await expect(page.getByRole('button', { name: /^Other \/ Unspecified \(5 rules\)/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /^Execution \(2 rules\)/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /^Credential Access \(2 rules\)/ })).toBeVisible()
  await expect(page.getByText('7/7 enabled', { exact: true })).toBeVisible()
  await expect(page.locator('[data-rule-id="multi"]')).toHaveCount(2)
  const toggles = page.getByRole('switch')
  await expect(toggles).toHaveCount(9)
  for (const toggle of await toggles.all()) await expect(toggle).toBeDisabled()
  expect(state.writes).toEqual([])
  expect(state.unexpected).toEqual([])
})

test('a successful empty Rules response is an empty state', async ({ page }) => {
  await isolate(page, { rules: { total: 0, rules: [] } })
  await page.goto('/rules')
  await expect(page.getByText('No rules match the current filters.')).toBeVisible()
  await expect(page.getByRole('alert')).toHaveCount(0)
})

test('Rules API failures are distinct from an empty list', async ({ page }) => {
  await isolate(page, { rulesStatus: 503, rules: { error: 'Rules service unavailable' } })
  await page.goto('/rules')
  await expect(page.getByRole('alert')).toContainText('Rules service unavailable')
  await expect(page.getByText('No rules match the current filters.')).toHaveCount(0)
})

test('malformed Rules responses are reported as errors', async ({ page }) => {
  await isolate(page, { rules: {} })
  await page.goto('/rules')
  await expect(page.getByRole('alert')).toContainText('Invalid rules response')
  await expect(page.getByText('No rules match the current filters.')).toHaveCount(0)
})

for (const [index, severity] of labels.entries()) {
  test(`numeric ${index + 1} is ${severity} in list, filter, detail and ${index === 0 ? 'disabled escalation' : 'escalation payload'}`, async ({ page }) => {
    const a = alert(`numeric-${index + 1}`, { event: { severity: index + 1 } })
    const state = await isolate(page, { alerts: [a] })
    await page.goto('/alerts')
    const row = page.locator('tbody tr').filter({ hasText: a._id })
    await expect(row.getByText(title(severity), { exact: true })).toBeVisible()
    if (index === 3) await expect(row).toHaveClass(/border-l-orange-500/)
    if (index === 4) await expect(row).toHaveClass(/border-l-red-500/)
    await page.getByRole('combobox').nth(1).selectOption(severity)
    await expect(row).toBeVisible()
    await row.click()
    await expect(page.getByRole('tabpanel').getByText(title(severity), { exact: true })).toBeVisible()
    const escalate = page.getByRole('button', { name: 'Escalate to Case' })
    if (severity === 'informational') {
      await expect(escalate).toBeDisabled()
      expect(state.writes).toEqual([])
    } else {
      await expect(escalate).toBeEnabled()
      await escalate.click()
      await expect.poll(() => state.writes.find(w => w.path === '/cases')?.body.severity).toBe(severity)
      await expect.poll(() => state.writes.find(w => w.path.startsWith('/alerts/'))?.body.status).toBe('escalated')
      await expect(row.getByText('Escalated', { exact: true })).toBeVisible()
    }
    expect(state.errors).toEqual([])
    expect(state.unexpected).toEqual([])
  })
}

const edgeCases = [
  ...labels.flatMap((expected, i) => [
    { id: `numeric-string-${i + 1}`, fields: { event: { severity: ` ${i + 1} ` } }, expected },
    { id: `name-${expected}`, fields: { event: { severity: ` ${expected.toUpperCase()} ` } }, expected },
    { id: `rule-only-${i + 1}`, fields: { rule: { severity: i + 1 } }, expected },
  ]),
  { id: 'missing', fields: {}, expected: 'unknown' },
  { id: 'null', fields: { event: { severity: null } }, expected: 'unknown' },
  { id: 'empty', fields: { event: { severity: '' }, rule: { severity: ' ' } }, expected: 'unknown' },
  { id: 'invalid', fields: { event: { severity: 75 }, rule: { severity: 'urgent' } }, expected: 'unknown' },
  { id: 'zero-fallback', fields: { event: { severity: 0 }, rule: { severity: 'High' } }, expected: 'high' },
  { id: 'boolean-fallback', fields: { event: { severity: true }, rule: { severity: '5' } }, expected: 'critical' },
  { id: 'invalid-fallback', fields: { event: { severity: 'urgent' }, rule: { severity: 'critical' } }, expected: 'critical' },
  { id: 'conflict-high', fields: { event: { severity: 4 }, rule: { severity: 'low' } }, expected: 'high' },
  { id: 'conflict-info', fields: { event: { severity: 1 }, rule: { severity: 'critical' } }, expected: 'informational' },
]

test('strings, missing values and conflicts normalize consistently in list and filters', async ({ page }) => {
  const state = await isolate(page, { alerts: edgeCases.map(c => alert(c.id, c.fields)) })
  await page.goto('/alerts')
  for (const c of edgeCases) {
    await expect(page.locator('tbody tr').filter({ hasText: c.id }).getByText(title(c.expected), { exact: true })).toBeVisible()
  }
  for (const severity of [...labels, 'unknown']) {
    await page.getByRole('combobox').nth(1).selectOption(severity)
    await expect(page.locator('tbody tr')).toHaveCount(edgeCases.filter(c => c.expected === severity).length)
    for (const c of edgeCases.filter(c => c.expected === severity)) await expect(page.locator('tbody').getByText(c.id, { exact: true })).toBeVisible()
  }
  await page.getByRole('button', { name: 'Clear filters' }).click()
  await expect(page.locator('tbody tr')).toHaveCount(edgeCases.length)
  expect(state.errors).toEqual([])
  expect(state.unexpected).toEqual([])
})

test('directly fetched alert detail uses the same normalization', async ({ page }) => {
  const detail = alert('outside-list', { event: { severity: '5' }, rule: { severity: 'low' } })
  const state = await isolate(page, { detail })
  await page.goto('/alerts?id=outside-list')
  await expect(page.getByRole('tabpanel').getByText('Critical', { exact: true })).toBeVisible()
  expect(state.errors).toEqual([])
  expect(state.unexpected).toEqual([])
})

for (const severity of ['informational', 'unknown']) {
  for (const openedFrom of ['list', 'direct']) {
    test(`${severity} escalation is blocked from ${openedFrom} detail without status changes or writes`, async ({ page }) => {
      const initialStatus = openedFrom === 'list' ? 'new' : 'acknowledged'
      const initialLabel = openedFrom === 'list' ? 'New' : 'Acknowledged'
      const a = alert(`blocked-${severity}-${openedFrom}`, {
        event: { outcome: initialStatus, ...(severity === 'informational' ? { severity: 1 } : {}) },
        // A valid event level remains authoritative despite conflicting rule metadata.
        ...(severity === 'informational' ? { rule: { severity: 'critical' } } : {}),
      })
      const state = await isolate(page, openedFrom === 'list' ? { alerts: [a] } : { detail: a })
      const mutations: string[] = []
      page.on('request', request => {
        const path = new URL(request.url()).pathname
        if ((request.method() === 'PATCH' && path.startsWith('/api/v1/alerts/')) ||
            (request.method() === 'POST' && path === '/api/v1/cases')) {
          mutations.push(`${request.method()} ${path}`)
        }
      })
      await page.goto(openedFrom === 'list' ? '/alerts' : `/alerts?id=${a._id}`)
      if (openedFrom === 'list') await page.locator('tbody').getByText(a._id, { exact: true }).click()
      const detail = page.locator('div.fixed').filter({ has: page.getByRole('heading', { name: a._id, exact: true }) }).first()
      const escalate = page.getByRole('button', { name: 'Escalate to Case' })
      await expect(page.getByRole('tabpanel').getByText(title(severity), { exact: true })).toBeVisible()
      await expect(detail.getByText(initialLabel, { exact: true })).toBeVisible()
      await expect(page.getByText(`Case escalation does not support ${severity} severity yet.`, { exact: true })).toBeVisible()
      await expect(escalate).toBeDisabled()
      await expect(escalate).toHaveAccessibleDescription(`Case escalation does not support ${severity} severity yet.`)
      // Attempt an actual pointer click, bypassing Playwright's enabled check.
      // The browser must keep the disabled action inert.
      await escalate.click({ force: true })
      // Drain browser event/render work before checking that no writes were scheduled.
      await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
      await expect(detail.getByText(initialLabel, { exact: true })).toBeVisible()
      await expect(detail.getByText('Escalated', { exact: true })).toHaveCount(0)
      if (openedFrom === 'list') {
        const row = page.locator('tbody tr').filter({ hasText: a._id })
        await expect(row.getByText(initialLabel, { exact: true })).toBeVisible()
      }
      expect(mutations).toEqual([])
      expect(state.writes).toEqual([])
      expect(state.unexpected).toEqual([])
      expect(state.errors).toEqual([])
    })
  }
}
