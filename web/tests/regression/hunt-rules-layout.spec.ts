import { test, expect, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'

const apiEvents = JSON.parse(readFileSync(new URL('../../../internal/query/testdata/hunt-events.json', import.meta.url), 'utf8'))
const rules = JSON.parse(readFileSync(new URL('../fixtures/rules-api.json', import.meta.url), 'utf8'))
const longValue = 'command-with-an-unbroken-argument-' + 'x'.repeat(4000)
const query = 'host.name IN ("alpha")'
const range = { from: '2026-10-03T11:00:00.000Z', to: '2026-10-03T12:00:00.000Z' }
const events = Array.from({ length: 100 }, (_, index) => ({
  ...apiEvents[0],
  _id: index ? `layout-${index}` : 'long-id-' + 'a'.repeat(512),
  _source: {
    ...apiEvents[0]._source,
    '@timestamp': new Date(Date.parse(range.from) + index * 1000).toISOString(),
    process: { name: 'powershell.exe', command_line: longValue },
    event: { ...apiEvents[0]._source.event, original: longValue },
  },
}))

test.use({ timezoneId: 'America/New_York' })

async function isolate(page: Page) {
  const state = { requests: [] as any[], unexpected: [] as string[], errors: [] as string[] }
  page.on('pageerror', error => state.errors.push(error.message))
  await page.addInitScript(() => {
    localStorage.setItem('akeso-refresh-token', 'isolated-layout-token')
    localStorage.setItem('akeso-theme', 'light')
  })
  await page.route('**/*', async route => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.origin !== 'http://127.0.0.1:4179') {
      state.unexpected.push(request.url())
      return route.abort()
    }
    if (!url.pathname.startsWith('/api/')) return route.continue()
    if (url.pathname === '/api/v1/auth/refresh') return route.fulfill({ json: { access_token: 'test-token', expires_in: 3600 } })
    if (url.pathname === '/api/v1/auth/profile') return route.fulfill({ json: { username: 'regression', role: 'admin' } })
    if (url.pathname === '/api/v1/rules' && request.method() === 'GET') return route.fulfill({ json: rules })
    if (url.pathname === '/api/v1/query' && request.method() === 'POST') {
      state.requests.push(request.postDataJSON())
      return route.fulfill({ json: { result_type: 'events', total: 7310, hits: events, time_range: range } })
    }
    state.unexpected.push(request.method() + ' ' + url.pathname)
    return route.abort()
  })
  return state
}

for (const viewport of [{ width: 1400, height: 900 }, { width: 615, height: 476 }]) {
  test.describe(`${viewport.width}x${viewport.height} demo layout`, () => {
    test.use({ viewport })

    test('Hunt contains long evidence, shows the returned subset and preserves chart brush bounds', async ({ page }) => {
      const state = await isolate(page)
      await page.goto('/hunt')
      await page.locator('.cm-content').fill(query)
      await page.getByRole('button', { name: 'Search', exact: true }).click()
      await expect(page.locator('[data-evidence-row]')).toHaveCount(100)
      await expect(page.getByTestId('hunt-summary')).toContainText('Showing 100 returned events of 7310 matches.')
      await expect(page.getByTestId('hunt-summary')).toContainText('Histogram and field counts describe returned records only.')
      await expect(page.getByTestId('hunt-summary')).toContainText(range.from)
      await expect(page.getByTestId('hunt-summary')).toContainText(range.to)
      await expect(page.getByRole('button', { name: /100 events over time/ })).toBeVisible()

      // All bins remain; only the axis label density changes. Visible label
      // rectangles must not collide, even when most format to the same minute.
      await expect(page.locator('.recharts-bar-rectangle')).toHaveCount(30)
      const ticks = page.locator('.recharts-xAxis-tick-labels .recharts-cartesian-axis-tick-value')
      await expect.poll(() => ticks.count()).toBeGreaterThan(1)
      const boxes = await ticks.evaluateAll(nodes => nodes.map(node => {
        const box = node.getBoundingClientRect()
        return { left: box.left, right: box.right }
      }))
      expect(boxes.length).toBeLessThanOrEqual(viewport.width > 1000 ? 14 : 7)
      expect(boxes.every((box, i) => !i || box.left >= boxes[i - 1].right + 16)).toBe(true)

      const scroller = page.getByTestId('hunt-table-scroll')
      const table = scroller.locator('table')
      const before = await table.boundingBox()
      expect((await table.getByRole('columnheader', { name: 'Original timestamp' }).boundingBox())!.width).toBeLessThanOrEqual(240)
      expect(await scroller.evaluate(el => el.clientHeight)).toBeGreaterThanOrEqual(viewport.width < 768 ? 240 : 120)
      await page.getByRole('button', { name: 'Expand event', exact: true }).first().click()
      await expect(page.getByRole('tabpanel')).toContainText(longValue)
      for (const name of ['Table', 'JSON', 'Raw']) {
        await page.getByRole('tab', { name, exact: true }).click()
        expect((await table.boundingBox())!.width).toBeCloseTo(before!.width, 0)
        expect((await page.getByRole('tabpanel').boundingBox())!.width).toBeLessThanOrEqual((await scroller.boundingBox())!.width)
        if (name === 'JSON') expect(JSON.parse(await page.getByRole('tabpanel').innerText())).toEqual(events[0])
        if (name === 'Raw') expect(await page.getByRole('tabpanel').locator('pre').textContent()).toBe(longValue)
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width)
      await page.getByRole('button', { name: 'Collapse event', exact: true }).first().click()

      // An edited query must not make retained evidence appear to belong to it.
      await page.locator('.cm-content').fill('host.name IN ("bravo")')
      await expect(page.getByTestId('hunt-summary')).toContainText('Query: ' + query)
      await page.locator('.cm-content').fill(query)
      const firstHandle = page.getByRole('slider').first()
      await firstHandle.press('ArrowRight')
      await page.getByRole('button', { name: 'Search', exact: true }).click()
      await expect.poll(() => state.requests.length).toBe(2)
      expect(state.requests[1]).toEqual({
        query, size: 100,
        // 100 events, 0..99 seconds, in the existing 30 bins: 3301 ms each.
        time_range: { from: '2026-10-03T11:00:03.301Z', to: '2026-10-03T11:01:39.030Z' },
      })
      expect(state.unexpected).toEqual([])
      expect(state.errors).toEqual([])
    })

    test('Rules keeps aligned labeled metadata and all 107 IDs with compact summaries', async ({ page }) => {
      const state = await isolate(page)
      await page.goto('/rules')
      await expect(page.getByText('107/107 enabled', { exact: true })).toBeVisible()
      const rendered = page.locator('[data-rule-id]')
      const actual = await rendered.evaluateAll(nodes => [...new Set(nodes.map(node => node.getAttribute('data-rule-id')))].sort())
      expect(actual).toEqual(rules.rules.map(rule => rule.id).sort())
      expect((await page.getByTestId('rules-summary').boundingBox())!.height).toBeLessThanOrEqual(72)
      const labels = page.getByLabel('Rule columns')
      await expect(labels).toHaveText('StateSeverityRule nameTechniqueSourceHitsLast triggered')
      const headers = await labels.locator(':scope > span').evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().x))
      const values = await rendered.first().locator(':scope > *').evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().x))
      // Grid cells use matching tracks; count/date cells are right-aligned.
      headers.forEach((x, i) => expect(Math.abs(x - values[i])).toBeLessThanOrEqual(1))
      for (const control of await page.getByRole('switch').all()) await expect(control).toBeDisabled()
      for (const name of ['Severity', 'Source', 'State']) {
        const box = await page.getByRole('combobox', { name, exact: true }).boundingBox()
        expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width)
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width)
      await rendered.first().press('Enter')
      await expect(rendered.first()).toHaveAttribute('aria-expanded', 'true')
      await rendered.first().press('Enter')
      await expect(rendered.first()).toHaveAttribute('aria-expanded', 'false')
      expect(state.unexpected).toEqual([])
      expect(state.errors).toEqual([])
    })
  })
}
