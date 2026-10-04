import { test, expect, type Page, type Route } from '@playwright/test'
import { readFileSync } from 'node:fs'

const events = JSON.parse(readFileSync(new URL('../../../internal/query/testdata/hunt-events.json', import.meta.url), 'utf8'))
const filters = JSON.parse(readFileSync(new URL('../../../internal/query/testdata/hunt-filters.json', import.meta.url), 'utf8'))
const bothHosts = 'host.name IN ("alpha", "bravo")'
const fixedNow = Date.parse('2026-10-03T12:00:00Z')
const range = { from: '2026-10-03T11:00:00.000Z', to: '2026-10-03T12:00:00.000Z' }
const response = (hits: any[] = [], extra: any = {}) => ({
  result_type: 'events', total: hits.length, hits, time_range: range, ...extra,
})
const rows = (page: Page) => page.locator('[data-evidence-row]')
const ids = (page: Page) => rows(page).evaluateAll(rs => rs.map(r => r.getAttribute('data-evidence-id')))
const states = new WeakMap<Page, any>()

test.use({ timezoneId: 'UTC' })
test.afterEach(async ({ page }) => {
  const state = states.get(page)
  if (state) {
    expect(state.unexpected).toEqual([])
    expect(state.errors).toEqual([])
  }
})

async function isolate(page: Page, onQuery?: (route: Route, body: any, n: number) => Promise<void>) {
  const state = { requests: [] as any[], unexpected: [] as string[], errors: [] as string[], now: fixedNow }
  states.set(page, state)
  page.on('pageerror', err => state.errors.push(err.message))
  await page.addInitScript(() => localStorage.setItem('akeso-refresh-token', 'isolated-test-token'))
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
    if (url.pathname !== '/api/v1/query' || request.method() !== 'POST') {
      state.unexpected.push(request.method() + ' ' + url.pathname)
      return route.abort()
    }
    const body = request.postDataJSON()
    state.requests.push(body)
    if (onQuery) return onQuery(route, body, state.requests.length)
    const duration = { '15m': 900000, '1h': 3600000, '24h': 86400000 }[body.time_range?.relative]
    const effective = duration ? { from: new Date(state.now - duration).toISOString(), to: new Date(state.now).toISOString() } : body.time_range
    const hits = events.filter((event: any) => {
      const host = event._source.host.name
      const hostMatch = body.query === bothHosts ? ['alpha', 'bravo'].includes(host) : body.query === 'host.name = alpha' ? host === 'alpha' : false
      const ts = Date.parse(event._source['@timestamp'])
      return hostMatch && (!effective || (ts >= Date.parse(effective.from) && ts < Date.parse(effective.to)))
    })
    return route.fulfill({ json: response(hits, { time_range: effective }) })
  })
  return state
}

async function search(page: Page, query = bothHosts) {
  await page.locator('.cm-content').fill(query)
  await page.getByRole('button', { name: 'Search', exact: true }).click()
}
async function start(page: Page) {
  await page.goto('/hunt')
  await page.getByRole('button', { name: '1h', exact: true }).click()
}

test('selected time intersects two hosts, excludes decoy/boundaries and preserves exact evidence', async ({ page }) => {
  const state = await isolate(page)
  await start(page)
  await search(page)
  await expect(rows(page)).toHaveCount(3)
  expect(await ids(page)).toEqual(['alpha-start', 'alpha-end', 'bravo-inside'])
  expect(state.requests[0]).toEqual({ query: bothHosts, size: 100, time_range: { relative: '1h' } })
  await expect(page.getByTestId('hunt-summary')).toContainText(range.from)
  await expect(page.getByTestId('hunt-summary')).toContainText(range.to)
  for (const event of events.slice(0, 3)) {
    const row = page.locator('[data-evidence-id="' + event._id + '"]')
    await expect(row).toHaveAttribute('data-evidence-index', event._index)
    await expect(row.getByText(event._source['@timestamp'], { exact: true })).toBeVisible()
    await expect(row.getByText(event._source.host.name, { exact: true })).toBeVisible()
  }
  await page.getByRole('button', { name: /host.name.*2 values/ }).click()
  await expect(page.getByRole('button', { name: 'alpha 67%' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'bravo 33%' })).toBeVisible()
  await page.getByRole('button', { name: /event.category.*1 values/ }).click()
  await expect(page.getByRole('button', { name: 'authentication 33%' })).toBeVisible()
  await page.locator('[data-evidence-id="alpha-start"]').click()
  await expect(page.getByText('Index: ' + events[0]._index + ' · ID: alpha-start')).toBeVisible()
  await page.getByRole('tab', { name: 'JSON', exact: true }).click()
  expect(JSON.parse(await page.getByRole('tabpanel').innerText())).toEqual(events[0])
  await page.getByRole('tab', { name: 'Raw', exact: true }).click()
  expect(await page.getByRole('tabpanel').locator('pre').textContent()).toBe(events[0]._source.event.original)
  await page.locator('[data-evidence-id="alpha-start"]').click()
  await page.locator('[data-evidence-id="alpha-end"]').click()
  await page.getByRole('tab', { name: 'Raw', exact: true }).click()
  expect(JSON.parse(await page.getByRole('tabpanel').innerText())).toEqual(events[1]._source.raw)
})

test('field statistics and context menu produce supported escaped filters before pipelines', async ({ page }) => {
  const state = await isolate(page, async route => { await route.fulfill({ json: response([events[0]]) }) })
  await start(page)
  await search(page, filters[1].query)
  await expect(rows(page)).toHaveCount(1)
  await rows(page).getByText(filters[1].value, { exact: true }).click({ button: 'right' })
  await page.getByRole('button', { name: 'Filter out (−)', exact: true }).click()
  await expect(page.locator('.cm-content')).toHaveText(filters[1].expected)
  await page.getByRole('button', { name: 'Search', exact: true }).click()
  await expect.poll(() => state.requests.length).toBe(2)
  expect(state.requests[1].query).toBe(filters[1].expected)
  await expect(rows(page)).toHaveCount(1)
  await page.locator('.cm-content').fill('')
  await page.getByRole('button', { name: /user.name.*1 values/ }).click()
  await page.getByRole('button', { name: filters[0].value + ' 100%' }).click()
  await expect(page.locator('.cm-content')).toHaveText(filters[0].expected)
})

test('manual and interval refresh reissue the selected relative query', async ({ page }) => {
  await page.clock.install({ time: new Date(fixedNow) })
  const state = await isolate(page)
  await start(page)
  await search(page)
  await expect(rows(page)).toHaveCount(3)
  state.now += 1000
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect.poll(() => state.requests.length).toBe(2)
  await expect(page.getByTestId('hunt-summary')).toContainText('2026-10-03T12:00:01.000Z')
  expect(state.requests[1]).toEqual(state.requests[0])
  await page.getByRole('button', { name: 'Off', exact: true }).click()
  await page.getByRole('button', { name: '10s', exact: true }).click()
  state.now += 10000
  await page.clock.fastForward(10000)
  await expect.poll(() => state.requests.length).toBe(3)
  await expect(page.getByTestId('hunt-summary')).toContainText('2026-10-03T12:00:11.000Z')
  expect(state.requests[2]).toEqual(state.requests[0])
})

test('absolute picker submits UTC bounds together with the query', async ({ page }) => {
  await page.clock.install({ time: new Date(fixedNow) })
  const state = await isolate(page)
  await page.goto('/hunt')
  await page.getByRole('button', { name: 'Last 24h', exact: true }).click()
  await page.getByRole('textbox', { name: 'From time' }).fill('23:00')
  await page.getByRole('textbox', { name: 'To time' }).fill('00:00')
  await page.getByRole('button', { name: 'Apply', exact: true }).click()
  await search(page)
  await expect.poll(() => state.requests.length).toBe(1)
  expect(state.requests[0]).toEqual({
    query: bothHosts, size: 100,
    time_range: { from: '2026-10-02T23:00:00.000Z', to: '2026-10-03T00:00:00.000Z' },
  })
  await expect(page.getByText('No results for this query and time range.')).toBeVisible()
  await expect(page.getByTestId('hunt-summary')).toContainText('2026-10-02T23:00:00.000Z')
})

for (const olderFailure of [false, true]) {
  test('older ' + (olderFailure ? 'failure' : 'success') + ' cannot replace a newer success', async ({ page }) => {
    let held: Route | undefined
    const state = await isolate(page, async (route, _body, n) => {
      if (n === 1) { held = route; return }
      await route.fulfill({ json: response([events[2]]) })
    })
    await start(page)
    await search(page, 'host.name = alpha')
    await expect.poll(() => state.requests.length).toBe(1)
    await page.locator('.cm-content').fill('host.name = bravo')
    await page.getByRole('button', { name: 'Refresh', exact: true }).click()
    await expect(rows(page)).toHaveCount(1)
    expect(await ids(page)).toEqual(['bravo-inside'])
    await held!.fulfill(olderFailure ? { status: 502, json: { error: 'Old failure' } } : { json: response([events[0]]) })
    // Browser task barrier after the older fetch resolves, without arbitrary network sleeps.
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
    expect(await ids(page)).toEqual(['bravo-inside'])
    await expect(page.getByTestId('hunt-summary')).toContainText('host.name = bravo')
    await expect(page.getByRole('alert')).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeEnabled()
  })
}

test('older success cannot overwrite a newer error', async ({ page }) => {
  let held: Route | undefined
  const state = await isolate(page, async (route, _body, n) => {
    if (n === 1) { held = route; return }
    await route.fulfill({ status: 502, json: { error: 'Newest request failed' } })
  })
  await start(page)
  await search(page)
  await expect.poll(() => state.requests.length).toBe(1)
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Newest request failed')
  await held!.fulfill({ json: response([events[0]]) })
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
  await expect(rows(page)).toHaveCount(0)
  await expect(page.getByRole('alert')).toContainText('Newest request failed')
})

test('missing metadata/timestamps and fields-only hits render without invented evidence', async ({ page }) => {
  const hits = [
    events[0],
    { ...events[0], _index: 'akeso-events-another', _source: { host: { name: 'other' } } },
    { _source: { host: { name: 'missing' }, message: { text: 'object payload' } } },
    { _id: 'projection', _index: 'akeso-events-test', fields: { 'host.name': ['projected'], '@timestamp': null } },
  ]
  await isolate(page, async route => { await route.fulfill({ json: response(hits, { result_type: 'fields' }) }) })
  await start(page)
  await search(page, 'host.name exists | fields host.name')
  await expect(rows(page)).toHaveCount(4)
  expect(await ids(page)).toEqual(['alpha-start', 'alpha-start', null, 'projection'])
  await expect(page.getByTestId('hunt-summary')).toContainText('field projections (partial records)')
  await expect(rows(page).nth(2)).toContainText('{"text":"object payload"}')
  await expect(rows(page).nth(3)).toContainText('["projected"]')
  await expect(page.locator('body')).not.toContainText('[object Object]')
  await expect(page.locator('body')).not.toContainText('Invalid Date')
  await expect(page.locator('body')).not.toContainText('1970-')
  await rows(page).nth(2).click()
  await expect(page.getByText('Index: Not returned · ID: Not returned')).toBeVisible()
  await page.getByRole('tab', { name: 'Raw', exact: true }).click()
  await expect(page.getByRole('tabpanel')).toHaveText('Original raw payload was not returned.')
  await rows(page).nth(0).click()
  await rows(page).nth(1).click()
  await expect(page.getByText('Index: akeso-events-another · ID: alpha-start')).toBeVisible()
})

test('aggregates are labeled and never rendered as event evidence', async ({ page }) => {
  const aggs = { group_by: { buckets: [{ key: 'alpha', doc_count: 2 }] } }
  await isolate(page, async route => { await route.fulfill({ json: response([], { result_type: 'aggregation', total: 2, aggs }) }) })
  await start(page)
  await search(page, 'count() by host.name')
  await expect(page.getByTestId('hunt-summary')).toContainText('Aggregate results — not individual evidence records.')
  await expect(page.getByLabel('Aggregate results')).toContainText('"doc_count": 2')
  await expect(rows(page)).toHaveCount(0)
  await expect(page.getByText('No results for this query and time range.')).toHaveCount(0)
})

test('successful zero matches has a distinct no-results state', async ({ page }) => {
  await isolate(page)
  await start(page)
  await search(page, 'host.name = absent')
  await expect(page.getByText('No results for this query and time range.')).toBeVisible()
  await expect(page.getByRole('alert')).toHaveCount(0)
})

for (const failure of [
  { name: 'invalid query', status: 400, json: { error: { message: 'Bad query syntax' } }, expected: 'Invalid query or time range: Bad query syntax' },
  { name: 'API failure', status: 503, json: { error: { reason: 'Service unavailable' } }, expected: 'Hunt request failed: Service unavailable' },
  { name: 'opaque object error', status: 502, json: { error: { code: 'upstream' } }, expected: 'Hunt request failed: Request failed' },
  { name: 'malformed success', status: 200, json: {}, expected: 'Invalid Hunt response' },
  { name: 'network failure', abort: true, expected: 'Hunt request failed:' },
]) {
  test(failure.name + ' is explicit and clears prior results', async ({ page }) => {
    await isolate(page, async (route, _body, n) => {
      if (n === 1) return route.fulfill({ json: response([events[0]]) })
      if (failure.abort) return route.abort('failed')
      await route.fulfill({ status: failure.status, json: failure.json })
    })
    await start(page)
    await search(page)
    await expect(rows(page)).toHaveCount(1)
    await page.getByRole('button', { name: 'Refresh', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText(failure.expected)
    await expect(rows(page)).toHaveCount(0)
    await expect(page.getByTestId('hunt-summary')).toHaveCount(0)
    await expect(page.getByText('No results for this query and time range.')).toHaveCount(0)
    await expect(page.locator('body')).not.toContainText('[object Object]')
  })
}

for (const suffix of ['', ' | sort @timestamp desc | head 25']) {
  test('match-all host selection preserves filtering/time/pipelines' + suffix, async ({ page }) => {
    const initial = '*' + suffix
    const filtered = 'host.name IN ("alpha")' + suffix
    const state = await isolate(page, async (route, body) => {
      if (![initial, filtered].includes(body.query)) {
        return route.fulfill({ status: 400, json: { error: 'Invalid generated expression' } })
      }
      const hits = events.filter((hit: any) => {
        const ts = Date.parse(hit._source['@timestamp'])
        return ts >= Date.parse(range.from) && ts < Date.parse(range.to)
          && (body.query === initial || hit._source.host.name === 'alpha')
      })
      await route.fulfill({ json: response(hits) })
    })
    await start(page)
    await search(page, initial)
    await expect(rows(page)).toHaveCount(4)
    await page.getByRole('button', { name: /host.name.*3 values/ }).click()
    await page.getByRole('button', { name: 'alpha 50%', exact: true }).click()
    await expect(page.locator('.cm-content')).toHaveText(filtered)
    await page.getByRole('button', { name: 'Search', exact: true }).click()
    await expect(rows(page)).toHaveCount(2)
    expect(await ids(page)).toEqual(['alpha-start', 'alpha-end'])
    expect(state.requests).toEqual([
      { query: initial, size: 100, time_range: { relative: '1h' } },
      { query: filtered, size: 100, time_range: { relative: '1h' } },
    ])
    await expect(page.getByTestId('hunt-summary')).toContainText(range.from)
    await expect(page.getByTestId('hunt-summary')).toContainText(range.to)
    await expect(page.getByRole('alert')).toHaveCount(0)
  })
}

for (const failure of [false, true]) {
  test('slow auto-refresh ' + (failure ? 'failure' : 'success') + ' settles without overlap or starvation', async ({ page }) => {
    await page.clock.install({ time: new Date(fixedNow) })
    const held = new Map<number, Route>()
    const state = await isolate(page, async (route, _body, n) => {
      if (n === 1) return route.fulfill({ json: response([events[0]]) })
      held.set(n, route)
    })
    await start(page)
    await search(page)
    await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeEnabled()
    await page.getByRole('button', { name: 'Off', exact: true }).click()
    await page.getByRole('button', { name: '10s', exact: true }).click()
    await page.keyboard.press('Escape')
    await page.clock.runFor(10000)
    await expect.poll(() => state.requests.length).toBe(2)
    await page.clock.runFor(10000)
    await page.clock.runFor(10000)
    // The timer-driven request has been pending for two full refresh intervals.
    await held.get(2)!.fulfill(failure
      ? { status: 502, json: { error: 'Slow upstream failure' } }
      : { json: response([events[2]]) })
    await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeEnabled()
    await expect(page.getByRole('status').filter({ hasText: 'Searching' })).toHaveCount(0)
    expect(state.requests).toHaveLength(2)
    if (failure) {
      await expect(page.getByRole('alert')).toContainText('Hunt request failed: Slow upstream failure')
      await expect(rows(page)).toHaveCount(0)
      await expect(page.getByText('No results for this query and time range.')).toHaveCount(0)
    } else {
      expect(await ids(page)).toEqual(['bravo-inside'])
      await expect(page.getByRole('alert')).toHaveCount(0)
    }
    // Polling resumes after either success or failure, with the same time scope.
    await page.clock.runFor(10000)
    await expect.poll(() => state.requests.length).toBe(3)
    expect(state.requests[2]).toEqual(state.requests[1])
    await held.get(3)!.fulfill({ json: response([events[0]]) })
    await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeEnabled()
    expect(await ids(page)).toEqual(['alpha-start'])
    await expect(page.getByRole('alert')).toHaveCount(0)
  })
}

test('user query and time change supersedes slow auto-refresh without premature loading cleanup', async ({ page }) => {
  await page.clock.install({ time: new Date(fixedNow) })
  const held = new Map<number, Route>()
  const state = await isolate(page, async (route, _body, n) => {
    if (n === 1) return route.fulfill({ json: response(events.slice(0, 3)) })
    held.set(n, route)
  })
  await start(page)
  await search(page)
  await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeEnabled()
  await page.getByRole('button', { name: 'Off', exact: true }).click()
  await page.getByRole('button', { name: '10s', exact: true }).click()
  await page.keyboard.press('Escape')
  await page.clock.runFor(10000)
  await expect.poll(() => state.requests.length).toBe(2)
  await page.locator('.cm-content').fill('host.name = alpha')
  await page.getByRole('button', { name: '15m', exact: true }).click()
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect.poll(() => state.requests.length).toBe(3)
  expect(state.requests[2]).toEqual({ query: 'host.name = alpha', size: 100, time_range: { relative: '15m' } })
  await page.clock.runFor(20000)
  // Finishing an old request must neither finish nor unlock the newer request.
  await held.get(2)!.fulfill({ json: response([events[2]]) })
  await expect(page.getByRole('button', { name: 'Searching...', exact: true })).toBeDisabled()
  await page.clock.runFor(10000)
  expect(state.requests).toHaveLength(3)
  await expect(rows(page)).toHaveCount(0)
  const narrow = { from: '2026-10-03T11:45:00.000Z', to: range.to }
  await held.get(3)!.fulfill({ json: response([events[1]], { time_range: narrow }) })
  await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeEnabled()
  expect(await ids(page)).toEqual(['alpha-end'])
  await expect(page.getByTestId('hunt-summary')).toContainText('host.name = alpha')
  await expect(page.getByTestId('hunt-summary')).toContainText(narrow.from)
  await page.clock.runFor(10000)
  await expect.poll(() => state.requests.length).toBe(4)
  expect(state.requests[3]).toEqual(state.requests[2])
  await held.get(4)!.fulfill({ json: response([events[1]], { time_range: narrow }) })
  await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeEnabled()
  expect(await ids(page)).toEqual(['alpha-end'])
})
