import { test, expect, type Locator, type Page } from '@playwright/test'

const query = 'host.name IN ("alpha")'
const historical = { from: '2026-03-26T17:58:00.000Z', to: '2026-03-26T18:46:00.000Z' }
const viewports = [
  { name: 'narrow panel', width: 615, height: 476 },
  { name: 'desktop', width: 1400, height: 1000 },
]

test.use({ timezoneId: 'America/New_York' })

// The static regression server has no API proxy. Only these intercepted routes
// are allowed; the layout tests cannot query or modify the running lab.
async function isolate(page: Page) {
  const state = { requests: [] as any[], unexpected: [] as string[], errors: [] as string[] }
  page.on('pageerror', error => state.errors.push(error.message))
  await page.clock.setFixedTime(new Date('2026-03-27T16:00:00Z'))
  await page.addInitScript(() => localStorage.setItem('akeso-refresh-token', 'isolated-picker-token'))
  await page.route('**/*', async route => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.origin !== 'http://127.0.0.1:4179') {
      state.unexpected.push(request.method() + ' ' + request.url())
      return route.abort()
    }
    if (!url.pathname.startsWith('/api/')) return route.continue()
    if (url.pathname === '/api/v1/auth/refresh') return route.fulfill({ json: { access_token: 'test-token', expires_in: 3600 } })
    if (url.pathname === '/api/v1/auth/profile') return route.fulfill({ json: { username: 'regression', role: 'admin' } })
    if (url.pathname === '/api/v1/query' && request.method() === 'POST') {
      const body = request.postDataJSON()
      state.requests.push(body)
      return route.fulfill({ json: { result_type: 'events', total: 0, hits: [], time_range: body.time_range } })
    }
    state.unexpected.push(request.method() + ' ' + url.pathname)
    return route.abort()
  })
  await page.goto('/hunt')
  await page.locator('.cm-content').fill(query)
  return state
}

function picker(page: Page) {
  return page.locator('[id^="headlessui-popover-panel-"]').filter({ has: page.getByRole('textbox', { name: 'From time' }) })
}

async function expectContained(page: Page) {
  await expect.poll(async () => {
    const box = await picker(page).boundingBox()
    const viewport = page.viewportSize()!
    return !!box && box.x >= 8 && box.y >= 8 && box.x + box.width <= viewport.width - 8 && box.y + box.height <= viewport.height - 8
  }, { message: 'The entire picker must fit inside the viewport, including at short panel heights' }).toBe(true)
}

async function expectReachable(control: Locator) {
  await control.scrollIntoViewIfNeeded()
  // Visibility alone misses controls clipped by overflow or covered by the
  // navigation sidebar. Hit-testing proves a real pointer can reach them.
  await expect.poll(() => control.evaluate(element => {
    const box = element.getBoundingClientRect()
    const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2)
    return hit === element || element.contains(hit)
  })).toBe(true)
}

for (const viewport of viewports) {
  test.describe(viewport.name, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height } })

    test('absolute picker is unclipped and applies/reopens the historical range by pointer', async ({ page }) => {
      const state = await isolate(page)
      await page.getByRole('button', { name: 'Last 24h', exact: true }).click()
      await expectContained(page)

      for (const index of [0, 1]) {
        const previous = page.getByRole('button', { name: 'Go to the Previous Month', exact: true }).nth(index)
        const next = page.getByRole('button', { name: 'Go to the Next Month', exact: true }).nth(index)
        await expectReachable(previous)
        await previous.click()
        await expect(page.getByRole('grid', { name: 'February 2026', exact: true })).toBeVisible()
        await expectReachable(next)
        await next.click()
      }

      // From already selects March 26. Choose the same date for To, then set
      // the previously live-verified 13:58–14:46 local range (EDT, UTC−04:00).
      const toDay = page.getByRole('button', { name: 'Thursday, March 26th, 2026', exact: true })
      await expectReachable(toDay)
      await toDay.click()
      for (const [name, value] of [['From time', '13:58'], ['To time', '14:46']]) {
        const input = page.getByRole('textbox', { name, exact: true })
        await expectReachable(input)
        await input.fill(value)
      }
      const apply = page.getByRole('button', { name: 'Apply', exact: true })
      await expectReachable(apply)
      await expectContained(page)
      await apply.click()
      await page.getByRole('button', { name: 'Search', exact: true }).click()
      await expect.poll(() => state.requests.length).toBe(1)
      expect(state.requests[0]).toEqual({ query, size: 100, time_range: historical })

      const trigger = page.getByRole('button', { name: 'Mar 26 13:58 — Mar 26 14:46', exact: true })
      await trigger.click()
      await expectContained(page)
      await expect(page.getByRole('textbox', { name: 'From time' })).toHaveValue('13:58')
      await expect(page.getByRole('textbox', { name: 'To time' })).toHaveValue('14:46')
      await page.getByRole('button', { name: 'Apply', exact: true }).click()
      await page.getByRole('button', { name: 'Refresh', exact: true }).click()
      await expect.poll(() => state.requests.length).toBe(2)
      expect(state.requests[1]).toEqual(state.requests[0])
      expect(state.unexpected).toEqual([])
      expect(state.errors).toEqual([])
    })

    test('absolute picker preserves keyboard access, dismissal, focus and selected bounds', async ({ page }) => {
      const state = await isolate(page)
      const trigger = page.getByRole('button', { name: 'Last 24h', exact: true })
      await trigger.focus()
      await page.keyboard.press('Enter')
      await expectContained(page)
      await page.keyboard.press('Tab')
      await expect.poll(() => picker(page).evaluate(panel => panel.contains(document.activeElement))).toBe(true)

      const from = page.getByRole('textbox', { name: 'From time', exact: true })
      const to = page.getByRole('textbox', { name: 'To time', exact: true })
      await from.fill('13:58')
      await to.fill('14:46')
      // Tab through native controls to Apply; focus must remain reachable in
      // the scrollable panel and application must not require a pointer.
      const apply = page.getByRole('button', { name: 'Apply', exact: true })
      for (let count = 0; count < 8 && !(await apply.evaluate(el => el === document.activeElement)); count++) {
        await page.keyboard.press('Tab')
      }
      await expect(apply).toBeFocused()
      await expectReachable(apply)
      await page.keyboard.press('Enter')
      await expect(picker(page)).toHaveCount(0)
      const selected = page.getByRole('button', { name: 'Mar 26 13:58 — Mar 27 14:46', exact: true })
      await expect(selected).toBeFocused()
      await page.getByRole('button', { name: 'Search', exact: true }).click()
      await expect.poll(() => state.requests.length).toBe(1)
      expect(state.requests[0]).toEqual({ query, size: 100, time_range: { from: historical.from, to: '2026-03-27T18:46:00.000Z' } })

      await selected.focus()
      await page.keyboard.press('Enter')
      await from.fill('11:00')
      await page.keyboard.press('Escape')
      await expect(picker(page)).toHaveCount(0)
      await expect(selected).toBeFocused()
      await page.getByRole('button', { name: 'Refresh', exact: true }).click()
      await expect.poll(() => state.requests.length).toBe(2)
      expect(state.requests[1]).toEqual(state.requests[0])
      await selected.click()
      await expect(from).toHaveValue('13:58')
      await expect(to).toHaveValue('14:46')
      await page.keyboard.press('Escape')
      await expect(selected).toBeFocused()
      expect(state.unexpected).toEqual([])
      expect(state.errors).toEqual([])
    })
  })
}
