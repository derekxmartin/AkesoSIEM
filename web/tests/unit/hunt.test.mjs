import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { appendFilter, fieldValue, computeFieldStats, generateHistogramBuckets, validateHuntResponse, huntError } from '../../src/lib/hunt.js'

const fixtures = JSON.parse(readFileSync(new URL('../../../internal/query/testdata/hunt-events.json', import.meta.url)))
const filterCases = JSON.parse(readFileSync(new URL('../../../internal/query/testdata/hunt-filters.json', import.meta.url)))

test('generated filters match the exact queries exercised by the Go parser', () => {
  for (const c of filterCases) assert.equal(appendFilter(c.query, c.field, c.value, c.exclude), c.expected)
})

test('nested ECS, literal dotted keys, arrays, and missing fields agree in table/stats', () => {
  const hits = [fixtures[0], { fields: { 'host.name': ['bravo'], 'event.category': ['authentication'] } }, { _source: { host: { name: null }, user: { name: {} } } }]
  assert.equal(fieldValue(hits[0], 'host.name'), 'alpha')
  assert.deepEqual(fieldValue(hits[1], 'host.name'), ['bravo'])
  assert.equal(fieldValue(hits[2], 'message'), undefined)
  const stats = computeFieldStats(hits)
  assert.deepEqual(stats['event.category'].values, [{ value: 'authentication', count: 2, pct: 67 }])
  assert.equal(stats['host.name'].values.length, 2)
  assert.ok(!JSON.stringify(stats).includes('[object Object]'))
})

test('histogram omits missing, invalid and timezone-free timestamps without mutating evidence', () => {
  const before = JSON.stringify(fixtures)
  const bad = [null, undefined, '', 123, 'invalid', '2026-10-03T12:00:00'].map(ts => ({ _source: { '@timestamp': ts } }))
  assert.deepEqual(generateHistogramBuckets(bad), [])
  const buckets = generateHistogramBuckets([...fixtures, ...bad])
  assert.equal(buckets.reduce((sum, b) => sum + b.count, 0), fixtures.length)
  assert.ok(buckets.every(b => Date.parse(b.end) > Date.parse(b.time)))
  assert.equal(JSON.stringify(fixtures), before)
})

test('invalid responses and structured API errors never become successful empty results', () => {
  for (const value of [null, {}, { hits: [] }, { result_type: 'events', hits: [null], total: 1 }]) assert.throws(() => validateHuntResponse(value))
  assert.equal(huntError({status:400,data:{error:{message:'Bad syntax'}}}), 'Invalid query or time range: Bad syntax')
  assert.equal(huntError({status:502,data:{error:{}},message:'[object Object]'}), 'Hunt request failed: Request failed')
})
