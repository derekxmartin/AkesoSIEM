const statisticFields = ['event.action', 'event.category', 'user.name', 'host.name', 'source.ip', 'destination.ip', 'process.name', 'log.level', 'network.protocol', 'destination.port']

export function sourceOf(hit) {
  return hit?._source ?? hit?.fields ?? {}
}

export function fieldValue(hit, field) {
  const source = sourceOf(hit)
  if (Object.hasOwn(source, field)) return source[field]
  return field.split('.').reduce((value, key) => value?.[key], source)
}

export function rawPayload(hit) {
  return fieldValue(hit, 'raw') ?? fieldValue(hit, 'event.original')
}

export function valueText(value) {
  if (value == null) return '—'
  return typeof value === 'object' ? JSON.stringify(value) : String(value)
}

export function isFilterValue(value) {
  return ['string', 'number', 'boolean'].includes(typeof value)
}

export function timestampMillis(value) {
  // Do not turn missing values, numeric IDs, or timezone-free strings into dates.
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/i.test(value)) return NaN
  return Date.parse(value)
}

export function generateHistogramBuckets(results, bucketCount = 30) {
  const timestamps = results.map(hit => timestampMillis(fieldValue(hit, '@timestamp'))).filter(Number.isFinite)
  if (!timestamps.length) return []
  const min = Math.min(...timestamps)
  const max = Math.max(...timestamps)
  const width = Math.max(1, Math.ceil((max - min + 1) / bucketCount))
  const buckets = Array.from({ length: bucketCount }, (_, i) => ({
    time: new Date(min + i * width).toISOString(),
    end: new Date(min + (i + 1) * width).toISOString(),
    count: 0,
  }))
  timestamps.forEach(time => { buckets[Math.min(Math.floor((time - min) / width), bucketCount - 1)].count++ })
  return buckets
}

export function computeFieldStats(results) {
  const stats = {}
  for (const field of statisticFields) {
    const counts = new Map()
    for (const hit of results) {
      const value = fieldValue(hit, field)
      // Count an array value at most once per returned record; skip objects.
      for (const item of new Set((Array.isArray(value) ? value : [value]).filter(isFilterValue))) {
        const key = String(item)
        counts.set(key, (counts.get(key) || 0) + 1)
      }
    }
    const values = [...counts].sort((a, b) => b[1] - a[1]).slice(0, 10)
    if (values.length) stats[field] = {
      total: results.length,
      values: values.map(([value, count]) => ({ value, count, pct: Math.round(count / results.length * 100) })),
    }
  }
  return stats
}

export function literalFilter(field, value, exclude = false) {
  if (!/^[@A-Za-z_][\w.@-]*$/.test(field) || !isFilterValue(value)) throw new Error('This field cannot be used as a filter')
  // IN is exact; unlike =, literal * and ? are not wildcards.
  const escaped = String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  return (exclude ? 'NOT ' : '') + field + ' IN ("' + escaped + '")'
}

// Locate syntax outside quoted values so pipes/WHERE inside evidence stay literal.
function syntaxPositions(query) {
  let quote = null
  let pipe = query.length
  let where = -1
  for (let i = 0; i < query.length; i++) {
    const ch = query[i]
    if (quote) {
      if (ch === '\\') i++
      else if (ch === quote) quote = null
    } else if (ch === '"' || ch === "'") quote = ch
    else if (ch === '|') { pipe = i; break }
    else if (where < 0 && /^where\b/i.test(query.slice(i)) && (i === 0 || /\s/.test(query[i - 1]))) where = i
  }
  return { pipe, where }
}

function combineFilter(expression, filter) {
  let unwrapped = expression.trim()
  while (unwrapped.startsWith('(') && unwrapped.endsWith(')')) {
    unwrapped = unwrapped.slice(1, -1).trim()
  }
  // A standalone match-all contributes no predicate; do not put its nil AST
  // inside an AND. Keep real predicates grouped so OR precedence is unchanged.
  if (!expression.trim() || unwrapped === '*') return filter
  return '(' + expression.trim() + ') AND ' + filter
}

export function appendFilter(query, field, value, exclude = false) {
  const filter = literalFilter(field, value, exclude)
  const { pipe, where } = syntaxPositions(query)
  const head = query.slice(0, pipe).trim()
  const tail = query.slice(pipe)
  let combined
  if (/^(count|sum|avg|min|max)\s*\(/i.test(head)) {
    combined = where < 0
      ? head + ' where ' + filter
      : query.slice(0, where).trim() + ' where ' + combineFilter(query.slice(where + 5, pipe), filter)
  } else combined = combineFilter(head, filter)
  return combined + (tail ? ' ' + tail : '')
}

export function validateHuntResponse(response) {
  if (!response || !['events', 'fields', 'aggregation'].includes(response.result_type)
    || !Array.isArray(response.hits) || !Number.isFinite(response.total) || response.total < 0
    || !response.hits.every(hit => hit && typeof hit === 'object' && !Array.isArray(hit))
    || !Number.isFinite(timestampMillis(response.time_range?.from))
    || !Number.isFinite(timestampMillis(response.time_range?.to))
    || timestampMillis(response.time_range.from) >= timestampMillis(response.time_range.to)
    || (response.result_type === 'aggregation' && (!response.aggs || typeof response.aggs !== 'object'))) {
    throw new Error('Invalid Hunt response: expected evidence records and effective time bounds')
  }
  return response
}

export function huntError(error) {
  const detail = error?.data?.error
  const message = typeof detail === 'string' ? detail
    : typeof detail?.message === 'string' ? detail.message
      : typeof detail?.reason === 'string' ? detail.reason
        : (error?.message && error.message !== '[object Object]' ? error.message : 'Request failed')
  return (error?.status === 400 ? 'Invalid query or time range: ' : 'Hunt request failed: ') + message
}
