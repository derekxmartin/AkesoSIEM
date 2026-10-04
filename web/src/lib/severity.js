const severityByNumber = ['unknown', 'informational', 'low', 'medium', 'high', 'critical']
const severityNames = new Set(severityByNumber.slice(1))

function parseSeverity(value) {
  if (typeof value === 'number') {
    return Number.isInteger(value) && value >= 1 && value <= 5 ? severityByNumber[value] : null
  }
  if (typeof value !== 'string') return null
  const normalized = value.trim().toLowerCase()
  if (/^[1-5]$/.test(normalized)) return severityByNumber[Number(normalized)]
  return severityNames.has(normalized) ? normalized : null
}

// Producer contract (internal/ingest/pipeline.go): 1 informational ... 5 critical.
// A valid event severity is authoritative even when rule.severity conflicts.
// Missing/invalid event values fall back to a valid rule severity; otherwise
// return Unknown explicitly, never silently downgrade to Low or Medium.
export function normalizeSeverity(eventSeverity, ruleSeverity) {
  return parseSeverity(eventSeverity) ?? parseSeverity(ruleSeverity) ?? 'unknown'
}
