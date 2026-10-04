// Canonical API IDs are separate from the labels displayed in group headers.
export const tacticGroups = [
  { id: 'reconnaissance', label: 'Reconnaissance' },
  { id: 'resource_development', label: 'Resource Development' },
  { id: 'initial_access', label: 'Initial Access' },
  { id: 'execution', label: 'Execution' },
  { id: 'persistence', label: 'Persistence' },
  { id: 'privilege_escalation', label: 'Privilege Escalation' },
  { id: 'defense_evasion', label: 'Defense Evasion' },
  { id: 'credential_access', label: 'Credential Access' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'lateral_movement', label: 'Lateral Movement' },
  { id: 'collection', label: 'Collection' },
  { id: 'command_and_control', label: 'Command and Control' },
  { id: 'exfiltration', label: 'Exfiltration' },
  { id: 'impact', label: 'Impact' },
  { id: 'other', label: 'Other / Unspecified' },
]

const knownTactics = new Set(tacticGroups.map(group => group.id))

function ruleTactics(rule) {
  const values = Array.isArray(rule.tactics) && rule.tactics.length ? rule.tactics : [rule.tactic]
  return [...new Set(values.map(value => {
    const id = typeof value === 'string' ? value.trim().toLowerCase().replace(/[\s-]+/g, '_') : ''
    return knownTactics.has(id) ? id : 'other'
  }))]
}

// Global stats count IDs once; each tactic group counts its unique members.
// Merge memberships if the same ID is repeated in the response.
export function uniqueRules(rules) {
  const byId = new Map()
  for (const rule of rules) {
    const existing = byId.get(rule.id)
    byId.set(rule.id, existing
      ? { ...existing, tactics: [...new Set([...ruleTactics(existing), ...ruleTactics(rule)])] }
      : rule)
  }
  return [...byId.values()]
}

export function groupRules(rules) {
  const groups = tacticGroups.map(group => ({ ...group, rules: [] }))
  const byId = new Map(groups.map(group => [group.id, group]))
  for (const rule of uniqueRules(rules)) {
    for (const id of ruleTactics(rule)) byId.get(id).rules.push(rule)
  }
  return groups.filter(group => group.rules.length > 0)
}
