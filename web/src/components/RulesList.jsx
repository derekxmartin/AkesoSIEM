import { useState, useMemo, Fragment } from 'react'
import { ChevronRightIcon } from '@heroicons/react/24/outline'
import SeverityBadge from './SeverityBadge'
import { groupRules } from '../lib/rules'

const sourceLabel = {
  sigma_curated: 'Sigma',
  akeso_portfolio: 'Akeso',
}

const sourceBadgeClass = {
  sigma_curated: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  akeso_portfolio: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
}

// Shared tracks keep each value under the same column label across tactics.
const rowColumns = 'grid grid-cols-[2.5rem_6.5rem_minmax(16rem,1fr)_6.5rem_4.5rem_3.5rem_6rem] items-center gap-3 px-3'

function formatTriggered(ts) {
  if (!ts) return 'Never'
  const diff = Date.now() - new Date(ts).getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

export default function RulesList({ rules }) {
  const [collapsed, setCollapsed] = useState({})
  const [expandedRule, setExpandedRule] = useState(null)

  const grouped = useMemo(() => groupRules(rules), [rules])

  function toggleCollapse(tactic) {
    setCollapsed((prev) => ({ ...prev, [tactic]: !prev[tactic] }))
  }

  return (
    <div className="overflow-x-auto" data-testid="rules-list-scroll">
      <div className={grouped.length ? 'min-w-[880px] space-y-2' : 'space-y-2'}>
      {grouped.length > 0 && <div className={`${rowColumns} py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-400`} aria-label="Rule columns">
        <span>State</span>
        <span>Severity</span>
        <span>Rule name</span>
        <span>Technique</span>
        <span>Source</span>
        <span className="text-right">Hits</span>
        <span className="text-right">Last triggered</span>
      </div>}
      {grouped.map(({ id: tactic, label, rules: tacticRules }) => (
        <div key={tactic} data-tactic-id={tactic} className="rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
          {/* Tactic header */}
          <button
            onClick={() => toggleCollapse(tactic)}
            aria-expanded={!collapsed[tactic]}
            className="w-full flex items-center justify-between px-3 py-2 bg-slate-50 dark:bg-slate-800/50 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-indigo-500"
          >
            <div className="flex items-center gap-2">
              <ChevronRightIcon
                className={`h-4 w-4 text-slate-400 transition-transform ${collapsed[tactic] ? '' : 'rotate-90'}`}
              />
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">{label}</span>
              <span className="text-xs text-slate-600 dark:text-slate-400">({tacticRules.length} rule{tacticRules.length !== 1 ? 's' : ''})</span>
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-600 dark:text-slate-400">
              <span>{tacticRules.filter((r) => r.enabled).length} enabled</span>
              <span>{tacticRules.reduce((sum, r) => sum + (r.hitCount || 0), 0).toLocaleString()} hits</span>
            </div>
          </button>

          {/* Rules list */}
          {!collapsed[tactic] && (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {tacticRules.map((rule) => (
                <Fragment key={rule.id}>
                  <div
                    data-rule-id={rule.id}
                    role="button"
                    tabIndex={0}
                    aria-expanded={expandedRule === rule.id}
                    onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        setExpandedRule(expandedRule === rule.id ? null : rule.id)
                      }
                    }}
                    className={`${rowColumns} py-2 cursor-pointer transition-colors focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-indigo-500 ${
                      expandedRule === rule.id
                        ? 'bg-indigo-50 dark:bg-indigo-500/10'
                        : 'bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                    }`}
                  >
                    {/* Toggle */}
                    <button
                      role="switch"
                      aria-label={`Enable ${rule.name}`}
                      aria-checked={rule.enabled}
                      title="Rule state is read-only"
                      disabled
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0 ${
                        rule.enabled ? 'bg-indigo-600' : 'bg-slate-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow-sm transition-transform ${
                          rule.enabled ? 'translate-x-[1.125rem]' : 'translate-x-[0.1875rem]'
                        }`}
                      />
                    </button>

                    {/* Severity */}
                    <div className="[&>span]:text-slate-800 dark:[&>span]:text-slate-200">
                      <SeverityBadge severity={rule.severity} />
                    </div>

                    {/* Name */}
                    <div className="min-w-0">
                      <span title={rule.name} className={`text-sm font-medium truncate block ${
                        rule.enabled ? 'text-slate-800 dark:text-slate-200' : 'text-slate-600 dark:text-slate-400'
                      }`}>
                        {rule.name}
                      </span>
                    </div>

                    {/* Technique */}
                    <span className="text-xs font-mono text-slate-600 dark:text-slate-400">
                      {rule.techniqueId}
                    </span>

                    {/* Source badge */}
                    <span className={`inline-flex justify-self-start items-center px-1.5 py-0.5 rounded text-xs font-medium ${sourceBadgeClass[rule.source] || 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300'}`}>
                      {sourceLabel[rule.source] || rule.source || '—'}
                    </span>

                    {/* Hit count */}
                    <div className="text-right tabular-nums">
                      <span className="text-sm font-mono text-slate-600 dark:text-slate-300">
                        {(rule.hitCount || 0).toLocaleString()}
                      </span>
                    </div>

                    {/* Last triggered */}
                    <div className="text-right">
                      <span className="text-xs text-slate-600 dark:text-slate-400">{formatTriggered(rule.lastTriggered)}</span>
                    </div>
                  </div>

                  {/* Expanded detail row */}
                  {expandedRule === rule.id && (
                    <div className="px-3 py-3 bg-slate-50 dark:bg-slate-800/30 border-t border-slate-100 dark:border-slate-800 [overflow-wrap:anywhere]">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                        <div>
                          <p className="text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider mb-1">Description</p>
                          <p className="text-slate-700 dark:text-slate-300">{rule.description}</p>
                        </div>
                        <div className="space-y-2">
                          <div className="flex gap-4">
                            <div>
                              <p className="text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider">Technique</p>
                              <p className="text-slate-700 dark:text-slate-300 font-mono text-xs">{rule.techniqueId} — {rule.techniqueName}</p>
                            </div>
                          </div>
                          <div className="flex gap-4">
                            <div>
                              <p className="text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider">Author</p>
                              <p className="text-slate-700 dark:text-slate-300">{rule.author}</p>
                            </div>
                            <div>
                              <p className="text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider">Last Triggered</p>
                              <p className="text-slate-700 dark:text-slate-300">{rule.lastTriggered ? new Date(rule.lastTriggered).toLocaleString() : 'Never'}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </Fragment>
              ))}
            </div>
          )}
        </div>
      ))}

      {grouped.length === 0 && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-8 text-center text-slate-400">
          No rules match the current filters.
        </div>
      )}
      </div>
    </div>
  )
}
