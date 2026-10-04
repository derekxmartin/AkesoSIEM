import { useState, useEffect, useMemo } from 'react'
import { ShieldCheckIcon, ListBulletIcon, TableCellsIcon, FunnelIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'
import RulesList from '../components/RulesList'
import AttackHeatmap from '../components/AttackHeatmap'
import { api } from '../lib/api'
import { uniqueRules } from '../lib/rules'

const tabs = [
  { id: 'list', label: 'Detection Rules', icon: ListBulletIcon },
  { id: 'heatmap', label: 'ATT&CK Coverage', icon: TableCellsIcon },
]

export default function Rules() {
  usePageTitle('Rules')
  const [activeTab, setActiveTab] = useState('list')
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true
    api.get('/rules')
      .then((resp) => {
        if (!Array.isArray(resp?.rules)) throw new Error('Invalid rules response')
        if (active) setRules(uniqueRules(resp.rules))
      })
      .catch((err) => { if (active) setError(err.message || 'Request failed') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])
  const [severityFilter, setSeverityFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [enabledFilter, setEnabledFilter] = useState('')

  const filteredRules = useMemo(() => {
    let result = rules
    if (severityFilter) result = result.filter((r) => r.severity === severityFilter)
    if (sourceFilter) result = result.filter((r) => r.source === sourceFilter)
    if (enabledFilter === 'enabled') result = result.filter((r) => r.enabled)
    if (enabledFilter === 'disabled') result = result.filter((r) => !r.enabled)
    return result
  }, [rules, severityFilter, sourceFilter, enabledFilter])

  const ruleStats = useMemo(() => ({
    total: rules.length,
    enabled: rules.filter((r) => r.enabled).length,
    totalHits: rules.reduce((sum, r) => sum + (r.hitCount || 0), 0),
  }), [rules])

  const hasFilters = severityFilter || sourceFilter || enabledFilter

  return (
    <div className="-m-2 space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheckIcon className="h-5 w-5 text-indigo-500" />
          <h1 className="text-xl font-semibold">Rules</h1>
          <span className="ml-1 text-xs text-slate-600 dark:text-slate-400">
            {ruleStats.enabled}/{ruleStats.total} enabled
          </span>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-3 gap-2" data-testid="rules-summary">
        <div className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2.5">
          <p className="text-xs font-medium text-slate-600 dark:text-slate-400">Total Rules</p>
          <p className="text-xl font-semibold tabular-nums text-slate-900 dark:text-white">{ruleStats.total}</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2.5">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-medium text-slate-600 dark:text-slate-400">Enabled</p>
            <p className="text-xl font-semibold tabular-nums text-slate-900 dark:text-white">{ruleStats.enabled}</p>
          </div>
          <div className="mt-1 h-1 rounded-full bg-slate-100 dark:bg-slate-700 overflow-hidden">
            <div
              className="h-full rounded-full bg-indigo-300 dark:bg-indigo-500/60"
              style={{ width: `${ruleStats.total ? (ruleStats.enabled / ruleStats.total) * 100 : 0}%` }}
            />
          </div>
        </div>
        <div className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2.5">
          <p className="text-xs font-medium text-slate-600 dark:text-slate-400">Total Hits</p>
          <p className="text-xl font-semibold tabular-nums text-slate-900 dark:text-white">{ruleStats.totalHits.toLocaleString()}</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-slate-200 dark:border-slate-700">
        <div className="flex gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 h-9 px-3 text-xs font-medium border-b-2 transition-colors -mb-px focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-indigo-500 ${
                activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                  : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-300'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Filters (list view only) */}
        {activeTab === 'list' && (
          <div className="flex flex-wrap items-center gap-2 pb-2">
            <FunnelIcon className="h-4 w-4 text-slate-500" />
            <select
              aria-label="Severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="h-8 px-2 rounded-lg text-xs border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus-visible:outline-2 focus-visible:outline-indigo-500"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
            <select
              aria-label="Source"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="h-8 px-2 rounded-lg text-xs border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus-visible:outline-2 focus-visible:outline-indigo-500"
            >
              <option value="">All Sources</option>
              <option value="sigma_curated">Sigma</option>
              <option value="akeso_portfolio">Akeso</option>
            </select>
            <select
              aria-label="State"
              value={enabledFilter}
              onChange={(e) => setEnabledFilter(e.target.value)}
              className="h-8 px-2 rounded-lg text-xs border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus-visible:outline-2 focus-visible:outline-indigo-500"
            >
              <option value="">All States</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
            {hasFilters && (
              <button
                onClick={() => { setSeverityFilter(''); setSourceFilter(''); setEnabledFilter('') }}
                className="h-8 px-2 rounded-lg text-xs font-medium text-indigo-700 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-500/10 focus-visible:outline-2 focus-visible:outline-indigo-500"
              >
                Clear
              </button>
            )}
          </div>
        )}
      </div>

      {/* Tab content */}
      {activeTab === 'list' && (loading ? (
        <p role="status" className="p-8 text-center text-slate-400">Loading rules...</p>
      ) : error ? (
        <div role="alert" className="rounded-lg border border-red-300 dark:border-red-800 p-4 text-red-700 dark:text-red-300">
          Unable to load rules: {error}
        </div>
      ) : (
        <RulesList rules={filteredRules} />
      ))}
      {activeTab === 'heatmap' && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <AttackHeatmap />
        </div>
      )}
    </div>
  )
}
