import { useState } from 'react'
import {
  GlobeAltIcon,
  FingerPrintIcon,
  UserIcon,
  CpuChipIcon,
  ServerIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ClipboardIcon,
} from '@heroicons/react/24/outline'

const typeConfig = {
  ip: { label: 'IP Addresses', icon: ServerIcon, color: 'text-blue-500' },
  hash: { label: 'File Hashes', icon: FingerPrintIcon, color: 'text-red-500' },
  domain: { label: 'Domains', icon: GlobeAltIcon, color: 'text-green-500' },
  user: { label: 'Users', icon: UserIcon, color: 'text-amber-500' },
  process: { label: 'Processes', icon: CpuChipIcon, color: 'text-purple-500' },
  ja3: { label: 'JA3 Fingerprints', icon: FingerPrintIcon, color: 'text-cyan-500' },
  ja4: { label: 'JA4 Fingerprints', icon: FingerPrintIcon, color: 'text-teal-500' },
  community_id: { label: 'Community IDs', icon: ServerIcon, color: 'text-indigo-500' },
  sni: { label: 'SNI', icon: GlobeAltIcon, color: 'text-emerald-500' },
}

const typeOrder = ['ip', 'domain', 'hash', 'user', 'process', 'ja3', 'ja4', 'community_id', 'sni']

function groupObservables(observables) {
  const groups = {}
  for (const obs of observables) {
    if (!groups[obs.type]) groups[obs.type] = []
    groups[obs.type].push(obs)
  }
  return groups
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text)
}

export default function ObservableList({ observables }) {
  const [expanded, setExpanded] = useState({})

  if (!observables || observables.length === 0) {
    return <p className="text-sm text-slate-400">No observables extracted.</p>
  }

  const groups = groupObservables(observables)

  function toggleGroup(type) {
    setExpanded((prev) => ({ ...prev, [type]: !prev[type] }))
  }

  return (
    <div className="space-y-2">
      {typeOrder.filter((t) => groups[t]).map((type) => {
        const config = typeConfig[type] || { label: type, icon: ServerIcon, color: 'text-slate-500' }
        const Icon = config.icon
        const items = groups[type]
        const isExpanded = expanded[type] !== false // default expanded

        return (
          <div key={type} className="rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
            <button
              onClick={() => toggleGroup(type)}
              className="w-full flex items-center gap-2 px-3 py-2 bg-slate-50 dark:bg-slate-800/50 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              {isExpanded
                ? <ChevronDownIcon className="h-4 w-4 text-slate-400" />
                : <ChevronRightIcon className="h-4 w-4 text-slate-400" />
              }
              <Icon className={`h-4 w-4 ${config.color}`} />
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{config.label}</span>
              <span className="text-xs text-slate-400 ml-auto">{items.length}</span>
            </button>
            {isExpanded && (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {items.map((obs, i) => (
                  <div key={i} className="flex items-center px-3 py-1.5 group">
                    <span className="text-sm font-mono text-slate-800 dark:text-slate-200 truncate flex-1" title={obs.value}>
                      {obs.value}
                    </span>
                    <span className="text-xs text-slate-400 mr-2 shrink-0">{obs.source}</span>
                    <button
                      onClick={() => copyToClipboard(obs.value)}
                      className="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-opacity p-1"
                      title="Copy to clipboard"
                    >
                      <ClipboardIcon className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
