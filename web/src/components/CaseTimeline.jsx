import {
  ChatBubbleLeftIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  PlusCircleIcon,
  ShieldCheckIcon,
  UserIcon,
  BoltIcon,
} from '@heroicons/react/24/outline'

function formatTimestamp(ts) {
  const d = new Date(ts)
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

const actionConfig = {
  comment: { icon: ChatBubbleLeftIcon, color: 'bg-indigo-500', label: 'Comment' },
  status_change: { icon: ArrowPathIcon, color: 'bg-blue-500', label: 'Status Change' },
  alert_merged: { icon: PlusCircleIcon, color: 'bg-purple-500', label: 'Alerts Merged' },
  observable_added: { icon: PlusCircleIcon, color: 'bg-teal-500', label: 'Observable Added' },
  escalation: { icon: BoltIcon, color: 'bg-amber-500', label: 'Escalation' },
  resolution: { icon: ShieldCheckIcon, color: 'bg-green-500', label: 'Resolution' },
  assignee_changed: { icon: UserIcon, color: 'bg-cyan-500', label: 'Assignee Changed' },
  severity_changed: { icon: ExclamationTriangleIcon, color: 'bg-orange-500', label: 'Severity Changed' },
}

function renderContent(entry) {
  const c = entry.content
  switch (entry.action_type) {
    case 'comment':
      return <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap">{c.text}</p>
    case 'status_change':
      return (
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Status changed from <span className="font-medium text-slate-800 dark:text-slate-200">{c.from}</span> to{' '}
          <span className="font-medium text-slate-800 dark:text-slate-200">{c.to}</span>
        </p>
      )
    case 'alert_merged':
      return (
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Merged alerts: <span className="font-mono text-xs">{(c.alert_ids || []).join(', ')}</span>
        </p>
      )
    case 'observable_added':
      return (
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Added observable: <span className="font-mono text-xs">{c.type}: {c.value}</span>
        </p>
      )
    case 'escalation':
      return <p className="text-sm text-slate-600 dark:text-slate-400">{c.message}</p>
    case 'resolution':
      return (
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Resolved as <span className="font-medium text-slate-800 dark:text-slate-200">{c.type}</span>
          {c.notes && <span> — {c.notes}</span>}
        </p>
      )
    case 'assignee_changed':
      return (
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Assignee changed from <span className="font-medium">{c.from || 'Unassigned'}</span> to{' '}
          <span className="font-medium">{c.to || 'Unassigned'}</span>
        </p>
      )
    case 'severity_changed':
      return (
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Severity changed from <span className="font-medium">{c.from}</span> to{' '}
          <span className="font-medium">{c.to}</span>
        </p>
      )
    default:
      return <p className="text-sm text-slate-500">{JSON.stringify(c)}</p>
  }
}

export default function CaseTimeline({ timeline }) {
  if (!timeline || timeline.length === 0) {
    return <p className="text-sm text-slate-400">No timeline entries yet.</p>
  }

  // Show newest first.
  const sorted = [...timeline].reverse()

  return (
    <div className="relative pl-6 border-l-2 border-slate-200 dark:border-slate-700 space-y-5">
      {sorted.map((entry, i) => {
        const config = actionConfig[entry.action_type] || actionConfig.comment
        const Icon = config.icon
        return (
          <div key={i} className="relative">
            <div className={`absolute -left-[25px] top-1 h-4 w-4 rounded-full flex items-center justify-center ${config.color}`}>
              <Icon className="h-2.5 w-2.5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{entry.author}</span>
                <span className="text-xs text-slate-400 dark:text-slate-500">{formatTimestamp(entry.timestamp)}</span>
              </div>
              {renderContent(entry)}
            </div>
          </div>
        )
      })}
    </div>
  )
}
