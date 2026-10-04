import { useState, useMemo, useCallback, Fragment } from 'react'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
} from '@tanstack/react-table'
import { Tab, TabGroup, TabList, TabPanel, TabPanels } from '@headlessui/react'
import { ChevronRightIcon, ChevronDownIcon } from '@heroicons/react/24/outline'

import { sourceOf, fieldValue, valueText, isFilterValue, rawPayload } from '../lib/hunt'

const displayColumns = [
  { field: '@timestamp', label: 'Original timestamp', size: 216 },
  { field: 'event.action', label: 'Action', size: 152 },
  { field: 'source.ip', label: 'Src IP', size: 112 },
  { field: 'destination.ip', label: 'Dst IP', size: 112 },
  { field: 'user.name', label: 'User', size: 104 },
  { field: 'host.name', label: 'Host', size: 144 },
  { field: 'process.name', label: 'Process', size: 128 },
  { field: 'message', label: 'Message', size: 224 },
]

function ExpandedRow({ row }) {
  return (
    <TabGroup className="w-[100cqw] max-w-full min-w-0">
      <p className="px-3 py-2 text-xs leading-5 font-mono text-slate-600 dark:text-slate-300 break-all">Index: {row._index || 'Not returned'} · ID: {row._id || 'Not returned'}</p>
      <TabList className="flex border-b border-slate-200 dark:border-slate-700 px-3">
        {['Table', 'JSON', 'Raw'].map((tab) => (
          <Tab
            key={tab}
            className={({ selected }) =>
              `px-3 py-1.5 text-xs font-medium border-b-2 -mb-px transition-colors focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-indigo-500 ${
                selected
                  ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
              }`
            }
          >
            {tab}
          </Tab>
        ))}
      </TabList>

      <TabPanels className="min-w-0 p-3">
        {/* Table view */}
        <TabPanel className="min-w-0 max-h-72 overflow-auto focus-visible:outline-2 focus-visible:outline-indigo-500">
          <div className="min-w-0 rounded border border-slate-200 dark:border-slate-700 divide-y divide-slate-200 dark:divide-slate-700">
            {Object.entries(sourceOf(row)).map(([key, val]) => (
              <div key={key} className="grid grid-cols-[minmax(6rem,9rem)_minmax(0,1fr)] text-xs leading-5">
                <span className="px-2 py-1.5 font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-800/50 [overflow-wrap:anywhere]" title={key}>
                  {key}
                </span>
                <span tabIndex={0} aria-label={`${key} value`} className="min-w-0 max-h-32 overflow-auto px-2 py-1.5 font-mono text-slate-800 dark:text-slate-200 whitespace-pre-wrap [overflow-wrap:anywhere] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-indigo-500" title={valueText(val)}>
                  {valueText(val)}
                </span>
              </div>
            ))}
          </div>
        </TabPanel>

        {/* JSON view */}
        <TabPanel className="min-w-0 focus-visible:outline-2 focus-visible:outline-indigo-500">
          <pre tabIndex={0} className="min-w-0 text-xs leading-5 font-mono text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-900 rounded p-3 overflow-auto max-h-64 whitespace-pre-wrap break-all focus-visible:outline-2 focus-visible:outline-indigo-500">
            {JSON.stringify(row, null, 2)}
          </pre>
        </TabPanel>

        {/* Raw view */}
        <TabPanel className="min-w-0 focus-visible:outline-2 focus-visible:outline-indigo-500">
          <pre tabIndex={0} className="min-w-0 text-xs leading-5 font-mono text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-900 rounded p-3 overflow-auto max-h-64 whitespace-pre-wrap break-all focus-visible:outline-2 focus-visible:outline-indigo-500">
            {rawPayload(row) == null ? 'Original raw payload was not returned.' : valueText(rawPayload(row))}
          </pre>
        </TabPanel>
      </TabPanels>
    </TabGroup>
  )
}

export default function ResultsTable({ data, pageSize, onPageSizeChange, onContextMenu, emptyMessage }) {
  const [sorting, setSorting] = useState([])
  const [expandedRows, setExpandedRows] = useState({})

  const toggleExpanded = useCallback((id) => {
    setExpandedRows(prev => ({ ...prev, [id]: !prev[id] }))
  }, [])

  const columns = useMemo(() => [
    {
      id: 'expand',
      header: '',
      cell: ({ row }) => (
        <button
          onClick={(e) => { e.stopPropagation(); toggleExpanded(row.id) }}
          aria-label={expandedRows[row.id] ? 'Collapse event' : 'Expand event'}
          aria-expanded={!!expandedRows[row.id]}
          className="flex h-5 w-5 items-center justify-center rounded text-slate-500 hover:text-indigo-600 dark:hover:text-indigo-400 focus-visible:outline-2 focus-visible:outline-indigo-500"
        >
          {expandedRows[row.id]
            ? <ChevronDownIcon className="h-3.5 w-3.5" />
            : <ChevronRightIcon className="h-3.5 w-3.5" />
          }
        </button>
      ),
      size: 32,
      enableSorting: false,
    },
    ...displayColumns.map(({ field, label, size }) => ({
      id: field,
      header: label,
      accessorFn: (row) => fieldValue(row, field),
      cell: ({ getValue, row, column }) => {
        const val = getValue()
        return (
          <span
            className="text-xs font-mono text-slate-700 dark:text-slate-300 truncate block cursor-default"
            title={valueText(val)}
            onContextMenu={(e) => {
              e.preventDefault()
              if (!isFilterValue(val)) return
              onContextMenu?.({ x: e.clientX, y: e.clientY, field: column.id, value: val, row: row.original })
            }}
          >
            {valueText(val)}
          </span>
        )
      },
      size,
    })),
  ], [expandedRows, toggleExpanded, onContextMenu])

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    // Rendering keys never become evidence identities; missing metadata stays missing.
    getRowId: (row, index) => row._id != null && row._index != null ? JSON.stringify([row._index, row._id]) : `row-position-${index}`,
  })

  return (
    <div className="[container-type:inline-size] rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 overflow-hidden flex flex-col h-full">
      {/* Header bar */}
      <div className="flex shrink-0 items-center justify-between gap-2 px-3 py-1.5 bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
        <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
          Results
        </span>
        <div className="flex items-center gap-2">
          <label htmlFor="hunt-page-size" className="text-xs text-slate-600 dark:text-slate-400">Rows per page:</label>
          <select
            id="hunt-page-size"
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            className="h-7 text-xs px-2 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus-visible:outline-2 focus-visible:outline-indigo-500"
          >
            {[25, 50, 100, 200].map(n => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Scrollable table */}
      <div className="overflow-auto flex-1 min-h-0" data-testid="hunt-table-scroll">
        <table className="table-fixed w-full" style={{ minWidth: table.getTotalSize() }}>
          <colgroup>
            {table.getVisibleLeafColumns().map(column => <col key={column.id} style={{ width: column.getSize() }} />)}
          </colgroup>
          <thead className="sticky top-0 z-10">
            {table.getHeaderGroups().map(headerGroup => (
              <tr key={headerGroup.id} className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
                {headerGroup.headers.map(header => (
                  <th
                    key={header.id}
                    aria-sort={header.column.getIsSorted() === 'asc' ? 'ascending' : header.column.getIsSorted() === 'desc' ? 'descending' : undefined}
                    className="px-2 py-1.5 text-left text-[10px] font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap"
                  >
                    {header.column.getCanSort() ? <button
                      onClick={header.column.getToggleSortingHandler()}
                      className="flex items-center gap-0.5 uppercase tracking-wider rounded hover:text-indigo-600 focus-visible:outline-2 focus-visible:outline-indigo-500"
                    >
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {header.column.getIsSorted() === 'asc' && ' ↑'}
                      {header.column.getIsSorted() === 'desc' && ' ↓'}
                    </button> : flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map(row => {
              const isExpanded = expandedRows[row.id]
              return (
                <Fragment key={row.id}>
                  <tr
                    data-evidence-row=""
                    data-evidence-id={row.original._id}
                    data-evidence-index={row.original._index}
                    onClick={() => toggleExpanded(row.id)}
                    className="cursor-pointer border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                  >
                    {row.getVisibleCells().map(cell => (
                      <td
                        key={cell.id}
                        className="px-2 py-1 overflow-hidden whitespace-nowrap"
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={columns.length} className="p-0 bg-slate-50/50 dark:bg-slate-800/30 border-b border-slate-200 dark:border-slate-700">
                        <ExpandedRow row={row.original} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>

      {data.length === 0 && (
        <div className="px-4 py-12 text-center text-sm text-slate-400">
          {emptyMessage}
        </div>
      )}
    </div>
  )
}
