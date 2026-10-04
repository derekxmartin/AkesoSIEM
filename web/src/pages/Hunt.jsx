import { useState, useMemo, useCallback, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { MagnifyingGlassIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'
import { subDays } from 'date-fns'
import QueryBar from '../components/QueryBar'
import TimePicker from '../components/TimePicker'
import ResultsHistogram from '../components/ResultsHistogram'
import ResultsTable from '../components/ResultsTable'
import FieldStatsSidebar from '../components/FieldStatsSidebar'
import ContextMenu from '../components/ContextMenu'
import { generateHistogramBuckets, computeFieldStats, appendFilter, literalFilter, validateHuntResponse, huntError, valueText } from '../lib/hunt'
import { api } from '../lib/api'

export default function Hunt() {
  usePageTitle('Hunt')
  const [searchParams, setSearchParams] = useSearchParams()
  const [query, setQuery] = useState(searchParams.get('q') || '')
  const [timeRange, setTimeRange] = useState({ relative: '24h', from: subDays(new Date(), 1), to: new Date() })
  const [refreshInterval, setRefreshInterval] = useState(0)
  const [isSearching, setIsSearching] = useState(false)
  const [results, setResults] = useState([])
  const [response, setResponse] = useState(null)
  const [error, setError] = useState(null)
  const [submittedQuery, setSubmittedQuery] = useState('')
  const requestSequence = useRef(0)
  const pendingRequests = useRef(0)
  const [pageSize, setPageSize] = useState(100)
  const [contextMenu, setContextMenu] = useState(null)
  const [showFieldStats, setShowFieldStats] = useState(true)
  const [histogramCollapsed, setHistogramCollapsed] = useState(false)
  const [histogramHeight, setHistogramHeight] = useState(80)

  const histogram = useMemo(() => generateHistogramBuckets(results), [results])
  const fieldStats = useMemo(() => computeFieldStats(results), [results])

  const handleSearch = useCallback(() => {
    if (!query.trim()) return
    const sequence = ++requestSequence.current
    pendingRequests.current++
    setIsSearching(true)
    setResults([])
    setResponse(null)
    setError(null)
    setContextMenu(null)
    const bounds = timeRange.relative
      ? { relative: timeRange.relative }
      : { from: timeRange.from.toISOString(), to: timeRange.to.toISOString() }
    api.post('/query', { query: query.trim(), size: pageSize, time_range: bounds })
      .then(validateHuntResponse)
      .then((resp) => {
        if (sequence !== requestSequence.current) return
        setResponse(resp)
        setResults(resp.result_type === 'aggregation' ? [] : resp.hits)
        setSubmittedQuery(query.trim())
      })
      .catch((err) => {
        if (sequence !== requestSequence.current) return
        setError(huntError(err))
      })
      .finally(() => {
        pendingRequests.current--
        if (sequence === requestSequence.current) setIsSearching(false)
      })
  }, [query, pageSize, timeRange])

  useEffect(() => {
    if (!refreshInterval) return
    const timer = setInterval(() => {
      // Only timer-driven refreshes wait. User searches can supersede a slow
      // request, while each completion releases only its own pending count.
      if (pendingRequests.current === 0) handleSearch()
    }, refreshInterval)
    return () => clearInterval(timer)
  }, [refreshInterval, handleSearch])

  useEffect(() => () => { requestSequence.current++ }, [])

  // Auto-search when arriving with ?q= parameter.
  useEffect(() => {
    const q = searchParams.get('q')
    if (q && results.length === 0) {
      handleSearch()
      setSearchParams({}, { replace: true })
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const handleBrushZoom = useCallback((brushRange) => {
    setTimeRange(brushRange)
  }, [])

  const handleFieldFilter = useCallback((field, value) => {
    setQuery(prev => appendFilter(prev, field, value))
  }, [])

  const handleContextMenuAction = useCallback((item) => {
    if (item.action === 'filter_in') {
      handleFieldFilter(contextMenu.field, contextMenu.value)
    } else if (item.action === 'filter_out') {
      setQuery(prev => appendFilter(prev, contextMenu.field, contextMenu.value, true))
    } else if (item.action === 'copy') {
      navigator.clipboard?.writeText(valueText(contextMenu.value))
    } else if (item.action === 'external' && item.url) {
      window.open(item.url, '_blank', 'noopener')
    } else if (item.action === 'search_all' || item.action === 'search_user' || item.action === 'search_auth') {
      setQuery(literalFilter(contextMenu.field, contextMenu.value))
    }
  }, [contextMenu, handleFieldFilter])

  return (
    <div className="-m-2 flex flex-col h-[calc(100%+1rem)] min-h-0 gap-2">
      {/* Compact header keeps the query and its actions together. */}
      <div className="grid shrink-0 grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3">
        <div className="flex items-center gap-1.5">
          <MagnifyingGlassIcon className="h-5 w-5 text-indigo-500" />
          <h1 className="text-xl font-semibold">Hunt</h1>
        </div>
        <QueryBar
          value={query}
          onChange={setQuery}
          onSearch={handleSearch}
          isSearching={isSearching}
        />
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFieldStats(prev => !prev)}
            aria-pressed={showFieldStats}
            className={`h-8 px-3 text-xs font-medium rounded-lg border transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 ${
              showFieldStats
                ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-500/10'
                : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800'
            }`}
          >
            Fields
          </button>
        </div>
      </div>

      {/* Time picker */}
      <div className="shrink-0">
        <TimePicker
          range={timeRange}
          onRangeChange={setTimeRange}
          refreshInterval={refreshInterval}
          onRefreshChange={setRefreshInterval}
          onRefresh={handleSearch}
        />
      </div>

      {isSearching && <p role="status" className="text-sm">Searching…</p>}
      {error && <p role="alert" className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      {response && (
        <div className="shrink-0 space-y-0.5 text-[11px] leading-4 text-slate-600 dark:text-slate-400 [overflow-wrap:anywhere]" data-testid="hunt-summary">
          <p className={submittedQuery === query.trim() ? 'sr-only' : undefined}>Query: {submittedQuery}</p>
          <p>Effective UTC range: <span className="font-mono">{response.time_range.from} ≤ @timestamp &lt; {response.time_range.to}</span></p>
          <p>{response.result_type === 'aggregation' ? 'Aggregate results — not individual evidence records.'
            : `Showing ${results.length} returned ${response.result_type === 'fields' ? 'field projections (partial records)' : 'events'} of ${response.total} matches. Histogram and field counts describe returned records only.`}</p>
        </div>
      )}
      {response?.result_type === 'aggregation' && (
        <pre aria-label="Aggregate results" className="p-3 text-xs overflow-auto">{JSON.stringify(response.aggs, null, 2)}</pre>
      )}

      {/* Results area */}
      {histogram.length > 0 && (
        <div className="shrink-0">
          <ResultsHistogram
            data={histogram}
            onBrushChange={handleBrushZoom}
            height={histogramHeight}
            onHeightChange={setHistogramHeight}
            collapsed={histogramCollapsed}
            onToggleCollapse={() => setHistogramCollapsed(prev => !prev)}
          />
        </div>
      )}

      {!error && !isSearching && response?.result_type !== 'aggregation' && <div className="flex flex-col md:flex-row gap-3 flex-1 min-h-64">
        {/* Field stats sidebar */}
        {showFieldStats && (
          <div className="order-last md:order-first h-32 md:h-auto w-full md:w-44 xl:w-48 shrink-0 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 overflow-hidden">
            <FieldStatsSidebar stats={fieldStats} onFilter={handleFieldFilter} />
          </div>
        )}

        {/* Results table */}
        <div className="flex-1 min-w-0 min-h-80 md:min-h-0">
          <ResultsTable
            data={results}
            emptyMessage={response ? 'No results for this query and time range.' : 'Run a search to see evidence.'}
            pageSize={pageSize}
            onPageSizeChange={setPageSize}
            onContextMenu={setContextMenu}
          />
        </div>
      </div>}

      {/* Context menu */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          field={contextMenu.field}
          value={contextMenu.value}
          onClose={() => setContextMenu(null)}
          onAction={handleContextMenuAction}
        />
      )}
    </div>
  )
}
