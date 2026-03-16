import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bars3Icon, BellIcon, SparklesIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline'
import ThemeToggle from './ThemeToggle'
import UserMenu from './UserMenu'

export default function Header({ onMobileMenuToggle }) {
  const [searchQuery, setSearchQuery] = useState('')
  const navigate = useNavigate()

  function handleSearch(e) {
    if (e.key === 'Enter' && searchQuery.trim()) {
      navigate(`/hunt?q=${encodeURIComponent(searchQuery.trim())}`)
      setSearchQuery('')
    }
  }

  return (
    <header className="sticky top-0 z-30 h-16 flex items-center gap-4 px-4 border-b border-slate-200 bg-white/80 dark:border-slate-700 dark:bg-slate-900/80 backdrop-blur-md">
      {/* Mobile menu button */}
      <button
        onClick={onMobileMenuToggle}
        className="lg:hidden text-slate-400 hover:text-white"
      >
        <Bars3Icon className="h-6 w-6" />
      </button>

      {/* Time range placeholder (left) */}
      <div className="hidden sm:flex items-center gap-2 text-sm text-slate-400">
        <span className="px-3 py-1.5 rounded-md bg-slate-100 border border-slate-200 text-slate-600 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300">
          Last 24 hours
        </span>
      </div>

      {/* Global search — navigates to Hunt page */}
      <div className="flex-1 max-w-lg mx-auto">
        <div className="relative">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={handleSearch}
            placeholder="Search events... (Enter to hunt)"
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-600 placeholder-slate-400 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300 dark:placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500"
          />
        </div>
      </div>

      {/* Right section */}
      <div className="flex items-center gap-3">
        <ThemeToggle />

        {/* AI assistant placeholder */}
        <button className="text-slate-400 hover:text-indigo-400 transition-colors" title="AI Assistant">
          <SparklesIcon className="h-5 w-5" />
        </button>

        {/* Notifications placeholder */}
        <button className="text-slate-400 hover:text-white transition-colors" title="Notifications">
          <BellIcon className="h-5 w-5" />
        </button>

        {/* User menu */}
        <UserMenu />
      </div>
    </header>
  )
}
