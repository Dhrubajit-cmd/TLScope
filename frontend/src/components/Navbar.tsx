import React from 'react'
import { Shield, Search, History, FileText, Info, PlayCircle, AlertCircle } from 'lucide-react'
import type { HealthResponse } from '../types'

interface NavbarProps {
  activeTab: string
  setActiveTab: (tab: string) => void
  health: HealthResponse | null
  healthLoading: boolean
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  health,
  healthLoading,
}) => {
  return (
    <header className="navbar">
      <div className="nav-inner">
        <div className="brand-section" onClick={() => setActiveTab('overview')}>
          <div className="brand-icon">
            <Shield size={20} strokeWidth={2.2} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <span className="brand-name">TLScope</span>
              <span className="brand-tag">CNS Mini Project</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              TLS & Digital Certificate Security Analyzer
            </div>
          </div>
        </div>

        <nav className="nav-tabs">
          <button
            className={`nav-tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'analyze' ? 'active' : ''}`}
            onClick={() => setActiveTab('analyze')}
          >
            <Search size={15} />
            Analyze Domain
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'demo' ? 'active' : ''}`}
            onClick={() => setActiveTab('demo')}
          >
            <PlayCircle size={15} />
            Demo Scenarios
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            <History size={15} />
            Scan History
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'report' ? 'active' : ''}`}
            onClick={() => setActiveTab('report')}
          >
            <FileText size={15} />
            Report
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'about' ? 'active' : ''}`}
            onClick={() => setActiveTab('about')}
          >
            <Info size={15} />
            About
          </button>
        </nav>

        <div className="nav-status">
          {healthLoading ? (
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Checking API...</span>
          ) : health && health.status === 'ok' ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }} title={`API v${health.version} online`}>
              <div className="status-dot" />
              <span>Backend Online</span>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#b91c1c' }}>
              <AlertCircle size={14} />
              <span>Backend Offline</span>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
