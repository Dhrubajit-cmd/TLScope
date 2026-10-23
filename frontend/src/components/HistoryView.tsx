import React, { useState } from 'react'
import { History, Trash2, ExternalLink, ArrowRight } from 'lucide-react'
import type { HistorySummary } from '../types'
import { clearHistory } from '../services/api'

interface HistoryViewProps {
  history: HistorySummary[]
  onSelectHistoryItem: (id: string) => void
  onClearHistory: () => void
  onOpenAnalyze: () => void
}

export const HistoryView: React.FC<HistoryViewProps> = ({
  history,
  onSelectHistoryItem,
  onClearHistory,
  onOpenAnalyze,
}) => {
  const [filterQuery, setFilterQuery] = useState('')
  const [clearing, setClearing] = useState(false)

  const handleClear = async () => {
    if (!window.confirm('Clear all in-memory scan history?')) return
    setClearing(true)
    try {
      await clearHistory()
      onClearHistory()
    } catch (err) {
      console.error(err)
    } finally {
      setClearing(false)
    }
  }

  const filteredHistory = history.filter((item) => {
    const q = filterQuery.toLowerCase()
    return (
      item.hostname.toLowerCase().includes(q) ||
      item.resolvedIp.toLowerCase().includes(q) ||
      item.trustStatus.toLowerCase().includes(q) ||
      item.securityGrade.toLowerCase().includes(q)
    )
  })

  return (
    <div>
      <div className="surface-card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <History size={18} color="var(--accent-teal)" />
              Assessment History ({history.length})
            </div>
            <div className="card-subtitle">
              Bounded in-memory scan log retained for the active session.
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="btn btn-danger btn-sm"
              onClick={handleClear}
              disabled={history.length === 0 || clearing}
            >
              <Trash2 size={13} />
              Clear History
            </button>
          </div>
        </div>

        {/* Filter Input */}
        <div style={{ marginBottom: '16px' }}>
          <div className="input-group" style={{ maxWidth: '360px' }}>
            <input
              type="text"
              className="text-input"
              placeholder="Filter by hostname, IP, or status..."
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              style={{ padding: '7px 12px', fontSize: '13px' }}
            />
          </div>
        </div>

        {filteredHistory.length === 0 ? (
          <div style={{ padding: '36px', textAlign: 'center', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
            <History size={32} color="var(--text-subtle)" style={{ marginBottom: '10px' }} />
            <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>
              No Assessments Found
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '16px' }}>
              {filterQuery ? 'No scan results match the filter query.' : 'Run your first TLS domain assessment or explore demo scenarios.'}
            </div>
            <button className="btn btn-primary btn-sm" onClick={onOpenAnalyze}>
              Analyze a Domain Now
              <ArrowRight size={13} />
            </button>
          </div>
        ) : (
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Target Hostname</th>
                  <th>Resolved IP</th>
                  <th>Timestamp</th>
                  <th>TLS Version</th>
                  <th>Trust Status</th>
                  <th>Grade / Score</th>
                  <th>Findings</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredHistory.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{item.hostname}</span>
                        {item.isDemo && <span className="badge badge-demo">Demo</span>}
                      </div>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{item.resolvedIp}</td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td>{item.tlsVersion || 'N/A'}</td>
                    <td>
                      <span className={`badge ${item.trustStatus === 'trusted' ? 'badge-pass' : item.trustStatus === 'expired' || item.trustStatus === 'mismatch' || item.trustStatus === 'untrusted' ? 'badge-fail' : 'badge-warn'}`}>
                        {item.trustStatus}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${item.securityGrade === 'A+' || item.securityGrade === 'A' ? 'badge-pass' : item.securityGrade === 'B' ? 'badge-warn' : 'badge-fail'}`}>
                        {item.securityGrade} {item.score !== undefined ? `(${item.score})` : ''}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '4px' }}>
                        {item.highSeverityCount > 0 && (
                          <span className="badge badge-fail" title={`${item.highSeverityCount} High Findings`}>
                            {item.highSeverityCount} High
                          </span>
                        )}
                        {item.warningCount > 0 && (
                          <span className="badge badge-warn" title={`${item.warningCount} Warnings`}>
                            {item.warningCount} Warn
                          </span>
                        )}
                        {item.findingCount === 0 && (
                          <span className="badge badge-pass">0 Issues</span>
                        )}
                      </div>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => onSelectHistoryItem(item.id)}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                      >
                        Reopen <ExternalLink size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
