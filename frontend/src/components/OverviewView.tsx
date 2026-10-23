import React, { useState } from 'react'
import { ArrowRight, Play, Clock, ShieldCheck, Lock, ExternalLink } from 'lucide-react'
import type { AssessmentResult, HistorySummary } from '../types'

interface OverviewViewProps {
  onAnalyze: (hostname: string) => void
  onSelectAssessment: (assessment: AssessmentResult) => void
  onOpenTab: (tab: string) => void
  history: HistorySummary[]
  demos: AssessmentResult[]
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  onAnalyze,
  onSelectAssessment,
  onOpenTab,
  history,
  demos,
}) => {
  const [inputHost, setInputHost] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (inputHost.trim()) {
      onAnalyze(inputHost.trim())
    }
  }

  return (
    <div>
      {/* Hero Banner */}
      <div className="surface-card elevated" style={{ background: 'linear-gradient(180deg, #ffffff 0%, #f8fafc 100%)', borderTop: '3px solid var(--accent-teal)' }}>
        <div style={{ maxWidth: '800px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '3px 10px', background: 'var(--accent-teal-light)', color: 'var(--accent-teal-dark)', borderRadius: '20px', fontSize: '12px', fontWeight: 600, marginBottom: '14px' }}>
            <Lock size={13} />
            Cloud & Network Security Lab Project
          </div>
          <h1 style={{ fontSize: '28px', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em', marginBottom: '10px' }}>
            Inspect TLS Configurations & Digital Certificates
          </h1>
          <p style={{ fontSize: '15px', color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: '24px' }}>
            TLScope evaluates public HTTPS endpoints on port 443. It inspects negotiated TLS protocol versions, cipher suites, X.509 certificate chains, SAN coverage, and expiration countdowns using deterministic rule-based security findings.
          </p>

          <form onSubmit={handleSubmit} style={{ marginBottom: '16px' }}>
            <div className="input-group">
              <input
                type="text"
                className="text-input"
                placeholder="Enter public domain (e.g., cloudflare.com, github.com)..."
                value={inputHost}
                onChange={(e) => setInputHost(e.target.value)}
              />
              <button type="submit" className="btn btn-primary btn-lg" disabled={!inputHost.trim()}>
                Analyze Target
                <ArrowRight size={16} />
              </button>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '10px', fontSize: '12.5px', color: 'var(--text-muted)' }}>
              <span>Quick test targets:</span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => { setInputHost('cloudflare.com'); onAnalyze('cloudflare.com'); }}
              >
                cloudflare.com
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => { setInputHost('wikipedia.org'); onAnalyze('wikipedia.org'); }}
              >
                wikipedia.org
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => { setInputHost('github.com'); onAnalyze('github.com'); }}
              >
                github.com
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Demo Scenarios Section */}
      <div className="surface-card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <Play size={18} color="var(--accent-teal)" />
              Classroom Demo Scenarios
            </div>
            <div className="card-subtitle">
              Explore common PKI and certificate failure modes using simulated test fixtures without relying on misconfigured live servers.
            </div>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={() => onOpenTab('demo')}>
            View All Demos
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
          {demos.slice(0, 4).map((d) => {
            return (
              <div
                key={d.id}
                style={{
                  border: '1px solid var(--border-light)',
                  borderRadius: '6px',
                  padding: '16px',
                  backgroundColor: 'var(--bg-surface)',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  cursor: 'pointer',
                  transition: 'transform 0.1s ease, border-color 0.15s ease',
                }}
                onClick={() => onSelectAssessment(d)}
                onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--accent-teal)')}
                onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border-light)')}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span className="badge badge-demo">Demo</span>
                    <span className={`badge ${d.securityGrade === 'A+' || d.securityGrade === 'A' ? 'badge-pass' : d.securityGrade === 'B' ? 'badge-warn' : 'badge-fail'}`}>
                      Grade {d.securityGrade}
                    </span>
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '13.5px', marginBottom: '4px', color: 'var(--text-main)' }}>
                    {d.hostname}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px', lineHeight: 1.4 }}>
                    {d.findings[0]?.title || 'Baseline TLS evaluation'}
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-light)', paddingTop: '10px' }}>
                  <span style={{ fontSize: '11px', color: 'var(--text-subtle)' }}>
                    {d.findings.length} Finding{d.findings.length !== 1 ? 's' : ''}
                  </span>
                  <span style={{ fontSize: '12px', color: 'var(--accent-teal-dark)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                    Inspect <ExternalLink size={12} />
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Recent History Snapshot */}
      {history.length > 0 && (
        <div className="surface-card">
          <div className="card-header">
            <div>
              <div className="card-title">
                <Clock size={18} color="var(--accent-teal)" />
                Recent Assessments
              </div>
              <div className="card-subtitle">
                Summaries of recent scans held in session memory.
              </div>
            </div>
            <button className="btn btn-secondary btn-sm" onClick={() => onOpenTab('history')}>
              Full History ({history.length})
            </button>
          </div>

          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Target Hostname</th>
                  <th>Resolved IP</th>
                  <th>TLS Version</th>
                  <th>Trust Status</th>
                  <th>Grade</th>
                  <th>Findings</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {history.slice(0, 5).map((h) => (
                  <tr key={h.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{h.hostname}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{h.resolvedIp}</td>
                    <td>{h.tlsVersion || 'N/A'}</td>
                    <td>
                      <span className={`badge ${h.trustStatus === 'trusted' ? 'badge-pass' : h.trustStatus === 'expired' || h.trustStatus === 'mismatch' || h.trustStatus === 'untrusted' ? 'badge-fail' : 'badge-warn'}`}>
                        {h.trustStatus}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${h.securityGrade === 'A+' || h.securityGrade === 'A' ? 'badge-pass' : h.securityGrade === 'B' ? 'badge-warn' : 'badge-fail'}`}>
                        {h.securityGrade}
                      </span>
                    </td>
                    <td>{h.findingCount}</td>
                    <td>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => onAnalyze(h.hostname)}
                      >
                        Re-Scan
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Technical Capabilities Matrix */}
      <div className="surface-card">
        <div className="card-header">
          <div className="card-title">
            <ShieldCheck size={18} color="var(--accent-teal)" />
            Core Technical Capabilities
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
          <div style={{ padding: '14px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
            <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px', color: 'var(--text-main)' }}>
              1. Strict Hostname Matching
            </div>
            <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Implements RFC 6125 and RFC 2818 rules, verifying wildcards and Subject Alternative Names (SANs) against requested targets.
            </div>
          </div>

          <div style={{ padding: '14px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
            <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px', color: 'var(--text-main)' }}>
              2. X.509 PKI Chain Trust
            </div>
            <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Validates digital signature hierarchy and intermediate certificates against the system root store without bypassing trust errors.
            </div>
          </div>

          <div style={{ padding: '14px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
            <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px', color: 'var(--text-main)' }}>
              3. Anti-SSRF Protection
            </div>
            <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Resolves DNS and blocks loopback, private RFC 1918, link-local, carrier-grade NAT, and intranet IP targets.
            </div>
          </div>

          <div style={{ padding: '14px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
            <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px', color: 'var(--text-main)' }}>
              4. Explainable Findings Engine
            </div>
            <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Translates cryptographic observations into plain-English severity alerts with concrete remediation recommendations.
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
