import React, { useState, useEffect } from 'react'
import {
  Search,
  Shield,
  ShieldAlert,
  AlertTriangle,
  XCircle,
  CheckCircle2,
  Download,
  FileText,
  Layers,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Info
} from 'lucide-react'
import type { AssessmentResult } from '../types'
import { downloadReportHTML, downloadReportJSON } from '../services/api'

interface AnalyzeViewProps {
  currentAssessment: AssessmentResult | null
  loading: boolean
  error: string | null
  onAnalyze: (hostname: string) => void
  onOpenReport: () => void
}

export const AnalyzeView: React.FC<AnalyzeViewProps> = ({
  currentAssessment,
  loading,
  error,
  onAnalyze,
  onOpenReport,
}) => {
  const [hostnameInput, setHostnameInput] = useState('')
  const [clientValidationErr, setClientValidationErr] = useState<string | null>(null)
  const [findingFilter, setFindingFilter] = useState<'ALL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'>('ALL')
  const [expandedChainIndex, setExpandedChainIndex] = useState<number | null>(0)
  const [loadingStep, setLoadingStep] = useState(0)

  // Sync input if assessment changes
  useEffect(() => {
    if (currentAssessment) {
      setHostnameInput(currentAssessment.hostname)
    }
  }, [currentAssessment])

  // Stepped loading animation
  useEffect(() => {
    if (!loading) {
      setLoadingStep(0)
      return
    }
    const timer1 = setTimeout(() => setLoadingStep(1), 400)
    const timer2 = setTimeout(() => setLoadingStep(2), 1100)
    const timer3 = setTimeout(() => setLoadingStep(3), 2000)
    const timer4 = setTimeout(() => setLoadingStep(4), 3000)

    return () => {
      clearTimeout(timer1)
      clearTimeout(timer2)
      clearTimeout(timer3)
      clearTimeout(timer4)
    }
  }, [loading])

  const validateInput = (value: string): boolean => {
    const trimmed = value.trim()
    if (!trimmed) {
      setClientValidationErr('Please enter a target hostname')
      return false
    }
    if (trimmed.includes('://') || trimmed.includes('/') || trimmed.includes('?')) {
      setClientValidationErr('URLs or paths are not permitted. Please enter only the domain (e.g. cloudflare.com)')
      return false
    }
    if (trimmed.includes(':')) {
      setClientValidationErr('Port numbers are prohibited. Assessments are restricted to port 443')
      return false
    }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(trimmed) || trimmed.includes('::')) {
      setClientValidationErr('IP address literals are disallowed. Please enter a valid DNS domain name')
      return false
    }
    if (!trimmed.includes('.')) {
      setClientValidationErr('Domain must contain at least two labels (e.g. domain.com)')
      return false
    }
    setClientValidationErr(null)
    return true
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setHostnameInput(e.target.value)
    if (clientValidationErr) {
      validateInput(e.target.value)
    }
  }

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (validateInput(hostnameInput)) {
      onAnalyze(hostnameInput.trim())
    }
  }

  const filteredFindings = (currentAssessment?.findings || []).filter((f) => {
    if (findingFilter === 'ALL') return true
    return f.severity === findingFilter
  })

  const getGradeClass = (grade: string) => {
    if (grade === 'A+' || grade === 'A') return 'grade-A'
    if (grade === 'B') return 'grade-B'
    if (grade === 'C') return 'grade-C'
    if (grade === 'F') return 'grade-F'
    return 'grade-Insufficient'
  }

  return (
    <div>
      {/* Search Bar Form */}
      <div className="surface-card">
        <form onSubmit={handleFormSubmit}>
          <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Target HTTPS Hostname (Port 443)
          </label>
          <div className="input-group">
            <input
              type="text"
              className={`text-input ${clientValidationErr ? 'error' : ''}`}
              placeholder="e.g., cloudflare.com, wikipedia.org, github.com"
              value={hostnameInput}
              onChange={handleInputChange}
              disabled={loading}
            />
            <button type="submit" className="btn btn-primary" disabled={loading || !hostnameInput.trim()}>
              {loading ? (
                <>
                  <div className="spinner" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Search size={16} />
                  <span>Analyze Domain</span>
                </>
              )}
            </button>
          </div>

          {clientValidationErr && (
            <div className="input-error-msg">
              <AlertTriangle size={14} />
              <span>{clientValidationErr}</span>
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '12px', fontSize: '12.5px', color: 'var(--text-muted)' }}>
            <span>Presets:</span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => { setHostnameInput('cloudflare.com'); onAnalyze('cloudflare.com'); }}
              disabled={loading}
            >
              cloudflare.com
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => { setHostnameInput('google.com'); onAnalyze('google.com'); }}
              disabled={loading}
            >
              google.com
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => { setHostnameInput('wikipedia.org'); onAnalyze('wikipedia.org'); }}
              disabled={loading}
            >
              wikipedia.org
            </button>
          </div>
        </form>
      </div>

      {/* Loading Progress State */}
      {loading && (
        <div className="surface-card">
          <div className="loading-phase-box">
            <div className="spinner" style={{ width: '36px', height: '36px', borderWidth: '3px', marginBottom: '16px' }} />
            <h3 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '8px' }}>
              Executing TLS Assessment for {hostnameInput}
            </h3>
            <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', marginBottom: '20px' }}>
              Connecting strictly on TCP port 443 with timeout guards and anti-SSRF verification.
            </p>

            <div className="progress-steps">
              <div className={`step-indicator ${loadingStep >= 0 ? (loadingStep > 0 ? 'done' : 'active') : ''}`}>
                1. Hostname Validation
              </div>
              <div className={`step-indicator ${loadingStep >= 1 ? (loadingStep > 1 ? 'done' : 'active') : ''}`}>
                2. DNS & SSRF Check
              </div>
              <div className={`step-indicator ${loadingStep >= 2 ? (loadingStep > 2 ? 'done' : 'active') : ''}`}>
                3. TCP & TLS Handshake
              </div>
              <div className={`step-indicator ${loadingStep >= 3 ? (loadingStep > 3 ? 'done' : 'active') : ''}`}>
                4. X.509 Chain Verification
              </div>
              <div className={`step-indicator ${loadingStep >= 4 ? 'active' : ''}`}>
                5. Findings Generation
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Global Error Banner */}
      {error && !loading && (
        <div className="surface-card" style={{ borderColor: 'var(--status-fail-border)', backgroundColor: 'var(--status-fail-bg)', borderWidth: '2px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
            <XCircle size={26} color="var(--status-fail-text)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 700, color: 'var(--status-fail-text)', fontSize: '15px', marginBottom: '6px' }}>
                Assessment Could Not Complete
              </div>
              <div style={{ fontSize: '13.5px', color: '#7f1d1d', lineHeight: 1.6, marginBottom: '12px' }}>
                {error}
              </div>
              <div style={{ fontSize: '12px', color: '#92400e', background: '#fffbeb', border: '1px solid #fef3c7', borderRadius: '6px', padding: '10px 14px', lineHeight: 1.6 }}>
                <strong>Common causes:</strong> the hostname is unreachable, the domain does not serve HTTPS on port 443,
                it resolved to a private/internal IP (SSRF protection), or the TLS connection timed out (5 s limit).
                Verify the hostname is correct and publicly accessible, then try again.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Empty state — no result, no error, not loading */}
      {!currentAssessment && !error && !loading && (
        <div className="surface-card" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <Shield size={46} color="var(--text-subtle)" style={{ marginBottom: '14px' }} />
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '8px' }}>
            No Assessment Yet
          </h2>
          <p style={{ fontSize: '14px', color: 'var(--text-muted)', maxWidth: '480px', margin: '0 auto 20px auto', lineHeight: 1.6 }}>
            Enter a publicly reachable domain above and click <strong>Analyze Domain</strong> to inspect its TLS
            configuration and digital certificate. Or use a preset button to scan a well-known host.
          </p>
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap' }}>
            {['google.com', 'cloudflare.com', 'github.com'].map(h => (
              <button key={h} className="btn btn-secondary" onClick={() => onAnalyze(h)}>
                Scan {h}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Assessment Results Details */}
      {currentAssessment && !loading && (
        <div>
          {/* Header Card with Grade & Score */}
          <div className="surface-card elevated">
            {currentAssessment.isDemo && (
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', background: '#f3e8ff', color: '#6b21a8', border: '1px solid #e9d5ff', padding: '3px 10px', borderRadius: '4px', fontSize: '11.5px', fontWeight: 600, marginBottom: '14px' }}>
                <Info size={13} />
                SIMULATED DEMO RESULT — Designed for classroom instruction without requiring live misconfigurations.
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <h2 style={{ fontSize: '24px', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em', fontFamily: 'var(--font-mono)' }}>
                    {currentAssessment.hostname}
                  </h2>
                  <span className={`badge ${currentAssessment.validation.trustStatus === 'trusted' ? 'badge-pass' : 'badge-fail'}`}>
                    {currentAssessment.validation.trustStatus}
                  </span>
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Destination: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>{currentAssessment.resolvedIp}:443</span> • Handshake: {currentAssessment.durationMs}ms • Scanned: {new Date(currentAssessment.timestamp).toLocaleString()}
                </div>
              </div>

              {/* Security Grade Avatar */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                <div className={`grade-badge ${getGradeClass(currentAssessment.securityGrade)}`}>
                  <div className="grade-letter">{currentAssessment.securityGrade}</div>
                  <div className="grade-score">{currentAssessment.score !== undefined ? `${currentAssessment.score}/100` : 'N/A'}</div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <button className="btn btn-secondary btn-sm" onClick={() => downloadReportJSON(currentAssessment)}>
                    <Download size={13} />
                    Export JSON
                  </button>
                  <button className="btn btn-secondary btn-sm" onClick={() => downloadReportHTML(currentAssessment)}>
                    <FileText size={13} />
                    Download HTML
                  </button>
                  <button className="btn btn-primary btn-sm" onClick={onOpenReport}>
                    <ExternalLink size={13} />
                    View Report
                  </button>
                </div>
              </div>
            </div>

            {/* Score Explanation */}
            <div style={{ marginTop: '16px', padding: '10px 14px', background: 'var(--bg-surface-subtle)', borderRadius: '6px', fontSize: '12.5px', color: 'var(--text-muted)' }}>
              <strong>Score Formula & Basis:</strong> {currentAssessment.scoreExplanation}
            </div>
          </div>

          {/* Metric Cards Grid */}
          <div className="stat-grid">
            <div className="stat-card">
              <div className="stat-label">Negotiated Protocol</div>
              <div className="stat-value mono" style={{ color: currentAssessment.tlsVersion === 'TLS 1.3' ? 'var(--status-pass-text)' : 'var(--text-main)' }}>
                {currentAssessment.tlsVersion || 'Unknown'}
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {currentAssessment.tlsVersion === 'TLS 1.3' ? 'Optimal (RFC 8446)' : 'Legacy Compatible'}
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Negotiated Cipher</div>
              <div className="stat-value mono" style={{ fontSize: '12px' }} title={currentAssessment.cipherSuite}>
                {currentAssessment.cipherSuite || 'None'}
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {currentAssessment.cipherSuite.includes('GCM') || currentAssessment.cipherSuite.includes('POLY1305') ? 'AEAD Encryption' : 'Non-AEAD Cipher'}
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Hostname & Chain Trust</div>
              <div className="stat-value" style={{ fontSize: '14px', color: currentAssessment.validation.chainVerified && currentAssessment.validation.hostnameVerified ? 'var(--status-pass-text)' : 'var(--status-fail-text)' }}>
                {currentAssessment.validation.chainVerified && currentAssessment.validation.hostnameVerified ? 'Verified & Trusted' : 'Trust Verification Failed'}
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Chain: {currentAssessment.validation.chainVerified ? 'Valid' : 'Invalid'} • Hostname: {currentAssessment.validation.hostnameVerified ? 'Match' : 'Mismatch'}
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Certificate Validity</div>
              {currentAssessment.peerCertificate ? (
                <>
                  <div className="stat-value" style={{ color: currentAssessment.peerCertificate.isExpired ? 'var(--status-fail-text)' : currentAssessment.peerCertificate.isExpiringSoon ? 'var(--status-warn-text)' : 'var(--status-pass-text)' }}>
                    {currentAssessment.peerCertificate.isExpired
                      ? `EXPIRED (${-currentAssessment.peerCertificate.daysRemaining}d ago)`
                      : `${currentAssessment.peerCertificate.daysRemaining} days left`}
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Expires: {new Date(currentAssessment.peerCertificate.notAfter).toLocaleDateString()}
                  </div>
                </>
              ) : (
                <div className="stat-value" style={{ color: 'var(--text-muted)' }}>No Certificate</div>
              )}
            </div>
          </div>

          {/* Certificate Technical Overview */}
          {currentAssessment.peerCertificate && (
            <div className="surface-card">
              <div className="card-header">
                <div className="card-title">
                  <Shield size={17} color="var(--accent-teal)" />
                  Presented Peer Certificate Details
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
                <div>
                  <div className="stat-label">Subject Common Name (CN)</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13.5px', fontWeight: 600 }}>
                    {currentAssessment.peerCertificate.subjectCommonName || 'N/A'}
                  </div>
                  {currentAssessment.peerCertificate.subjectOrganization?.length > 0 && (
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Org: {currentAssessment.peerCertificate.subjectOrganization.join(', ')}
                    </div>
                  )}
                </div>

                <div>
                  <div className="stat-label">Issuer Authority</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13.5px', fontWeight: 600 }}>
                    {currentAssessment.peerCertificate.issuerCommonName || 'N/A'}
                  </div>
                  {currentAssessment.peerCertificate.issuerOrganization?.length > 0 && (
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Org: {currentAssessment.peerCertificate.issuerOrganization.join(', ')}
                    </div>
                  )}
                </div>

                <div>
                  <div className="stat-label">Public Key Specifications</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13.5px' }}>
                    {currentAssessment.peerCertificate.publicKeyAlgorithm} {currentAssessment.peerCertificate.keySizeBits}-bit
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Signature: {currentAssessment.peerCertificate.signatureAlgorithm}
                  </div>
                </div>

                <div>
                  <div className="stat-label">Serial Number</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>
                    {currentAssessment.peerCertificate.serialNumber}
                  </div>
                </div>
              </div>

              {/* Subject Alternative Names (SANs) */}
              <div style={{ marginTop: '18px', borderTop: '1px solid var(--border-light)', paddingTop: '14px' }}>
                <div className="stat-label" style={{ marginBottom: '8px' }}>
                  Subject Alternative Names (SANs) ({currentAssessment.peerCertificate.dnsNames.length})
                </div>
                <div className="pill-list">
                  {currentAssessment.peerCertificate.dnsNames.map((san, idx) => (
                    <span key={idx} className="pill-item">
                      {san}
                    </span>
                  ))}
                </div>
              </div>

              {/* SHA-256 Fingerprint */}
              <div style={{ marginTop: '14px', borderTop: '1px solid var(--border-light)', paddingTop: '14px' }}>
                <div className="stat-label">SHA-256 Certificate Fingerprint</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                  {currentAssessment.peerCertificate.fingerprintSHA256}
                </div>
              </div>
            </div>
          )}

          {/* Security Findings & Remediation Section */}
          <div className="surface-card">
            <div className="card-header">
              <div>
                <div className="card-title">
                  <ShieldAlert size={17} color="var(--accent-teal)" />
                  Security Findings & Remediation Guidance ({currentAssessment.findings.length})
                </div>
                <div className="card-subtitle">
                  Deterministic findings derived from actual handshake parameters and certificate metadata.
                </div>
              </div>

              {/* Severity filter buttons */}
              <div style={{ display: 'flex', gap: '4px' }}>
                {(['ALL', 'HIGH', 'MEDIUM', 'INFO'] as const).map((sev) => (
                  <button
                    key={sev}
                    className={`btn btn-secondary btn-sm ${findingFilter === sev ? 'active' : ''}`}
                    onClick={() => setFindingFilter(sev)}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {filteredFindings.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', background: 'var(--bg-surface-subtle)', borderRadius: '6px', color: 'var(--text-muted)', fontSize: '13.5px' }}>
                No findings match the selected filter.
              </div>
            ) : (
              <div>
                {filteredFindings.map((f, idx) => {
                  const sevClass = f.severity === 'HIGH' ? 'badge-fail' : f.severity === 'MEDIUM' ? 'badge-warn' : 'badge-info'
                  return (
                    <div key={idx} className="finding-item">
                      <div className="finding-header">
                        <div className="finding-title-row">
                          <span className={`badge ${sevClass}`}>{f.severity}</span>
                          <span style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-main)' }}>{f.title}</span>
                          <span style={{ fontSize: '11.5px', fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)' }}>({f.ruleId})</span>
                        </div>
                      </div>

                      <div className="finding-body">
                        <div>
                          <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
                            Observed Evidence:
                          </div>
                          <div className="finding-evidence">{f.evidence}</div>
                        </div>

                        <div>
                          <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '2px' }}>
                            Security Explanation:
                          </div>
                          <div style={{ fontSize: '13px', color: 'var(--text-main)', lineHeight: 1.5 }}>
                            {f.explanation}
                          </div>
                        </div>

                        <div>
                          <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '2px' }}>
                            Actionable Remediation:
                          </div>
                          <div className="finding-remediation">{f.remediation}</div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Certificate Chain Hierarchy */}
          {currentAssessment.certificateChain && currentAssessment.certificateChain.length > 0 && (
            <div className="surface-card">
              <div className="card-header">
                <div className="card-title">
                  <Layers size={17} color="var(--accent-teal)" />
                  Presented Certificate Chain ({currentAssessment.certificateChain.length})
                </div>
                <div className="card-subtitle">
                  Inspect the complete chain of trust presented during the TLS handshake.
                </div>
              </div>

              <div>
                {currentAssessment.certificateChain.map((cert, index) => {
                  const isLeaf = index === 0
                  const isExpanded = expandedChainIndex === index
                  return (
                    <div
                      key={index}
                      style={{
                        border: '1px solid var(--border-light)',
                        borderRadius: '6px',
                        marginBottom: '8px',
                        overflow: 'hidden',
                      }}
                    >
                      <div
                        style={{
                          padding: '12px 16px',
                          background: isExpanded ? 'var(--bg-surface-subtle)' : 'var(--bg-surface)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          cursor: 'pointer',
                        }}
                        onClick={() => setExpandedChainIndex(isExpanded ? null : index)}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                          <span className={`badge ${isLeaf ? 'badge-pass' : 'badge-info'}`}>
                            {isLeaf ? 'Leaf / Server Cert' : `Intermediate / Root #${index}`}
                          </span>
                          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '13px' }}>
                            {cert.subjectCommonName || 'CN Not Present'}
                          </span>
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          Valid until {new Date(cert.notAfter).toLocaleDateString()}
                        </div>
                      </div>

                      {isExpanded && (
                        <div style={{ padding: '14px 16px', borderTop: '1px solid var(--border-light)', background: '#ffffff', fontSize: '12.5px' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '10px', marginBottom: '10px' }}>
                            <div>
                              <span style={{ color: 'var(--text-muted)' }}>Issuer: </span>
                              <strong>{cert.issuerCommonName}</strong>
                            </div>
                            <div>
                              <span style={{ color: 'var(--text-muted)' }}>Key: </span>
                              <strong>{cert.publicKeyAlgorithm} {cert.keySizeBits}-bit</strong>
                            </div>
                            <div>
                              <span style={{ color: 'var(--text-muted)' }}>Signature: </span>
                              <strong>{cert.signatureAlgorithm}</strong>
                            </div>
                            <div>
                              <span style={{ color: 'var(--text-muted)' }}>Serial: </span>
                              <span style={{ fontFamily: 'var(--font-mono)' }}>{cert.serialNumber}</span>
                            </div>
                          </div>
                          <div>
                            <span style={{ color: 'var(--text-muted)' }}>Fingerprint (SHA-256): </span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{cert.fingerprintSHA256}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Completed and Incomplete Checks Checklist */}
          <div className="surface-card">
            <div className="card-header">
              <div className="card-title">
                <CheckCircle2 size={17} color="var(--accent-teal)" />
                Assessment Checks Checklist ({currentAssessment.validation.completedChecks.length} Evaluated)
              </div>
            </div>

            <div className="data-table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: '12%' }}>Check ID</th>
                    <th style={{ width: '25%' }}>Check Name</th>
                    <th style={{ width: '12%' }}>Status</th>
                    <th style={{ width: '51%' }}>Evaluation Details</th>
                  </tr>
                </thead>
                <tbody>
                  {currentAssessment.validation.completedChecks.map((chk) => (
                    <tr key={chk.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{chk.id}</td>
                      <td style={{ fontWeight: 600 }}>{chk.name}</td>
                      <td>
                        <span className={`badge ${chk.passed ? 'badge-pass' : 'badge-fail'}`}>
                          {chk.passed ? 'PASSED' : 'FAILED'}
                        </span>
                      </td>
                      <td style={{ fontSize: '12.5px', color: 'var(--text-main)' }}>{chk.details}</td>
                    </tr>
                  ))}
                  {currentAssessment.validation.incompleteChecks?.map((chkId) => (
                    <tr key={chkId}>
                      <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{chkId}</td>
                      <td style={{ color: 'var(--text-muted)' }}>{chkId}</td>
                      <td>
                        <span className="badge badge-warn">INCOMPLETE</span>
                      </td>
                      <td style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                        Check could not be completed due to preceding handshake or connection termination.
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
