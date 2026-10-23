import React from 'react'
import { FileText, Download, Printer, ArrowRight } from 'lucide-react'
import type { AssessmentResult } from '../types'
import { downloadReportHTML, downloadReportJSON } from '../services/api'

interface ReportViewProps {
  currentAssessment: AssessmentResult | null
  onOpenAnalyze: () => void
}

export const ReportView: React.FC<ReportViewProps> = ({ currentAssessment, onOpenAnalyze }) => {
  if (!currentAssessment) {
    return (
      <div className="surface-card" style={{ textAlign: 'center', padding: '48px 24px' }}>
        <FileText size={42} color="var(--text-subtle)" style={{ marginBottom: '12px' }} />
        <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '6px' }}>
          No Assessment Selected for Reporting
        </h2>
        <p style={{ fontSize: '14px', color: 'var(--text-muted)', marginBottom: '20px', maxWidth: '500px', margin: '0 auto 20px auto' }}>
          Execute an assessment on any domain or select a demo scenario to view and export the formal security report.
        </p>
        <button className="btn btn-primary" onClick={onOpenAnalyze}>
          Run Domain Assessment
          <ArrowRight size={15} />
        </button>
      </div>
    )
  }

  const cert = currentAssessment.peerCertificate
  const scoreStr = currentAssessment.score !== undefined ? `${currentAssessment.score} / 100` : 'Insufficient data'

  const handlePrint = () => {
    window.print()
  }

  return (
    <div>
      {/* Top Action Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px', flexWrap: 'wrap', gap: '10px' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-main)' }}>
            Security Assessment Report Preview
          </h2>
          <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            Target: <strong style={{ fontFamily: 'var(--font-mono)' }}>{currentAssessment.hostname}</strong> (Port 443)
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn-secondary btn-sm" onClick={() => downloadReportJSON(currentAssessment)}>
            <Download size={14} />
            Export JSON
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => downloadReportHTML(currentAssessment)}>
            <Download size={14} />
            Download HTML File
          </button>
          <button className="btn btn-secondary btn-sm" onClick={handlePrint}>
            <Printer size={14} />
            Print Report
          </button>
        </div>
      </div>

      {/* Printable Report Sheet */}
      <div className="surface-card elevated" style={{ padding: '36px', maxWidth: '960px', margin: '0 auto', borderTop: '4px solid var(--accent-teal)' }}>
        {/* Report Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '2px solid #e2e8f0', paddingBottom: '20px', marginBottom: '24px' }}>
          <div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--accent-teal)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '4px' }}>
              TLScope Security Assessment Report
            </div>
            <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em', marginBottom: '4px' }}>
              {currentAssessment.hostname}
            </h1>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Resolved Destination: <span style={{ fontFamily: 'var(--font-mono)' }}>{currentAssessment.resolvedIp}:443</span> • Timestamp: {new Date(currentAssessment.timestamp).toUTCString()}
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div className={`badge ${currentAssessment.securityGrade === 'A+' || currentAssessment.securityGrade === 'A' ? 'badge-pass' : currentAssessment.securityGrade === 'B' ? 'badge-warn' : 'badge-fail'}`} style={{ fontSize: '18px', padding: '6px 16px', fontWeight: 800 }}>
              Grade {currentAssessment.securityGrade}
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Score: <strong>{scoreStr}</strong>
            </div>
          </div>
        </div>

        {/* Executive Summary */}
        <div style={{ marginBottom: '28px' }}>
          <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '12px' }}>
            1. Executive Assessment Summary
          </div>
          <p style={{ fontSize: '14px', color: 'var(--text-main)', lineHeight: 1.6, marginBottom: '12px' }}>
            An automated cryptographic handshake and PKI certificate analysis was performed on host <strong>{currentAssessment.hostname}</strong> over port 443. The server negotiated protocol <strong>{currentAssessment.tlsVersion}</strong> utilizing cipher suite <strong>{currentAssessment.cipherSuite}</strong>.
          </p>
          <div style={{ padding: '12px', background: 'var(--bg-surface-subtle)', borderRadius: '6px', fontSize: '13px', color: 'var(--text-muted)' }}>
            <strong>Scoring Methodology:</strong> {currentAssessment.scoreExplanation}
          </div>
        </div>

        {/* Observed Parameters */}
        <div style={{ marginBottom: '28px' }}>
          <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '12px' }}>
            2. Transport & Certificate Observations
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px' }}>
            <div style={{ padding: '12px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Negotiated Protocol</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '14px' }}>{currentAssessment.tlsVersion}</div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Cipher Suite</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '12px' }}>{currentAssessment.cipherSuite}</div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Hostname Verification</div>
              <div style={{ fontWeight: 600, color: currentAssessment.validation.hostnameVerified ? 'var(--status-pass-text)' : 'var(--status-fail-text)' }}>
                {currentAssessment.validation.hostnameVerified ? 'MATCHED (RFC 6125 Valid)' : 'FAILED (Mismatch)'}
              </div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Chain Verification</div>
              <div style={{ fontWeight: 600, color: currentAssessment.validation.chainVerified ? 'var(--status-pass-text)' : 'var(--status-fail-text)' }}>
                {currentAssessment.validation.chainVerified ? 'VERIFIED (Public CA Trust)' : 'FAILED (Untrusted / Missing)'}
              </div>
            </div>
          </div>
        </div>

        {/* Certificate Details */}
        {cert && (
          <div style={{ marginBottom: '28px' }}>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '12px' }}>
              3. Digital Certificate Specification
            </div>
            <table className="data-table">
              <tbody>
                <tr>
                  <td style={{ width: '25%', fontWeight: 600 }}>Subject Common Name</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{cert.subjectCommonName}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Issuer Common Name</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{cert.issuerCommonName}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Temporal Validity Window</td>
                  <td>
                    {new Date(cert.notBefore).toLocaleDateString()} to {new Date(cert.notAfter).toLocaleDateString()} ({cert.daysRemaining} days remaining)
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Public Key Specification</td>
                  <td>{cert.publicKeyAlgorithm} {cert.keySizeBits}-bit (Signature: {cert.signatureAlgorithm})</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Subject Alternative Names</td>
                  <td style={{ fontSize: '12px', fontFamily: 'var(--font-mono)' }}>{cert.dnsNames.join(', ')}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>SHA-256 Fingerprint</td>
                  <td style={{ fontSize: '11px', fontFamily: 'var(--font-mono)' }}>{cert.fingerprintSHA256}</td>
                </tr>
              </tbody>
            </table>
          </div>
        )}

        {/* Security Findings */}
        <div style={{ marginBottom: '28px' }}>
          <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '12px' }}>
            4. Security Findings & Recommended Remediation ({currentAssessment.findings.length})
          </div>

          {currentAssessment.findings.length === 0 ? (
            <div style={{ padding: '16px', background: '#ecfdf5', border: '1px solid #a7f3d0', borderRadius: '6px', color: '#065f46', fontSize: '13.5px' }}>
              Zero security vulnerabilities or misconfigurations detected. All evaluated parameters meet current standards.
            </div>
          ) : (
            <div className="data-table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: '12%' }}>Severity</th>
                    <th style={{ width: '28%' }}>Rule & Title</th>
                    <th style={{ width: '30%' }}>Observed Evidence</th>
                    <th style={{ width: '30%' }}>Remediation Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {currentAssessment.findings.map((f, i) => (
                    <tr key={i}>
                      <td>
                        <span className={`badge ${f.severity === 'HIGH' ? 'badge-fail' : f.severity === 'MEDIUM' ? 'badge-warn' : 'badge-info'}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td>
                        <strong>{f.title}</strong>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{f.ruleId}</div>
                      </td>
                      <td style={{ fontSize: '12px' }}>{f.evidence}</td>
                      <td style={{ fontSize: '12px', color: '#166534' }}>{f.remediation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Academic Limitations & Disclaimer */}
        <div style={{ padding: '16px', background: '#fffbeb', border: '1px solid #fef3c7', borderRadius: '6px', fontSize: '12px', color: '#92400e', lineHeight: 1.5 }}>
          <strong>Academic Course Context & Limitations:</strong> TLScope is an educational network security assessment tool developed for a Cloud and Network Security course. Assessments are restricted to passive TLS handshakes on standard TCP port 443 with bounded timeouts and anti-SSRF protections. This report does not represent a full penetration test, web application vulnerability scan, or absolute guarantee of server infrastructure security.
        </div>
      </div>
    </div>
  )
}
