import React from 'react'
import { PlayCircle, ArrowRight } from 'lucide-react'
import type { AssessmentResult } from '../types'

interface DemoViewProps {
  demos: AssessmentResult[]
  onSelectDemo: (demo: AssessmentResult) => void
}

export const DemoView: React.FC<DemoViewProps> = ({ demos, onSelectDemo }) => {
  return (
    <div>
      <div className="surface-card elevated">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <PlayCircle size={22} color="var(--accent-teal)" />
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-main)' }}>
            Classroom Security Demonstration Fixtures
          </h2>
        </div>
        <p style={{ fontSize: '14px', color: 'var(--text-muted)', lineHeight: 1.6, maxWidth: '850px' }}>
          Real public services strive to maintain valid certificates, making live demonstrations of security alerts difficult during a viva or presentation. TLScope provides these deterministic synthetic test cases to demonstrate certificate expiration, SAN mismatching, untrusted root authorities, and protocol warnings.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '16px' }}>
        {demos.map((demo) => {
          const highFinding = demo.findings.find((f) => f.severity === 'HIGH')
          const warnFinding = demo.findings.find((f) => f.severity === 'MEDIUM')
          const primaryFinding = highFinding || warnFinding || demo.findings[0]

          const getGradeBadge = (grade: string) => {
            if (grade === 'A+' || grade === 'A') return 'badge-pass'
            if (grade === 'B') return 'badge-warn'
            return 'badge-fail'
          }

          return (
            <div
              key={demo.id}
              className="surface-card"
              style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                borderLeft: `4px solid ${demo.securityGrade === 'A+' || demo.securityGrade === 'A' ? '#10b981' : demo.securityGrade === 'B' ? '#f59e0b' : '#ef4444'}`,
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                  <div>
                    <span className="badge badge-demo" style={{ marginBottom: '6px' }}>Simulated Test Case</span>
                    <h3 style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>
                      {demo.hostname}
                    </h3>
                  </div>
                  <span className={`badge ${getGradeBadge(demo.securityGrade)}`} style={{ fontSize: '13px', padding: '4px 10px' }}>
                    Grade {demo.securityGrade}
                  </span>
                </div>

                <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginBottom: '14px' }}>
                  {primaryFinding ? (
                    <div>
                      <strong style={{ color: 'var(--text-main)' }}>{primaryFinding.title}</strong>
                      <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        Rule: <span style={{ fontFamily: 'var(--font-mono)' }}>{primaryFinding.ruleId}</span>
                      </div>
                      <div style={{ marginTop: '6px', background: 'var(--bg-surface-subtle)', padding: '6px 10px', borderRadius: '4px', fontSize: '12px', color: '#334155' }}>
                        {primaryFinding.evidence}
                      </div>
                    </div>
                  ) : (
                    'Valid TLS configuration satisfying baseline security checks.'
                  )}
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px', fontSize: '12px', borderTop: '1px solid var(--border-light)', paddingTop: '10px', marginBottom: '16px' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Protocol: </span>
                    <strong style={{ fontFamily: 'var(--font-mono)' }}>{demo.tlsVersion}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Trust: </span>
                    <strong style={{ textTransform: 'capitalize' }}>{demo.validation.trustStatus}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Key Size: </span>
                    <strong>{demo.peerCertificate?.keySizeBits || 2048}-bit</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Score: </span>
                    <strong>{demo.score !== undefined ? `${demo.score}/100` : 'N/A'}</strong>
                  </div>
                </div>
              </div>

              <button
                className="btn btn-secondary btn-sm"
                onClick={() => onSelectDemo(demo)}
                style={{ width: '100%', display: 'flex', justifyContent: 'center', gap: '6px' }}
              >
                Inspect in Analyzer
                <ArrowRight size={14} />
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}
