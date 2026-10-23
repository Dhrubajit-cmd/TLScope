import React from 'react'
import { Shield, BookOpen, Cpu, Layers, Lock } from 'lucide-react'

export const AboutView: React.FC = () => {
  return (
    <div>
      <div className="surface-card elevated">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
          <div className="brand-icon">
            <Shield size={20} strokeWidth={2.2} />
          </div>
          <div>
            <h1 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-main)' }}>
              About TLScope — Project Documentation
            </h1>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Cloud & Network Security (CNS) Academic Mini Project
            </div>
          </div>
        </div>
        <p style={{ fontSize: '14.5px', color: 'var(--text-muted)', lineHeight: 1.6, marginTop: '12px' }}>
          TLScope is an educational Transport Layer Security (TLS) and Public Key Infrastructure (PKI) analyzer designed to inspect, verify, and diagnose the security posture of HTTPS servers. It provides real-time cryptographic inspection, deterministic rule-based findings, and an interactive learning interface for students and security evaluators.
        </p>
      </div>

      {/* Core Learning Objectives */}
      <div className="surface-card">
        <div className="card-header">
          <div className="card-title">
            <BookOpen size={18} color="var(--accent-teal)" />
            Learning & Academic Objectives
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px' }}>
          <div style={{ padding: '14px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '4px' }}>
              1. TLS Handshake Dynamics
            </h4>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Observe cipher suite negotiation, protocol version selection (TLS 1.2 vs 1.3), Server Name Indication (SNI), and Perfect Forward Secrecy (PFS) in live handshakes.
            </p>
          </div>

          <div style={{ padding: '14px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '4px' }}>
              2. X.509 PKI & Chain Validation
            </h4>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Understand the hierarchical trust model: Leaf certificates, intermediate Certificate Authorities (CAs), root trust stores, and signature validation algorithms.
            </p>
          </div>

          <div style={{ padding: '14px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '4px' }}>
              3. Anti-SSRF Defense Engineering
            </h4>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Implement defensive network programming in Go to prevent Server-Side Request Forgery by pre-validating DNS resolutions against private and loopback subnets.
            </p>
          </div>

          <div style={{ padding: '14px', background: 'var(--bg-surface-subtle)', borderRadius: '6px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '4px' }}>
              4. Deterministic Findings Engine
            </h4>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Replace black-box ratings with transparent, evidence-backed security rules that explain observations and recommend practical remediation steps.
            </p>
          </div>
        </div>
      </div>

      {/* Technical Architecture */}
      <div className="surface-card">
        <div className="card-header">
          <div className="card-title">
            <Cpu size={18} color="var(--accent-teal)" />
            System Architecture
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
          <div>
            <h4 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '8px' }}>
              Backend (Go 1.26+)
            </h4>
            <ul style={{ paddingLeft: '18px', fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.7 }}>
              <li><strong>net/http:</strong> REST API router serving health, analysis, history, and demo endpoints.</li>
              <li><strong>crypto/tls:</strong> Manages TLS handshake negotiation, SNI configuration, and cipher suite discovery.</li>
              <li><strong>crypto/x509:</strong> Safe certificate parsing, SAN extraction, and chain-of-trust verification.</li>
              <li><strong>context & time:</strong> Enforces strict timeout bounds (DNS: 4s, TCP: 5s, Handshake: 6s).</li>
              <li><strong>In-Memory Store:</strong> Thread-safe ring buffer (`sync.RWMutex`) retaining recent scan records.</li>
            </ul>
          </div>

          <div>
            <h4 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '8px' }}>
              Frontend (React + TypeScript + Vite)
            </h4>
            <ul style={{ paddingLeft: '18px', fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.7 }}>
              <li><strong>Single-Page Architecture:</strong> Modular view navigation without heavy runtime overhead.</li>
              <li><strong>Enterprise Design Tokens:</strong> Pure CSS design system with crisp typography and status colors.</li>
              <li><strong>Offline HTML Reports:</strong> Generates self-contained, printable security reports.</li>
              <li><strong>Demo Fixtures:</strong> Integrated synthetic scenarios allowing live demonstration of security alerts.</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Detection Rules Matrix */}
      <div className="surface-card">
        <div className="card-header">
          <div className="card-title">
            <Layers size={18} color="var(--accent-teal)" />
            Supported Detection Rules & Checks Matrix
          </div>
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: '20%' }}>Rule ID</th>
                <th style={{ width: '12%' }}>Severity</th>
                <th style={{ width: '25%' }}>Condition</th>
                <th style={{ width: '43%' }}>Remediation Recommendation</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-EXPIRED</td>
                <td><span className="badge badge-fail">HIGH</span></td>
                <td>Current time past certificate NotAfter date</td>
                <td>Renew and deploy a valid certificate immediately via CA/ACME provider.</td>
              </tr>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-HOSTNAME-MISMATCH</td>
                <td><span className="badge badge-fail">HIGH</span></td>
                <td>Target host not present in Subject CN or SAN extension</td>
                <td>Reissue certificate including target domain in SANs or adjust SNI configuration.</td>
              </tr>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-CHAIN-UNTRUSTED</td>
                <td><span className="badge badge-fail">HIGH</span></td>
                <td>Chain verification failed against system root store</td>
                <td>Serve complete intermediate certificate bundle; obtain certificate from public CA.</td>
              </tr>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-SELF-SIGNED</td>
                <td><span className="badge badge-fail">HIGH</span></td>
                <td>Subject matches Issuer without trusted root anchor</td>
                <td>Replace self-signed certificate with one issued by a trusted public CA.</td>
              </tr>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-EXPIRING-SOON</td>
                <td><span className="badge badge-warn">MEDIUM</span></td>
                <td>Certificate expires within 14 days</td>
                <td>Initiate renewal and automated deployment before certificate expiry.</td>
              </tr>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-EXPIRING-30D</td>
                <td><span className="badge badge-warn">LOW</span></td>
                <td>Certificate expires within 30 days</td>
                <td>Verify automated renewal daemons (e.g. Certbot) are scheduled.</td>
              </tr>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-OBSOLETE-TLS</td>
                <td><span className="badge badge-fail">HIGH</span></td>
                <td>Negotiated TLS version is 1.0 or 1.1</td>
                <td>Disable deprecated TLS versions in server config; enforce TLS 1.2+ minimum.</td>
              </tr>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-TLS12-ACCEPTABLE</td>
                <td><span className="badge badge-info">INFO</span></td>
                <td>Negotiated protocol is TLS 1.2</td>
                <td>Enable TLS 1.3 for enhanced latency and security while retaining TLS 1.2 fallback.</td>
              </tr>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-TLS13-MODERN</td>
                <td><span className="badge badge-pass">INFO</span></td>
                <td>Negotiated protocol is modern TLS 1.3</td>
                <td>Optimal modern protocol. Maintain standard security patch updates.</td>
              </tr>
              <tr>
                <td style={{ fontFamily: 'var(--font-mono)' }}>TLS-RULE-WEAK-KEY</td>
                <td><span className="badge badge-fail">HIGH</span></td>
                <td>RSA public key length under 2048 bits</td>
                <td>Generate new key pair with at least RSA 2048-bit or ECDSA P-256.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Safety and Limitations */}
      <div className="surface-card">
        <div className="card-header">
          <div className="card-title">
            <Lock size={18} color="var(--accent-teal)" />
            Safety Policy & Educational Scope Limitations
          </div>
        </div>

        <div style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
          <p style={{ marginBottom: '10px' }}>
            <strong>Safe Passive Assessment:</strong> TLScope only conducts standard, passive TLS handshakes on TCP port 443. It never sends exploit payloads, conducts port scanning, or attempts authentication bypasses.
          </p>
          <p style={{ marginBottom: '10px' }}>
            <strong>SSRF Mitigation:</strong> All hostnames are validated against strict DNS syntax, and all resolved destination IP addresses are checked against RFC 1918 private ranges, loopback addresses (127.0.0.1/::1), and link-local ranges before any network socket is opened.
          </p>
          <p>
            <strong>Disclaimer:</strong> This application is developed for educational purposes in a college Cloud and Network Security course. It does not replace comprehensive penetration testing or regulatory compliance audits.
          </p>
        </div>
      </div>
    </div>
  )
}
