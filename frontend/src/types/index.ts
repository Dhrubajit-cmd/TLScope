export interface CertificateSummary {
  subjectCommonName: string
  subjectOrganization: string[]
  issuerCommonName: string
  issuerOrganization: string[]
  serialNumber: string
  notBefore: string
  notAfter: string
  daysRemaining: number
  isExpired: boolean
  isExpiringSoon: boolean
  dnsNames: string[]
  ipAddresses?: string[]
  signatureAlgorithm: string
  publicKeyAlgorithm: string
  keySizeBits: number
  fingerprintSHA256: string
  ocspServer?: string[]
  crlDistributionPoints?: string[]
  isCA: boolean
}

export interface CheckResult {
  id: string
  name: string
  description: string
  passed: boolean
  status: 'passed' | 'failed' | 'incomplete'
  details: string
}

export interface Finding {
  ruleId: string
  title: string
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  affectedHostname: string
  evidence: string
  explanation: string
  remediation: string
  status: 'failed' | 'warning' | 'info' | 'passed'
}

export interface ValidationResult {
  hostnameVerified: boolean
  hostnameError?: string
  chainVerified: boolean
  chainError?: string
  trustStatus: 'trusted' | 'untrusted' | 'expired' | 'mismatch' | 'failed' | 'incomplete'
  completedChecks: CheckResult[]
  incompleteChecks: string[]
}

export interface AssessmentResult {
  id: string
  hostname: string
  resolvedIp: string
  port: number
  timestamp: string
  durationMs: number
  status: 'completed' | 'failed' | 'incomplete'
  errorMessage?: string
  tlsVersion: string
  tlsVersionRaw: number
  cipherSuite: string
  cipherSuiteRaw: number
  serverName: string
  negotiatedProtocol?: string
  peerCertificate?: CertificateSummary
  certificateChain?: CertificateSummary[]
  validation: ValidationResult
  findings: Finding[]
  securityGrade: 'A+' | 'A' | 'B' | 'C' | 'F' | 'Insufficient data'
  score?: number
  scoreExplanation: string
  isDemo?: boolean
}

export interface HistorySummary {
  id: string
  hostname: string
  resolvedIp: string
  timestamp: string
  status: string
  tlsVersion: string
  trustStatus: string
  securityGrade: string
  score?: number
  findingCount: number
  highSeverityCount: number
  warningCount: number
  isDemo?: boolean
}

export interface HealthResponse {
  status: string
  version: string
  timestamp: string
  uptimeSeconds: number
}
