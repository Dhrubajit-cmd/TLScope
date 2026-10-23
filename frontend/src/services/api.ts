import type { AssessmentResult, HealthResponse, HistorySummary } from '../types'

// Local Vite requests stay same-origin and use vite.config.ts to proxy /api.
// Vercel injects VITE_API_BASE_URL at build time for the deployed Go backend.
const API_BASE = (import.meta.env.VITE_API_BASE_URL?.trim() || '/api').replace(/\/$/, '')

export async function checkHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE}/health`)
  if (!res.ok) {
    throw new Error(`Health check failed with status ${res.status}`)
  }
  return res.json()
}

export async function analyzeDomain(hostname: string): Promise<AssessmentResult> {
  let res: Response
  try {
    res = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ hostname }),
    })
  } catch (networkErr: any) {
    // Catches fetch-level failures: backend offline, DNS failure, CORS
    throw new Error(
      'Cannot reach the TLScope backend. Check your network connection and try again.'
    )
  }

  // Try to parse JSON regardless of status so we can extract the error message
  let data: any
  try {
    data = await res.json()
  } catch {
    // Response body is not JSON (e.g. a raw 502/504 from a proxy)
    throw new Error(
      `Server returned an unexpected response (HTTP ${res.status}). ` +
        'Please check the backend is running correctly.'
    )
  }

  if (!res.ok) {
    // Backend returned a structured error — surface the human-readable message
    const msg: string =
      data?.error || data?.message || `Assessment failed with status ${res.status}`
    throw new Error(msg)
  }

  return data as AssessmentResult
}


export async function getHistory(): Promise<HistorySummary[]> {
  const res = await fetch(`${API_BASE}/history`)
  if (!res.ok) {
    throw new Error(`Failed to fetch history (status ${res.status})`)
  }
  return res.json()
}

export async function getHistoryItem(id: string): Promise<AssessmentResult> {
  const res = await fetch(`${API_BASE}/history/${id}`)
  if (!res.ok) {
    throw new Error(`Assessment ${id} not found`)
  }
  return res.json()
}

export async function clearHistory(): Promise<void> {
  const res = await fetch(`${API_BASE}/history`, {
    method: 'DELETE',
  })
  if (!res.ok) {
    throw new Error(`Failed to clear history`)
  }
}

export async function getDemos(): Promise<AssessmentResult[]> {
  const res = await fetch(`${API_BASE}/demo`)
  if (!res.ok) {
    throw new Error(`Failed to load demo scenarios`)
  }
  return res.json()
}

export async function downloadReportHTML(assessment: AssessmentResult): Promise<void> {
  const res = await fetch(`${API_BASE}/report/html`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(assessment),
  })

  if (!res.ok) {
    throw new Error(`Failed to generate HTML report from server`)
  }

  const blob = await res.blob()
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `tlscope-report-${assessment.hostname.replace(/[^a-zA-Z0-9.-]/g, '_')}.html`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(url)
}

export function downloadReportJSON(assessment: AssessmentResult): void {
  const jsonStr = JSON.stringify(assessment, null, 2)
  const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' })
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `tlscope-assessment-${assessment.hostname.replace(/[^a-zA-Z0-9.-]/g, '_')}.json`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(url)
}
