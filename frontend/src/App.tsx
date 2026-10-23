import React, { useState, useEffect } from 'react'
import { Navbar } from './components/Navbar'
import { OverviewView } from './components/OverviewView'
import { AnalyzeView } from './components/AnalyzeView'
import { DemoView } from './components/DemoView'
import { HistoryView } from './components/HistoryView'
import { ReportView } from './components/ReportView'
import { AboutView } from './components/AboutView'
import type { AssessmentResult, HealthResponse, HistorySummary } from './types'
import { checkHealth, getHistory, getDemos, analyzeDomain, getHistoryItem } from './services/api'

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('overview')
  const [currentAssessment, setCurrentAssessment] = useState<AssessmentResult | null>(null)
  const [history, setHistory] = useState<HistorySummary[]>([])
  const [demos, setDemos] = useState<AssessmentResult[]>([])
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthLoading, setHealthLoading] = useState<boolean>(true)
  const [scanLoading, setScanLoading] = useState<boolean>(false)
  const [scanError, setScanError] = useState<string | null>(null)

  // Initialize initial data from API
  useEffect(() => {
    const init = async () => {
      try {
        setHealthLoading(true)
        const h = await checkHealth()
        setHealth(h)
      } catch (err) {
        console.warn('Backend health check error:', err)
      } finally {
        setHealthLoading(false)
      }

      try {
        const hist = await getHistory()
        setHistory(hist)
      } catch (err) {
        console.warn('Failed to load initial history:', err)
      }

      try {
        const d = await getDemos()
        setDemos(d)
        // If no scan has been done, default current assessment to first demo for demonstration preview
        if (d.length > 0) {
          setCurrentAssessment(d[0])
        }
      } catch (err) {
        console.warn('Failed to load demo fixtures:', err)
      }
    }

    init()
  }, [])

  const handleAnalyze = async (hostname: string) => {
    setScanLoading(true)
    setScanError(null)
    setActiveTab('analyze')

    try {
      const result = await analyzeDomain(hostname)
      setCurrentAssessment(result)
      setScanError(null)
      // Refresh history
      try {
        const updatedHistory = await getHistory()
        setHistory(updatedHistory)
      } catch {
        // History refresh failure is non-critical
      }
    } catch (err: any) {
      // Clear stale result so the error banner is shown alone
      setCurrentAssessment(null)
      setScanError(err.message || 'An unexpected error occurred during the assessment.')
    } finally {
      setScanLoading(false)
    }
  }


  const handleSelectAssessment = (assessment: AssessmentResult) => {
    setCurrentAssessment(assessment)
    setScanError(null)
    setActiveTab('analyze')
  }

  const handleSelectHistoryItem = async (id: string) => {
    try {
      const item = await getHistoryItem(id)
      setCurrentAssessment(item)
      setScanError(null)
      setActiveTab('analyze')
    } catch (err: any) {
      setScanError(err.message || 'Failed to retrieve assessment details.')
    }
  }

  return (
    <div className="app-container">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        health={health}
        healthLoading={healthLoading}
      />

      <main className="main-content">
        {activeTab === 'overview' && (
          <OverviewView
            onAnalyze={handleAnalyze}
            onSelectAssessment={handleSelectAssessment}
            onOpenTab={setActiveTab}
            history={history}
            demos={demos}
          />
        )}

        {activeTab === 'analyze' && (
          <AnalyzeView
            currentAssessment={currentAssessment}
            loading={scanLoading}
            error={scanError}
            onAnalyze={handleAnalyze}
            onOpenReport={() => setActiveTab('report')}
          />
        )}

        {activeTab === 'demo' && (
          <DemoView
            demos={demos}
            onSelectDemo={handleSelectAssessment}
          />
        )}

        {activeTab === 'history' && (
          <HistoryView
            history={history}
            onSelectHistoryItem={handleSelectHistoryItem}
            onClearHistory={() => setHistory([])}
            onOpenAnalyze={() => setActiveTab('analyze')}
          />
        )}

        {activeTab === 'report' && (
          <ReportView
            currentAssessment={currentAssessment}
            onOpenAnalyze={() => setActiveTab('analyze')}
          />
        )}

        {activeTab === 'about' && (
          <AboutView />
        )}
      </main>

      <footer className="footer">
        <div>
          <strong>TLScope</strong> — Cloud & Network Security Course Mini Project
        </div>
        <div style={{ marginTop: '4px', fontSize: '11.5px', color: 'var(--text-subtle)' }}>
          Developed with Go, React, TypeScript, and Crypto Standard Libraries. Restricted to passive port 443 assessment.
        </div>
      </footer>
    </div>
  )
}

export default App
