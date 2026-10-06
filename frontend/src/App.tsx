import { useEffect, useState } from 'react'
import './App.css'
import ReactMarkdown from 'react-markdown'

type Indicator = {
  type?: string
  value?: string
  reputation?: string
  confidence?: number
  context?: string
}

type TimelineEvent = {
  event_id?: number
  timestamp?: string
  action?: string
  description?: string
  username?: string
  hostname?: string
  source_ip?: string
}

type MitreMapping = {
  technique_id?: string
  technique_name?: string
  tactic?: string
  confidence?: string
  reason?: string
}

type Incident = {
  incident_id: number
  username?: string
  hostname?: string
  source_ip?: string
  severity?: string
  risk_score?: number
  risk_level?: string
  risk_reasons?: string[]
  indicators?: Indicator[]
  timeline?: TimelineEvent[]
  mitre_attack?: MitreMapping[]
}

type AIInvestigation = {
  incident_id?: number
  summary?: string
  generation_mode?: string
  evidence_event_count?: number
  indicator_count?: number
}

function App() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [selectedIncident, setSelectedIncident] =
    useState<Incident | null>(null)

  const [detailsLoading, setDetailsLoading] = useState(false)

  const [aiInvestigation, setAiInvestigation] =
    useState<AIInvestigation | null>(null)

  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState('')

  useEffect(() => {
    fetch('http://127.0.0.1:8000/incidents')
      .then((response) => {
        if (!response.ok) {
          throw new Error('Failed to load incidents')
        }

        return response.json()
      })
      .then((data) => {
        if (Array.isArray(data)) {
          setIncidents(data)
        } else if (Array.isArray(data.incidents)) {
          setIncidents(data.incidents)
        } else {
          setIncidents([])
        }

        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [])

  const selectIncident = (incidentId: number) => {
    setDetailsLoading(true)
    setSelectedIncident(null)
    setAiInvestigation(null)
    setAiError('')

    fetch(`http://127.0.0.1:8000/incidents/${incidentId}`)
      .then((response) => {
        if (!response.ok) {
          throw new Error('Failed to load incident details')
        }

        return response.json()
      })
      .then((data) => {
        setSelectedIncident(data)
        setDetailsLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setDetailsLoading(false)
      })
  }

  const generateAIInvestigation = async () => {
    if (!selectedIncident) {
      return
    }

    setAiLoading(true)
    setAiError('')
    setAiInvestigation(null)

    try {
      const response = await fetch(
        `http://127.0.0.1:8000/investigations?incident_id=${selectedIncident.incident_id}`,
        {
          method: 'POST',
        }
      )

      if (!response.ok) {
        throw new Error('Failed to generate AI investigation')
      }

      const data = await response.json()

      if (data.status !== 'success') {
        throw new Error(
          data.message ?? 'AI investigation request failed'
        )
      }

      setAiInvestigation(data.investigation)
    } catch (err) {
      if (err instanceof Error) {
        setAiError(err.message)
      } else {
        setAiError('Unknown AI investigation error')
      }
    } finally {
      setAiLoading(false)
    }
  }

  const highRiskCount = incidents.filter(
    (incident) => (incident.risk_score ?? 0) >= 70
  ).length

  const indicatorCount = incidents.reduce(
    (total, incident) => total + (incident.indicators?.length ?? 0),
    0
  )

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>Cyber Incident Investigation Platform</h1>
          <p>Automated Detection, Correlation & Investigation</p>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          System Online
        </div>
      </header>

      <main className="dashboard">
        <section className="summary-grid">
          <div className="summary-card">
            <span>Total Incidents</span>
            <strong>{incidents.length}</strong>
          </div>

          <div className="summary-card">
            <span>High Risk</span>
            <strong>{highRiskCount}</strong>
          </div>

          <div className="summary-card">
            <span>Indicators</span>
            <strong>{indicatorCount}</strong>
          </div>

          <div className="summary-card">
            <span>Investigation Engine</span>
            <strong>Active</strong>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Security Incidents</h2>
              <p>
                Correlated incidents generated by the investigation engine.
              </p>
            </div>
          </div>

          {loading && (
            <div className="placeholder">Loading incidents...</div>
          )}

          {error && (
            <div className="placeholder">
              Backend error: {error}
            </div>
          )}

          {!loading && !error && incidents.length === 0 && (
            <div className="placeholder">No incidents found.</div>
          )}

          {!loading && !error && incidents.length > 0 && (
            <div className="incident-list">
              {incidents.map((incident) => (
                <div
                  className="incident-card"
                  key={incident.incident_id}
                  onClick={() => selectIncident(incident.incident_id)}
                >
                  <div>
                    <h3>Incident #{incident.incident_id}</h3>

                    <p>
                      <strong>User:</strong>{' '}
                      {incident.username ?? 'Unknown'}
                    </p>

                    <p>
                      <strong>Host:</strong>{' '}
                      {incident.hostname ?? 'Unknown'}
                    </p>

                    <p>
                      <strong>Source IP:</strong>{' '}
                      {incident.source_ip ?? 'Unknown'}
                    </p>
                  </div>

                  <div className="incident-risk">
                    <span>{incident.risk_level ?? 'Unknown'}</span>
                    <strong>{incident.risk_score ?? 0}</strong>
                    <small>Risk Score</small>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {detailsLoading && (
          <section className="panel incident-details">
            <div className="placeholder">
              Loading incident investigation...
            </div>
          </section>
        )}

        {selectedIncident && !detailsLoading && (
          <section className="panel incident-details">
            <div className="panel-heading">
              <div>
                <h2>
                  Incident #{selectedIncident.incident_id} Investigation
                </h2>

                <p>
                  {selectedIncident.username ?? 'Unknown'} ·{' '}
                  {selectedIncident.hostname ?? 'Unknown'} ·{' '}
                  {selectedIncident.source_ip ?? 'Unknown'}
                </p>
              </div>

              <button
                className="close-button"
                onClick={() => {
                  setSelectedIncident(null)
                  setAiInvestigation(null)
                  setAiError('')
                }}
              >
                Close
              </button>
            </div>

            <div className="details-content">
              <div className="ai-actions">
                <button
                  className="ai-button"
                  onClick={generateAIInvestigation}
                  disabled={aiLoading}
                >
                  {aiLoading
                    ? 'Generating Investigation...'
                    : 'Generate AI Investigation'}
                </button>
              </div>

              {aiError && (
                <div className="ai-error">
                  {aiError}
                </div>
              )}

              {aiInvestigation && (
                <div className="ai-report">
                  <h3>AI Investigation Summary</h3>

                  <div className="ai-markdown">
                    <ReactMarkdown>
                      {aiInvestigation.summary ?? ''}
                    </ReactMarkdown>
                  </div>

                  <div className="ai-meta">
                    <span>
                      Evidence Events:{' '}
                      {aiInvestigation.evidence_event_count ?? 0}
                    </span>

                    <span>
                      Indicators:{' '}
                      {aiInvestigation.indicator_count ?? 0}
                    </span>

                    <span>
                      Mode:{' '}
                      {aiInvestigation.generation_mode ?? 'Unknown'}
                    </span>
                  </div>
                </div>
              )}

              <h3>Risk Assessment</h3>

              <p>
                <strong>Risk Score:</strong>{' '}
                {selectedIncident.risk_score ?? 0}
              </p>

              <p>
                <strong>Risk Level:</strong>{' '}
                {selectedIncident.risk_level ?? 'Unknown'}
              </p>

              <h3>Risk Reasons</h3>

              <ul>
                {(selectedIncident.risk_reasons ?? []).map(
                  (reason, index) => (
                    <li key={index}>{reason}</li>
                  )
                )}
              </ul>

              <h3>Indicators</h3>

              {(selectedIncident.indicators ?? []).map(
                (indicator, index) => (
                  <div key={index}>
                    <p>
                      <strong>{indicator.type}</strong>:{' '}
                      {indicator.value}
                    </p>

                    <p>
                      Reputation:{' '}
                      {indicator.reputation ?? 'Unknown'}
                    </p>

                    <p>
                      Confidence:{' '}
                      {indicator.confidence ?? 0}
                    </p>

                    {indicator.context && (
                      <p>
                        Context: {indicator.context}
                      </p>
                    )}
                  </div>
                )
              )}

              <h3>MITRE ATT&CK</h3>

              {(selectedIncident.mitre_attack ?? []).map(
                (mapping, index) => (
                  <div key={index}>
                    <p>
                      <strong>
                        {mapping.technique_id} —{' '}
                        {mapping.technique_name}
                      </strong>
                    </p>

                    <p>
                      Tactic: {mapping.tactic}
                    </p>

                    <p>
                      Confidence: {mapping.confidence}
                    </p>

                    <p>{mapping.reason}</p>
                  </div>
                )
              )}

              <h3>Timeline</h3>

              {(selectedIncident.timeline ?? []).map(
                (event, index) => (
                  <div key={index}>
                    <p>
                      <strong>
                        {event.timestamp ?? 'Unknown time'}
                      </strong>
                    </p>

                    <p>
                      {event.action ?? 'Unknown action'}
                    </p>

                    <p>{event.description ?? ''}</p>
                  </div>
                )
              )}
            </div>
          </section>
        )}
      </main>
    </div>
  )
}

export default App