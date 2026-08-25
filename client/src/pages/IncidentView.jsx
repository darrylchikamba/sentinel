import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Check,
  Clipboard,
  RefreshCw,
} from 'lucide-react'

import api from '../api/axiosConfig'

const colours = {
  canvas: '#F4F4F0',
  surface: '#EAEAE5',
  card: '#FFFFFF',
  border: '#D0D0C8',
  textPrimary: '#0E0E0E',
  textSecondary: '#4A4A4A',
  textMuted: '#8A8A8A',
  accent: '#1A1A2E',
  critical: '#C0392B',
  high: '#E05C2A',
  medium: '#D4A017',
  low: '#2E7D4F',
}

const monoStyle = {
  fontFamily: "'JetBrains Mono', monospace",
  fontWeight: 400,
}

const sectionLabelStyle = {
  color: colours.textMuted,
  fontSize: '11px',
  fontWeight: 500,
  letterSpacing: '0.1em',
  textTransform: 'uppercase',
}

function formatDateTime(value) {
  if (!value) {
    return '—'
  }

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return '—'
  }

  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date)
}

function getErrorMessage(error) {
  const status = error?.response?.status

  if (status === 404) {
    return 'Incident report not found.'
  }

  if (status === 422) {
    return 'Invalid investigation identifier.'
  }

  if (status === 429) {
    return 'Too many requests. Please wait before trying again.'
  }

  const detail = error?.response?.data?.detail

  if (typeof detail === 'string' && detail.trim()) {
    return detail
  }

  return 'Unable to load incident report.'
}

function getRegenerateError(error) {
  const status = error?.response?.status

  if (status === 429) {
    return 'Regeneration limit reached. Please try again later.'
  }

  if (status === 404) {
    return 'Investigation not found.'
  }

  if (status === 500) {
    return 'Incident report regeneration failed.'
  }

  const detail = error?.response?.data?.detail

  if (typeof detail === 'string' && detail.trim()) {
    return detail
  }

  return 'Unable to regenerate the incident report.'
}

function normaliseMitreTechnique(value) {
  const text = String(value || '').trim()

  const match = text.match(
    /^(T\d{4}(?:\.\d{3})?)\s*(?:\((.*)\))?$/,
  )

  if (!match) {
    return {
      id: '',
      name: text,
    }
  }

  return {
    id: match[1],
    name: match[2] || '',
  }
}

function readableFlag(flag) {
  return String(flag || '')
    .replaceAll('_', ' ')
    .replace(/\bPOPIA\b/g, 'POPIA')
    .replace(/\bSA\b/g, 'SA')
}

function buildPlainTextReport(report) {
  const lines = [
    'SENTINEL INCIDENT REPORT',
    '',
    `Investigation ID: ${report.investigation_id}`,
    `Created: ${formatDateTime(report.created_at)}`,
    `Events: ${report.event_count}`,
    `High threats: ${report.high_threat_count}`,
    `Attack clusters: ${report.attack_clusters}`,
    '',
    'SUSPICIOUS ACTIVITY SUMMARY',
    report.incident_summary || 'No summary available.',
    '',
    'RECOMMENDED NEXT STEPS',
  ]

  if (report.incident_next_steps?.length) {
    report.incident_next_steps.forEach(
      (step, index) => {
        lines.push(`${index + 1}. ${step}`)
      },
    )
  } else {
    lines.push('None recorded.')
  }

  lines.push('', 'MITRE ATT&CK TECHNIQUES')

  if (report.mitre_techniques?.length) {
    report.mitre_techniques.forEach((technique) => {
      lines.push(`- ${technique}`)
    })
  } else {
    lines.push('None recorded.')
  }

  lines.push('', 'SOUTH AFRICAN INTELLIGENCE')
  lines.push(
    `POPIA flags: ${
      report.popia_flags?.length
        ? report.popia_flags.join(', ')
        : 'None'
    }`,
  )
  lines.push(
    `Cybercrimes Act flags: ${
      report.cybercrimes_flags?.length
        ? report.cybercrimes_flags.join(', ')
        : 'None'
    }`,
  )
  lines.push(
    `SA patterns matched: ${
      report.sa_patterns_matched?.length
        ? report.sa_patterns_matched.join(', ')
        : 'None'
    }`,
  )

  lines.push('', 'RAG SOURCES')

  if (report.rag_sources_used?.length) {
    report.rag_sources_used.forEach((source) => {
      lines.push(`- ${source}`)
    })
  } else {
    lines.push('None recorded.')
  }

  return lines.join('\n')
}

function MetricCard({ label, value }) {
  return (
    <div
      style={{
        padding: '16px',
        background: colours.card,
        border: `1px solid ${colours.border}`,
        borderRadius: 0,
      }}
    >
      <div style={sectionLabelStyle}>{label}</div>

      <div
        style={{
          ...monoStyle,
          marginTop: '8px',
          color: colours.textPrimary,
          fontSize: '21px',
          lineHeight: 1.2,
        }}
      >
        {value}
      </div>
    </div>
  )
}

function EmptyText({ children }) {
  return (
    <div
      style={{
        color: colours.textMuted,
        fontSize: '13px',
      }}
    >
      {children}
    </div>
  )
}

export default function IncidentView() {
  const { investigationId } = useParams()
  const navigate = useNavigate()

  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [retryCount, setRetryCount] = useState(0)

  const [regenerating, setRegenerating] =
    useState(false)
  const [regenerateError, setRegenerateError] =
    useState('')

  const [copyState, setCopyState] =
    useState('idle')

  useEffect(() => {
    let active = true

    async function loadReport() {
      setLoading(true)
      setError('')

      try {
        const response = await api.get(
          `/api/incident/${investigationId}`,
        )

        if (!active) {
          return
        }

        setReport(response.data)
      } catch (requestError) {
        if (!active) {
          return
        }

        setReport(null)
        setError(getErrorMessage(requestError))
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    loadReport()

    return () => {
      active = false
    }
  }, [investigationId, retryCount])

  const mitreTechniques = useMemo(
    () =>
      (report?.mitre_techniques || []).map(
        normaliseMitreTechnique,
      ),
    [report],
  )

  const handleRegenerate = async () => {
    if (regenerating) {
      return
    }

    setRegenerating(true)
    setRegenerateError('')

    try {
      const response = await api.post(
        `/api/incident/${investigationId}/regenerate`,
      )

      setReport(response.data)
    } catch (requestError) {
      setRegenerateError(
        getRegenerateError(requestError),
      )
    } finally {
      setRegenerating(false)
    }
  }

  const handleCopy = async () => {
    if (!report || copyState === 'copying') {
      return
    }

    setCopyState('copying')

    try {
      const text = buildPlainTextReport(report)

      await navigator.clipboard.writeText(text)

      setCopyState('copied')

      window.setTimeout(() => {
        setCopyState('idle')
      }, 2000)
    } catch {
      setCopyState('error')

      window.setTimeout(() => {
        setCopyState('idle')
      }, 2500)
    }
  }

  if (loading) {
    return (
      <div
        style={{
          color: colours.textMuted,
          fontSize: '13px',
        }}
      >
        Loading incident report...
      </div>
    )
  }

  if (error || !report) {
    return (
      <div
        style={{
          padding: '24px',
          background: colours.card,
          border: `1px solid ${colours.border}`,
          borderRadius: 0,
        }}
      >
        <div
          style={{
            ...sectionLabelStyle,
            marginBottom: '12px',
          }}
        >
          Incident report
        </div>

        <div
          style={{
            marginBottom: '18px',
            color: colours.critical,
            fontSize: '13px',
          }}
        >
          {error || 'Incident report unavailable.'}
        </div>

        <button
          type="button"
          onClick={() =>
            setRetryCount((value) => value + 1)
          }
          style={{
            padding: '10px 16px',
            background: colours.accent,
            border: 'none',
            borderRadius: 0,
            color: '#FFFFFF',
            cursor: 'pointer',
            fontFamily: "'Inter', sans-serif",
            fontSize: '12px',
            fontWeight: 500,
          }}
        >
          Retry
        </button>
      </div>
    )
  }

  return (
    <div
      style={{
        width: '100%',
        color: colours.textPrimary,
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: '24px',
          marginBottom: '28px',
          flexWrap: 'wrap',
        }}
      >
        <div>
          <button
            type="button"
            onClick={() =>
              navigate(`/analysis/${investigationId}`)
            }
            style={{
              margin: '0 0 12px 0',
              padding: 0,
              background: 'transparent',
              border: 'none',
              borderRadius: 0,
              color: colours.textMuted,
              cursor: 'pointer',
              fontFamily: "'Inter', sans-serif",
              fontSize: '12px',
              fontWeight: 400,
            }}
          >
            ← Back to analysis
          </button>

          <h1
            style={{
              margin: 0,
              color: colours.textPrimary,
              fontSize: '24px',
              fontWeight: 500,
              lineHeight: 1.25,
            }}
          >
            Incident Report
          </h1>

          <div
            style={{
              marginTop: '6px',
              color: colours.textMuted,
              fontSize: '12px',
            }}
          >
            BONA-generated cyber incident assessment ·{' '}
            {formatDateTime(report.created_at)}
          </div>
        </div>

        <div
          style={{
            display: 'flex',
            gap: '8px',
            flexWrap: 'wrap',
          }}
        >
          <button
            type="button"
            onClick={handleCopy}
            disabled={copyState === 'copying'}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '7px',
              padding: '10px 14px',
              background: colours.card,
              border: `1px solid ${colours.border}`,
              borderRadius: 0,
              color: colours.textSecondary,
              cursor:
                copyState === 'copying'
                  ? 'wait'
                  : 'pointer',
              fontFamily: "'Inter', sans-serif",
              fontSize: '12px',
              fontWeight: 500,
            }}
          >
            {copyState === 'copied' ? (
              <Check size={14} />
            ) : (
              <Clipboard size={14} />
            )}

            {copyState === 'copied'
              ? 'Copied'
              : copyState === 'copying'
                ? 'Copying...'
                : 'Copy Report'}
          </button>

          <button
            type="button"
            onClick={handleRegenerate}
            disabled={regenerating}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '7px',
              padding: '10px 14px',
              background: colours.accent,
              border: 'none',
              borderRadius: 0,
              color: '#FFFFFF',
              cursor: regenerating
                ? 'wait'
                : 'pointer',
              fontFamily: "'Inter', sans-serif",
              fontSize: '12px',
              fontWeight: 500,
              opacity: regenerating ? 0.7 : 1,
            }}
          >
            <RefreshCw size={14} />

            {regenerating
              ? 'Regenerating...'
              : 'Regenerate Report'}
          </button>
        </div>
      </div>

      {(copyState === 'error' ||
        regenerateError) && (
        <div
          style={{
            marginBottom: '18px',
            padding: '11px 14px',
            background: colours.card,
            border: `1px solid ${colours.critical}`,
            borderRadius: 0,
            color: colours.critical,
            fontSize: '12px',
          }}
        >
          {regenerateError ||
            'Could not copy the report to the clipboard.'}
        </div>
      )}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns:
            'repeat(3, minmax(0, 1fr))',
          gap: '12px',
          marginBottom: '20px',
        }}
      >
        <MetricCard
          label="Events analysed"
          value={report.event_count ?? 0}
        />

        <MetricCard
          label="High threats"
          value={report.high_threat_count ?? 0}
        />

        <MetricCard
          label="Attack clusters"
          value={report.attack_clusters ?? 0}
        />
      </div>

      <section
        style={{
          marginBottom: '16px',
          padding: '22px',
          background: colours.card,
          border: `1px solid ${colours.border}`,
          borderRadius: 0,
        }}
      >
        <div
          style={{
            ...sectionLabelStyle,
            marginBottom: '14px',
          }}
        >
          Suspicious activity summary
        </div>

        <div
          style={{
            color: colours.textPrimary,
            fontSize: '14px',
            lineHeight: 1.75,
            whiteSpace: 'pre-line',
          }}
        >
          {report.incident_summary ||
            'No incident summary available.'}
        </div>
      </section>

      <section
        style={{
          marginBottom: '16px',
          padding: '22px',
          background: colours.card,
          border: `1px solid ${colours.border}`,
          borderRadius: 0,
        }}
      >
        <div
          style={{
            ...sectionLabelStyle,
            marginBottom: '14px',
          }}
        >
          Recommended next steps
        </div>

        {report.incident_next_steps?.length ? (
          <div>
            {report.incident_next_steps.map(
              (step, index) => (
                <div
                  key={`${step}-${index}`}
                  style={{
                    display: 'grid',
                    gridTemplateColumns:
                      '32px minmax(0, 1fr)',
                    gap: '10px',
                    padding: '12px 0',
                    borderTop:
                      index === 0
                        ? 'none'
                        : `1px solid ${colours.border}`,
                  }}
                >
                  <div
                    style={{
                      ...monoStyle,
                      color: colours.textMuted,
                      fontSize: '12px',
                    }}
                  >
                    {String(index + 1).padStart(
                      2,
                      '0',
                    )}
                  </div>

                  <div
                    style={{
                      color: colours.textPrimary,
                      fontSize: '13px',
                      lineHeight: 1.6,
                    }}
                  >
                    {step}
                  </div>
                </div>
              ),
            )}
          </div>
        ) : (
          <EmptyText>
            No recommended actions recorded.
          </EmptyText>
        )}
      </section>

      <section
        style={{
          marginBottom: '16px',
          padding: '22px',
          background: colours.card,
          border: `1px solid ${colours.border}`,
          borderRadius: 0,
        }}
      >
        <div
          style={{
            ...sectionLabelStyle,
            marginBottom: '14px',
          }}
        >
          MITRE ATT&CK techniques
        </div>

        {mitreTechniques.length > 0 ? (
          <div
            style={{
              display: 'grid',
              gridTemplateColumns:
                'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '8px',
            }}
          >
            {mitreTechniques.map(
              (technique, index) => (
                <div
                  key={`${technique.id}-${technique.name}-${index}`}
                  style={{
                    padding: '13px',
                    background: colours.canvas,
                    border: `1px solid ${colours.border}`,
                    borderRadius: 0,
                  }}
                >
                  {technique.id && (
                    <div
                      style={{
                        ...monoStyle,
                        marginBottom: '5px',
                        color: colours.accent,
                        fontSize: '12px',
                        fontWeight: 500,
                      }}
                    >
                      {technique.id}
                    </div>
                  )}

                  <div
                    style={{
                      color: colours.textSecondary,
                      fontSize: '12px',
                      lineHeight: 1.5,
                    }}
                  >
                    {technique.name ||
                      'Technique identified'}
                  </div>
                </div>
              ),
            )}
          </div>
        ) : (
          <EmptyText>
            No grounded MITRE ATT&CK techniques
            recorded.
          </EmptyText>
        )}
      </section>

      <section
        style={{
          marginBottom: '16px',
          padding: '22px',
          background: colours.card,
          border: `1px solid ${colours.border}`,
          borderRadius: 0,
        }}
      >
        <div
          style={{
            ...sectionLabelStyle,
            marginBottom: '14px',
          }}
        >
          South African intelligence
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns:
              'repeat(3, minmax(0, 1fr))',
            gap: '12px',
          }}
        >
          <div
            style={{
              padding: '14px',
              background: colours.canvas,
              border: `1px solid ${colours.border}`,
              borderRadius: 0,
            }}
          >
            <div
              style={{
                ...sectionLabelStyle,
                marginBottom: '10px',
              }}
            >
              POPIA
            </div>

            {report.popia_flags?.length ? (
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                }}
              >
                {report.popia_flags.map((flag) => (
                  <div
                    key={flag}
                    style={{
                      color: colours.textSecondary,
                      fontSize: '12px',
                      lineHeight: 1.5,
                    }}
                  >
                    {readableFlag(flag)}
                  </div>
                ))}
              </div>
            ) : (
              <EmptyText>No flags</EmptyText>
            )}
          </div>

          <div
            style={{
              padding: '14px',
              background: colours.canvas,
              border: `1px solid ${colours.border}`,
              borderRadius: 0,
            }}
          >
            <div
              style={{
                ...sectionLabelStyle,
                marginBottom: '10px',
              }}
            >
              Cybercrimes Act
            </div>

            {report.cybercrimes_flags?.length ? (
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                }}
              >
                {report.cybercrimes_flags.map(
                  (flag) => (
                    <div
                      key={flag}
                      style={{
                        color:
                          colours.textSecondary,
                        fontSize: '12px',
                        lineHeight: 1.5,
                      }}
                    >
                      {readableFlag(flag)}
                    </div>
                  ),
                )}
              </div>
            ) : (
              <EmptyText>
                No reportable flags
              </EmptyText>
            )}
          </div>

          <div
            style={{
              padding: '14px',
              background: colours.canvas,
              border: `1px solid ${colours.border}`,
              borderRadius: 0,
            }}
          >
            <div
              style={{
                ...sectionLabelStyle,
                marginBottom: '10px',
              }}
            >
              SA threat patterns
            </div>

            {report.sa_patterns_matched?.length ? (
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                }}
              >
                {report.sa_patterns_matched.map(
                  (pattern) => (
                    <div
                      key={pattern}
                      style={{
                        color:
                          colours.textSecondary,
                        fontSize: '12px',
                        lineHeight: 1.5,
                      }}
                    >
                      {readableFlag(pattern)}
                    </div>
                  ),
                )}
              </div>
            ) : (
              <EmptyText>
                No SA-specific patterns
              </EmptyText>
            )}
          </div>
        </div>
      </section>

      <section
        style={{
          marginBottom: '16px',
          padding: '22px',
          background: colours.card,
          border: `1px solid ${colours.border}`,
          borderRadius: 0,
        }}
      >
        <div
          style={{
            ...sectionLabelStyle,
            marginBottom: '14px',
          }}
        >
          Grounding sources
        </div>

        {report.rag_sources_used?.length ? (
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '7px',
            }}
          >
            {report.rag_sources_used.map(
              (source, index) => (
                <span
                  key={`${source}-${index}`}
                  style={{
                    padding: '5px 8px',
                    background: colours.canvas,
                    border: `1px solid ${colours.border}`,
                    borderRadius: 0,
                    color: colours.textSecondary,
                    fontSize: '11px',
                  }}
                >
                  {source}
                </span>
              ),
            )}
          </div>
        ) : (
          <EmptyText>
            No RAG sources were recorded for this
            report.
          </EmptyText>
        )}
      </section>

      <section
        style={{
          padding: '18px 22px',
          background: colours.surface,
          border: `1px solid ${colours.border}`,
          borderRadius: 0,
        }}
      >
        <div
          style={{
            ...sectionLabelStyle,
            marginBottom: '12px',
          }}
        >
          Analysis metadata
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns:
              'repeat(2, minmax(0, 1fr))',
            columnGap: '30px',
          }}
        >
          <div
            style={{
              padding: '9px 0',
              borderTop: `1px solid ${colours.border}`,
            }}
          >
            <div
              style={{
                marginBottom: '4px',
                color: colours.textMuted,
                fontSize: '11px',
              }}
            >
              Investigation ID
            </div>

            <div
              style={{
                ...monoStyle,
                color: colours.textSecondary,
                fontSize: '11px',
                overflowWrap: 'anywhere',
              }}
            >
              {report.investigation_id}
            </div>
          </div>

          <div
            style={{
              padding: '9px 0',
              borderTop: `1px solid ${colours.border}`,
            }}
          >
            <div
              style={{
                marginBottom: '4px',
                color: colours.textMuted,
                fontSize: '11px',
              }}
            >
              Investigation created
            </div>

            <div
              style={{
                ...monoStyle,
                color: colours.textSecondary,
                fontSize: '11px',
              }}
            >
              {formatDateTime(report.created_at)}
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}