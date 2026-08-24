import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import api from '../api/axiosConfig'
import ThreatBadge from '../components/ThreatBadge'

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
  none: '#8A8A8A',
}

const colourByLevel = {
  Critical: colours.critical,
  High: colours.high,
  Medium: colours.medium,
  Low: colours.low,
  None: colours.none,
}

function normaliseLevel(level) {
  const candidate = String(level || '').trim().toLowerCase()
  if (candidate === 'critical') return 'Critical'
  if (candidate === 'high') return 'High'
  if (candidate === 'medium') return 'Medium'
  if (candidate === 'low') return 'Low'
  return 'None'
}

function formatDateTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'

  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date)
}

function getDistributionValue(distribution, key) {
  return Number(distribution?.[key] || distribution?.[key.toLowerCase()] || 0)
}

export default function Analysis() {
  const { investigationId } = useParams()
  const [investigation, setInvestigation] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('ALL')

  useEffect(() => {
    let active = true

    async function loadInvestigation() {
      setLoading(true)
      setError('')

      try {
        const response = await api.get(`/api/investigations/${investigationId}`)
        if (active) setInvestigation(response.data)
      } catch (requestError) {
        if (!active) return

        if (
          requestError?.response?.status === 404 ||
          requestError?.response?.status === 422
        ) {
          setError('Investigation not found or access denied.')
        } else {
          setError('Unable to load investigation.')
        }
      } finally {
        if (active) setLoading(false)
      }
    }

    loadInvestigation()

    return () => {
      active = false
    }
  }, [investigationId])

  const events = investigation?.events || []

  const filteredEvents = useMemo(() => {
    if (filter === 'ALL') return events
    return events.filter(
      (event) => normaliseLevel(event.threat_level).toUpperCase() === filter,
    )
  }, [events, filter])

  if (loading) {
    return <div style={{ color: colours.textMuted, fontSize: '13px' }}>Loading investigation...</div>
  }

  if (error || !investigation) {
    return <div style={{ color: colours.critical, fontSize: '13px' }}>{error || 'Investigation not found or access denied.'}</div>
  }

  const distribution = investigation.threat_distribution || {}
  const distributionItems = [
    ['Critical', getDistributionValue(distribution, 'critical')],
    ['High', getDistributionValue(distribution, 'high')],
    ['Medium', getDistributionValue(distribution, 'medium')],
    ['Low', getDistributionValue(distribution, 'low')],
    ['None', getDistributionValue(distribution, 'none')],
  ]
  const distributionTotal = distributionItems.reduce((sum, [, count]) => sum + count, 0)

  return (
    <div style={{ color: colours.textPrimary }}>
      <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 500, lineHeight: 1.25 }}>
        Analysis — {investigation.filename}
      </h1>

      <div style={{ marginTop: '4px', color: colours.textMuted, fontSize: '13px' }}>
        {investigation.event_count} events · {investigation.anomaly_count} flagged · Analysed {formatDateTime(investigation.created_at)}
      </div>

      <div style={{ marginTop: '32px' }}>
        <div style={{ display: 'flex', width: '100%', height: '12px', overflow: 'hidden', background: colours.surface, border: `1px solid ${colours.border}`, borderRadius: 0 }}>
          {distributionItems.map(([level, count]) => (
            <div
              key={level}
              style={{
                width: distributionTotal > 0 ? `${(count / distributionTotal) * 100}%` : '0%',
                background: colourByLevel[level],
              }}
            />
          ))}
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', marginTop: '10px' }}>
          {distributionItems.map(([level, count]) => (
            <div key={level} style={{ display: 'flex', alignItems: 'center', gap: '6px', color: colours.textSecondary, fontSize: '12px' }}>
              <span style={{ width: '8px', height: '8px', background: colourByLevel[level], borderRadius: 0 }} />
              <span>{level === 'None' ? 'Unscored' : level}</span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", color: colours.textMuted }}>({count})</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: '8px', marginTop: '20px', flexWrap: 'wrap' }}>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((value) => {
          const active = filter === value
          return (
            <button
              key={value}
              type="button"
              onClick={() => setFilter(value)}
              style={{ padding: '7px 10px', background: active ? colours.accent : colours.card, border: `1px solid ${active ? colours.accent : colours.border}`, borderRadius: 0, color: active ? '#FFFFFF' : colours.textSecondary, cursor: 'pointer', fontSize: '11px', fontWeight: 500 }}
            >
              {value}
            </button>
          )
        })}
      </div>

      <div style={{ marginTop: '16px', overflowX: 'auto', background: colours.card, border: `1px solid ${colours.border}`, borderRadius: 0 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: colours.surface }}>
              {['Event ID', 'Timestamp', 'Source IP', 'Dest IP', 'Event type', 'Threat score', 'Level', 'Signals'].map((heading, index) => (
                <th key={heading} style={{ padding: '10px 12px', borderBottom: `1px solid ${colours.border}`, color: colours.textMuted, fontSize: '11px', fontWeight: 500, letterSpacing: '0.08em', textAlign: index === 5 ? 'right' : 'left', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                  {heading}
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {filteredEvents.map((event, index) => {
              const level = normaliseLevel(event.threat_level)
              const signals = Array.isArray(event.threat_signals) ? event.threat_signals : []
              const eventId = event.event_id || event.transaction_id || `EVT-${String(index + 1).padStart(4, '0')}`

              return (
                <tr key={`${eventId}-${index}`} style={{ background: index % 2 === 1 ? colours.canvas : colours.card }}>
                  <td style={{ padding: '12px', borderBottom: `1px solid ${colours.border}`, color: colours.textMuted, fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', whiteSpace: 'nowrap' }}>{eventId}</td>
                  <td style={{ padding: '12px', borderBottom: `1px solid ${colours.border}`, color: colours.textSecondary, fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', whiteSpace: 'nowrap' }}>{formatDateTime(event.timestamp)}</td>
                  <td style={{ padding: '12px', borderBottom: `1px solid ${colours.border}`, fontFamily: "'JetBrains Mono', monospace", fontSize: '13px', whiteSpace: 'nowrap' }}>{event.src_ip || '—'}</td>
                  <td style={{ padding: '12px', borderBottom: `1px solid ${colours.border}`, fontFamily: "'JetBrains Mono', monospace", fontSize: '13px', whiteSpace: 'nowrap' }}>{event.dst_ip || '—'}</td>
                  <td style={{ padding: '12px', borderBottom: `1px solid ${colours.border}`, fontSize: '13px' }}>{event.event_type || '—'}</td>
                  <td style={{ padding: '12px', borderBottom: `1px solid ${colours.border}`, color: colourByLevel[level], fontFamily: "'JetBrains Mono', monospace", fontSize: '13px', textAlign: 'right' }}>{Number(event.threat_score || 0)}</td>
                  <td style={{ padding: '12px', borderBottom: `1px solid ${colours.border}` }}><ThreatBadge level={level} /></td>
                  <td style={{ padding: '12px', borderBottom: `1px solid ${colours.border}` }}>
                    {signals.length > 0 ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {signals.map((signal, signalIndex) => (
                          <span key={`${signal}-${signalIndex}`} style={{ padding: '2px 6px', border: `1px solid ${colours.border}`, borderRadius: 0, color: colours.textSecondary, fontSize: '10px' }}>{signal}</span>
                        ))}
                      </div>
                    ) : (
                      <span style={{ color: colours.textMuted, fontSize: '12px' }}>—</span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {filteredEvents.length === 0 && (
        <div style={{ padding: '16px', color: colours.textMuted, fontSize: '13px' }}>No events match this filter.</div>
      )}

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '20px', marginTop: '24px' }}>
        <Link to={`/graph/${investigationId}`} style={{ color: colours.accent, fontSize: '13px', fontWeight: 500, textDecoration: 'none' }}>View Attack Graph →</Link>
        <Link to={`/incident/${investigationId}`} style={{ color: colours.accent, fontSize: '13px', fontWeight: 500, textDecoration: 'none' }}>View Incident Report →</Link>
      </div>
    </div>
  )
}
