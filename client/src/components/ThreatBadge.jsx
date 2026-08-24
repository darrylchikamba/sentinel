const stylesByLevel = {
  Critical: { background: '#C0392B', color: '#FFFFFF' },
  High: { background: '#E05C2A', color: '#FFFFFF' },
  Medium: { background: '#D4A017', color: '#0E0E0E' },
  Low: { background: '#2E7D4F', color: '#FFFFFF' },
  None: { background: '#EAEAE5', color: '#8A8A8A' },
}

function normaliseLevel(level) {
  const candidate = String(level || '').trim().toLowerCase()
  if (candidate === 'critical') return 'Critical'
  if (candidate === 'high') return 'High'
  if (candidate === 'medium') return 'Medium'
  if (candidate === 'low') return 'Low'
  return 'None'
}

export default function ThreatBadge({ level }) {
  const normalisedLevel = normaliseLevel(level)
  const colours = stylesByLevel[normalisedLevel]

  return (
    <span
      style={{
        display: 'inline-block',
        padding: '3px 8px',
        border: 'none',
        borderRadius: 0,
        background: colours.background,
        color: colours.color,
        fontSize: '11px',
        fontWeight: 500,
        lineHeight: 1.3,
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {normalisedLevel}
    </span>
  )
}
