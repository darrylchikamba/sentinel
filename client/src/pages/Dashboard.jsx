import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import api from '../api/axiosConfig';

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
};

const sectionLabelStyle = {
  color: colours.textMuted,
  fontSize: '11px',
  fontWeight: 500,
  letterSpacing: '0.1em',
  textTransform: 'uppercase',
};

const monoStyle = {
  fontFamily: "'JetBrains Mono', monospace",
  fontWeight: 400,
};

function formatCurrentDate() {
  return new Intl.DateTimeFormat('en-ZA', {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  }).format(new Date());
}

function formatDateTime(value) {
  if (!value) return '—';

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';

  const parts = new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).formatToParts(date);

  const lookup = Object.fromEntries(
    parts
      .filter(({ type }) => type !== 'literal')
      .map(({ type, value: partValue }) => [type, partValue]),
  );

  return `${lookup.day} ${lookup.month} ${lookup.year}, ${lookup.hour}:${lookup.minute}`;
}

function truncateFilename(filename, maxLength = 30) {
  if (!filename) return 'Untitled investigation';
  if (filename.length <= maxLength) return filename;
  return `${filename.slice(0, maxLength - 3)}...`;
}

function KpiCard({ label, value, valueColour, note }) {
  return (
    <div
      style={{
        flex: '1 1 0',
        minWidth: '180px',
        background: colours.card,
        border: `1px solid ${colours.border}`,
        borderRadius: 0,
        padding: '20px 24px',
      }}
    >
      <div style={sectionLabelStyle}>{label}</div>
      <div
        style={{
          ...monoStyle,
          marginTop: '10px',
          color: valueColour || colours.textPrimary,
          fontSize: '32px',
          lineHeight: 1.1,
        }}
      >
        {value}
      </div>
      {note && (
        <div
          style={{
            marginTop: '8px',
            color: colours.textMuted,
            fontSize: '11px',
            lineHeight: 1.4,
          }}
        >
          {note}
        </div>
      )}
    </div>
  );
}

export default function Dashboard() {
  const [investigations, setInvestigations] = useState([]);
  const [total, setTotal] = useState(0);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [investigationError, setInvestigationError] = useState(false);

  useEffect(() => {
    let active = true;

    async function loadDashboard() {
      setLoading(true);
      setInvestigationError(false);

      const [investigationResult, healthResult] = await Promise.allSettled([
        api.get('/api/investigations?page=1&page_size=5'),
        api.get('/api/health'),
      ]);

      if (!active) return;

      if (investigationResult.status === 'fulfilled') {
        setInvestigations(investigationResult.value.data?.investigations || []);
        setTotal(investigationResult.value.data?.total || 0);
      } else {
        setInvestigations([]);
        setTotal(0);
        setInvestigationError(true);
      }

      setHealth(
        healthResult.status === 'fulfilled' ? healthResult.value.data || null : null,
      );
      setLoading(false);
    }

    loadDashboard();

    return () => {
      active = false;
    };
  }, []);

  const recentTotals = useMemo(
    () =>
      investigations.reduce(
        (accumulator, investigation) => ({
          events: accumulator.events + Number(investigation.event_count || 0),
          highThreats:
            accumulator.highThreats + Number(investigation.high_threat_count || 0),
          attackClusters:
            accumulator.attackClusters + Number(investigation.attack_clusters || 0),
        }),
        { events: 0, highThreats: 0, attackClusters: 0 },
      ),
    [investigations],
  );

  return (
    <div style={{ minHeight: '100%', color: colours.textPrimary }}>
      <h1
        style={{
          margin: 0,
          color: colours.textPrimary,
          fontSize: '24px',
          fontWeight: 500,
          lineHeight: 1.25,
        }}
      >
        Dashboard
      </h1>

      <div
        style={{
          marginTop: '4px',
          color: colours.textMuted,
          fontSize: '13px',
        }}
      >
        {formatCurrentDate()}
      </div>

      <div
        style={{
          display: 'flex',
          gap: '16px',
          marginTop: '32px',
          flexWrap: 'wrap',
        }}
      >
        <KpiCard label="Total investigations" value={total} />
        <KpiCard label="Events processed" value={recentTotals.events} note="Recent 5 analyses" />
        <KpiCard
          label="High threats flagged"
          value={recentTotals.highThreats}
          valueColour={colours.critical}
          note="Recent 5 analyses"
        />
        <KpiCard
          label="Attack clusters"
          value={recentTotals.attackClusters}
          valueColour={colours.high}
          note="Recent 5 analyses"
        />
      </div>

      <div
        style={{
          marginTop: '32px',
          marginBottom: '12px',
          ...sectionLabelStyle,
        }}
      >
        Recent investigations
      </div>

      {loading ? (
        <div style={{ padding: '18px 0', color: colours.textMuted, fontSize: '13px' }}>
          Loading investigations...
        </div>
      ) : investigationError ? (
        <div
          style={{
            background: colours.card,
            border: `1px solid ${colours.border}`,
            borderRadius: 0,
            padding: '20px',
            color: colours.critical,
            fontSize: '13px',
          }}
        >
          Unable to load investigations.
        </div>
      ) : investigations.length === 0 ? (
        <div
          style={{
            background: colours.card,
            border: `1px solid ${colours.border}`,
            borderRadius: 0,
            padding: '20px',
            color: colours.textMuted,
            fontSize: '13px',
          }}
        >
          No investigations yet.{' '}
          <Link
            to="/upload"
            style={{ color: colours.accent, fontWeight: 500, textDecoration: 'none' }}
          >
            Upload a log file to begin.
          </Link>
        </div>
      ) : (
        <div
          style={{
            overflowX: 'auto',
            background: colours.card,
            border: `1px solid ${colours.border}`,
            borderRadius: 0,
          }}
        >
          <table style={{ width: '100%', borderCollapse: 'collapse', background: colours.card }}>
            <thead>
              <tr style={{ background: colours.surface }}>
                {['Filename', 'Date', 'Events', 'High threats', 'Status', 'Action'].map(
                  (heading, index) => (
                    <th
                      key={heading}
                      scope="col"
                      style={{
                        padding: '10px 16px',
                        borderBottom: `1px solid ${colours.border}`,
                        color: colours.textMuted,
                        fontSize: '11px',
                        fontWeight: 500,
                        letterSpacing: '0.1em',
                        textAlign: index === 2 || index === 3 ? 'right' : 'left',
                        textTransform: 'uppercase',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {heading}
                    </th>
                  ),
                )}
              </tr>
            </thead>

            <tbody>
              {investigations.map((investigation, index) => {
                const highThreatCount = Number(investigation.high_threat_count || 0);

                return (
                  <tr
                    key={investigation.investigation_id}
                    style={{ background: index % 2 === 1 ? colours.canvas : colours.card }}
                  >
                    <td
                      title={investigation.filename || ''}
                      style={{
                        padding: '12px 16px',
                        borderBottom: `1px solid ${colours.border}`,
                        color: colours.textPrimary,
                        fontSize: '14px',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {truncateFilename(investigation.filename)}
                    </td>
                    <td
                      style={{
                        ...monoStyle,
                        padding: '12px 16px',
                        borderBottom: `1px solid ${colours.border}`,
                        color: colours.textSecondary,
                        fontSize: '13px',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {formatDateTime(investigation.created_at)}
                    </td>
                    <td
                      style={{
                        ...monoStyle,
                        padding: '12px 16px',
                        borderBottom: `1px solid ${colours.border}`,
                        fontSize: '13px',
                        textAlign: 'right',
                      }}
                    >
                      {Number(investigation.event_count || 0)}
                    </td>
                    <td
                      style={{
                        ...monoStyle,
                        padding: '12px 16px',
                        borderBottom: `1px solid ${colours.border}`,
                        color: highThreatCount > 0 ? colours.critical : colours.textMuted,
                        fontSize: '13px',
                        textAlign: 'right',
                      }}
                    >
                      {highThreatCount}
                    </td>
                    <td
                      style={{
                        padding: '12px 16px',
                        borderBottom: `1px solid ${colours.border}`,
                      }}
                    >
                      <span
                        style={{
                          display: 'inline-block',
                          padding: '3px 8px',
                          background: colours.surface,
                          border: `1px solid ${colours.border}`,
                          borderRadius: 0,
                          color: colours.textSecondary,
                          fontSize: '11px',
                          fontWeight: 500,
                          textTransform: 'uppercase',
                        }}
                      >
                        Processed
                      </span>
                    </td>
                    <td
                      style={{
                        padding: '12px 16px',
                        borderBottom: `1px solid ${colours.border}`,
                      }}
                    >
                      <Link
                        to={`/analysis/${investigation.investigation_id}`}
                        style={{
                          color: colours.accent,
                          fontSize: '13px',
                          fontWeight: 500,
                          textDecoration: 'none',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        View
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ marginTop: '24px', color: colours.textMuted, fontSize: '12px' }}>
        {health ? (
          <>
            Intelligence layer: {health.generation_provider || 'unknown'} /{' '}
            {health.embedding_provider || 'unknown'}
          </>
        ) : (
          <>Intelligence layer: unavailable</>
        )}
      </div>
    </div>
  );
}