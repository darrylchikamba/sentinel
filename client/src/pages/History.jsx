import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  Search,
  Trash2,
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

const sortOptions = [
  {
    value: 'created_at',
    label: 'Upload date',
  },
  {
    value: 'high_threat_count',
    label: 'High threats',
  },
  {
    value: 'event_count',
    label: 'Events',
  },
  {
    value: 'attack_clusters',
    label: 'Attack clusters',
  },
]

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

function getFetchError(error) {
  if (error?.response?.status === 429) {
    return 'Too many requests. Please wait before trying again.'
  }

  return 'Unable to load investigation history.'
}

function getDeleteError(error) {
  if (error?.response?.status === 404) {
    return 'Investigation was not found.'
  }

  if (error?.response?.status === 429) {
    return 'Too many deletion requests. Please try again later.'
  }

  return 'Unable to delete investigation.'
}

function truncateFilename(filename, maxLength = 42) {
  if (!filename) {
    return 'Untitled investigation'
  }

  if (filename.length <= maxLength) {
    return filename
  }

  return `${filename.slice(0, maxLength - 3)}...`
}

export default function History() {
  const [investigations, setInvestigations] = useState([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(0)

  const [page, setPage] = useState(1)
  const [sortBy, setSortBy] = useState('created_at')
  const [sortOrder, setSortOrder] = useState('desc')
  const [filterText, setFilterText] = useState('')

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [retryCount, setRetryCount] = useState(0)

  const [confirmDeleteId, setConfirmDeleteId] =
    useState(null)
  const [deletingId, setDeletingId] = useState(null)
  const [deleteError, setDeleteError] = useState('')

  useEffect(() => {
    let active = true

    async function loadInvestigations() {
      setLoading(true)
      setError('')

      try {
        const response = await api.get(
          '/api/investigations',
          {
            params: {
              page,
              page_size: 10,
              sort_by: sortBy,
              sort_order: sortOrder,
            },
          },
        )

        if (!active) {
          return
        }

        setInvestigations(
          response.data?.investigations || [],
        )
        setTotal(Number(response.data?.total || 0))
        setTotalPages(
          Number(response.data?.total_pages || 0),
        )
      } catch (requestError) {
        if (!active) {
          return
        }

        setInvestigations([])
        setTotal(0)
        setTotalPages(0)
        setError(getFetchError(requestError))
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    loadInvestigations()

    return () => {
      active = false
    }
  }, [
    page,
    sortBy,
    sortOrder,
    retryCount,
  ])

  const filteredInvestigations = useMemo(() => {
    const query = filterText.trim().toLowerCase()

    if (!query) {
      return investigations
    }

    return investigations.filter((investigation) =>
      String(investigation.filename || '')
        .toLowerCase()
        .includes(query),
    )
  }, [investigations, filterText])

  const start =
    total === 0 ? 0 : (page - 1) * 10 + 1

  const end =
    total === 0
      ? 0
      : Math.min(page * 10, total)

  const handleSortChange = (event) => {
    setSortBy(event.target.value)
    setPage(1)
    setFilterText('')
    setConfirmDeleteId(null)
    setDeleteError('')
  }

  const toggleSortOrder = () => {
    setSortOrder((current) =>
      current === 'desc' ? 'asc' : 'desc',
    )

    setPage(1)
    setFilterText('')
    setConfirmDeleteId(null)
    setDeleteError('')
  }

  const goToPage = (nextPage) => {
    if (
      nextPage < 1 ||
      nextPage > totalPages ||
      nextPage === page
    ) {
      return
    }

    setPage(nextPage)
    setFilterText('')
    setConfirmDeleteId(null)
    setDeleteError('')
  }

  const handleDelete = async (investigationId) => {
    if (deletingId) {
      return
    }

    setDeletingId(investigationId)
    setDeleteError('')

    try {
      await api.delete(
        `/api/investigations/${investigationId}`,
      )

      setConfirmDeleteId(null)

      /*
       * If the deleted investigation was the only item
       * on a page beyond page 1, move to the previous
       * page first. That state change triggers the
       * correct refetch automatically.
       */
      if (
        investigations.length === 1 &&
        page > 1
      ) {
        setPage((current) => current - 1)
      } else {
        /*
         * Stay on the current page but refetch rather
         * than merely removing the row locally.
         *
         * This keeps server pagination totals correct
         * and fills the vacated row from the next page
         * when one exists.
         */
        setRetryCount((value) => value + 1)
      }
    } catch (requestError) {
      setDeleteError(
        getDeleteError(requestError),
      )
    } finally {
      setDeletingId(null)
    }
  }

  const pageNumbers = useMemo(() => {
    if (totalPages <= 1) {
      return totalPages === 1 ? [1] : []
    }

    const pages = new Set([
      1,
      totalPages,
      page - 1,
      page,
      page + 1,
    ])

    return [...pages]
      .filter(
        (number) =>
          number >= 1 &&
          number <= totalPages,
      )
      .sort((a, b) => a - b)
  }, [page, totalPages])

  return (
    <div
      style={{
        width: '100%',
        color: colours.textPrimary,
      }}
    >
      <div
        style={{
          marginBottom: '28px',
        }}
      >
        <h1
          style={{
            margin: 0,
            color: colours.textPrimary,
            fontSize: '24px',
            fontWeight: 500,
            lineHeight: 1.25,
          }}
        >
          Analysis History
        </h1>

        <div
          style={{
            marginTop: '5px',
            color: colours.textMuted,
            fontSize: '13px',
          }}
        >
          Review and manage previous SENTINEL
          investigations
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns:
            'minmax(0, 1fr) 210px 130px',
          gap: '10px',
          marginBottom: '16px',
        }}
      >
        <div
          style={{
            position: 'relative',
          }}
        >
          <Search
            size={15}
            style={{
              position: 'absolute',
              left: '12px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: colours.textMuted,
              pointerEvents: 'none',
            }}
          />

          <input
            type="text"
            value={filterText}
            onChange={(event) =>
              setFilterText(event.target.value)
            }
            placeholder="Filter current page by filename..."
            style={{
              width: '100%',
              height: '40px',
              padding: '0 12px 0 36px',
              background: colours.card,
              border: `1px solid ${colours.border}`,
              borderRadius: 0,
              color: colours.textPrimary,
              fontFamily: "'Inter', sans-serif",
              fontSize: '13px',
              outline: 'none',
            }}
          />
        </div>

        <select
          value={sortBy}
          onChange={handleSortChange}
          style={{
            width: '100%',
            height: '40px',
            padding: '0 10px',
            background: colours.card,
            border: `1px solid ${colours.border}`,
            borderRadius: 0,
            color: colours.textSecondary,
            fontFamily: "'Inter', sans-serif",
            fontSize: '12px',
            outline: 'none',
            cursor: 'pointer',
          }}
        >
          {sortOptions.map((option) => (
            <option
              key={option.value}
              value={option.value}
            >
              Sort: {option.label}
            </option>
          ))}
        </select>

        <button
          type="button"
          onClick={toggleSortOrder}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '7px',
            height: '40px',
            padding: '0 10px',
            background: colours.card,
            border: `1px solid ${colours.border}`,
            borderRadius: 0,
            color: colours.textSecondary,
            cursor: 'pointer',
            fontFamily: "'Inter', sans-serif",
            fontSize: '12px',
            fontWeight: 500,
          }}
        >
          {sortOrder === 'desc' ? (
            <ArrowDown size={14} />
          ) : (
            <ArrowUp size={14} />
          )}

          {sortOrder === 'desc'
            ? 'Descending'
            : 'Ascending'}
        </button>
      </div>

      {deleteError && (
        <div
          style={{
            marginBottom: '12px',
            padding: '10px 12px',
            background: colours.card,
            border: `1px solid ${colours.critical}`,
            borderRadius: 0,
            color: colours.critical,
            fontSize: '12px',
          }}
        >
          {deleteError}
        </div>
      )}

      {loading ? (
        <div
          style={{
            padding: '22px 0',
            color: colours.textMuted,
            fontSize: '13px',
          }}
        >
          Loading investigation history...
        </div>
      ) : error ? (
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
              marginBottom: '16px',
              color: colours.critical,
              fontSize: '13px',
            }}
          >
            {error}
          </div>

          <button
            type="button"
            onClick={() =>
              setRetryCount(
                (value) => value + 1,
              )
            }
            style={{
              padding: '9px 14px',
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
      ) : total === 0 ? (
        <div
          style={{
            padding: '32px',
            background: colours.card,
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
            Investigation history
          </div>

          <div
            style={{
              marginBottom: '14px',
              color: colours.textSecondary,
              fontSize: '13px',
            }}
          >
            No investigations yet.
          </div>

          <Link
            to="/upload"
            style={{
              color: colours.accent,
              fontSize: '13px',
              fontWeight: 500,
              textDecoration: 'none',
            }}
          >
            Upload log data to begin →
          </Link>
        </div>
      ) : (
        <>
          <div
            style={{
              overflowX: 'auto',
              background: colours.card,
              border: `1px solid ${colours.border}`,
              borderRadius: 0,
            }}
          >
            <table
              style={{
                width: '100%',
                borderCollapse: 'collapse',
              }}
            >
              <thead>
                <tr
                  style={{
                    background: colours.surface,
                  }}
                >
                  {[
                    'Filename',
                    'Upload date',
                    'Events',
                    'High threats',
                    'Clusters',
                    'Status',
                    'Actions',
                  ].map((heading, index) => (
                    <th
                      key={heading}
                      scope="col"
                      style={{
                        padding: '10px 12px',
                        borderBottom: `1px solid ${colours.border}`,
                        color: colours.textMuted,
                        fontSize: '11px',
                        fontWeight: 500,
                        letterSpacing: '0.08em',
                        textAlign:
                          index === 2 ||
                          index === 3 ||
                          index === 4
                            ? 'right'
                            : 'left',
                        textTransform: 'uppercase',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {filteredInvestigations.map(
                  (investigation, index) => {
                    const highThreatCount =
                      Number(
                        investigation.high_threat_count ||
                          0,
                      )

                    const clusterCount =
                      Number(
                        investigation.attack_clusters ||
                          0,
                      )

                    const confirming =
                      confirmDeleteId ===
                      investigation.investigation_id

                    const deleting =
                      deletingId ===
                      investigation.investigation_id

                    return (
                      <tr
                        key={
                          investigation.investigation_id
                        }
                        style={{
                          background:
                            index % 2 === 1
                              ? colours.canvas
                              : colours.card,
                        }}
                      >
                        <td
                          title={
                            investigation.filename || ''
                          }
                          style={{
                            padding: '12px',
                            borderBottom: `1px solid ${colours.border}`,
                            color:
                              colours.textPrimary,
                            fontSize: '13px',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {truncateFilename(
                            investigation.filename,
                          )}
                        </td>

                        <td
                          style={{
                            ...monoStyle,
                            padding: '12px',
                            borderBottom: `1px solid ${colours.border}`,
                            color:
                              colours.textSecondary,
                            fontSize: '12px',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {formatDateTime(
                            investigation.created_at,
                          )}
                        </td>

                        <td
                          style={{
                            ...monoStyle,
                            padding: '12px',
                            borderBottom: `1px solid ${colours.border}`,
                            color:
                              colours.textPrimary,
                            fontSize: '12px',
                            textAlign: 'right',
                          }}
                        >
                          {Number(
                            investigation.event_count ||
                              0,
                          )}
                        </td>

                        <td
                          style={{
                            ...monoStyle,
                            padding: '12px',
                            borderBottom: `1px solid ${colours.border}`,
                            color:
                              highThreatCount > 0
                                ? colours.critical
                                : colours.textMuted,
                            fontSize: '12px',
                            textAlign: 'right',
                          }}
                        >
                          {highThreatCount}
                        </td>

                        <td
                          style={{
                            ...monoStyle,
                            padding: '12px',
                            borderBottom: `1px solid ${colours.border}`,
                            color:
                              clusterCount > 0
                                ? colours.high
                                : colours.textMuted,
                            fontSize: '12px',
                            textAlign: 'right',
                          }}
                        >
                          {clusterCount}
                        </td>

                        <td
                          style={{
                            padding: '12px',
                            borderBottom: `1px solid ${colours.border}`,
                          }}
                        >
                          <span
                            style={{
                              display:
                                'inline-block',
                              padding: '3px 7px',
                              background:
                                colours.surface,
                              border: `1px solid ${colours.border}`,
                              borderRadius: 0,
                              color:
                                colours.textSecondary,
                              fontSize: '10px',
                              fontWeight: 500,
                              textTransform:
                                'uppercase',
                            }}
                          >
                            Processed
                          </span>
                        </td>

                        <td
                          style={{
                            minWidth: '230px',
                            padding: '12px',
                            borderBottom: `1px solid ${colours.border}`,
                          }}
                        >
                          {confirming ? (
                            <div
                              style={{
                                display: 'flex',
                                alignItems:
                                  'center',
                                gap: '8px',
                                flexWrap: 'wrap',
                              }}
                            >
                              <span
                                style={{
                                  color:
                                    colours.textSecondary,
                                  fontSize: '11px',
                                }}
                              >
                                Delete this
                                investigation?
                              </span>

                              <button
                                type="button"
                                disabled={deleting}
                                onClick={() =>
                                  handleDelete(
                                    investigation.investigation_id,
                                  )
                                }
                                style={{
                                  padding: 0,
                                  background:
                                    'transparent',
                                  border: 'none',
                                  borderRadius: 0,
                                  color:
                                    colours.critical,
                                  cursor: deleting
                                    ? 'wait'
                                    : 'pointer',
                                  fontFamily:
                                    "'Inter', sans-serif",
                                  fontSize: '11px',
                                  fontWeight: 500,
                                }}
                              >
                                {deleting
                                  ? 'Deleting...'
                                  : 'Yes'}
                              </button>

                              <button
                                type="button"
                                disabled={deleting}
                                onClick={() => {
                                  setConfirmDeleteId(
                                    null,
                                  )
                                  setDeleteError('')
                                }}
                                style={{
                                  padding: 0,
                                  background:
                                    'transparent',
                                  border: 'none',
                                  borderRadius: 0,
                                  color:
                                    colours.textMuted,
                                  cursor: deleting
                                    ? 'not-allowed'
                                    : 'pointer',
                                  fontFamily:
                                    "'Inter', sans-serif",
                                  fontSize: '11px',
                                }}
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <div
                              style={{
                                display: 'flex',
                                alignItems:
                                  'center',
                                gap: '16px',
                              }}
                            >
                              <Link
                                to={`/analysis/${investigation.investigation_id}`}
                                style={{
                                  color:
                                    colours.accent,
                                  fontSize: '12px',
                                  fontWeight: 500,
                                  textDecoration:
                                    'none',
                                }}
                              >
                                View
                              </Link>

                              <button
                                type="button"
                                onClick={() => {
                                  setConfirmDeleteId(
                                    investigation.investigation_id,
                                  )
                                  setDeleteError('')
                                }}
                                style={{
                                  display: 'flex',
                                  alignItems:
                                    'center',
                                  gap: '5px',
                                  padding: 0,
                                  background:
                                    'transparent',
                                  border: 'none',
                                  borderRadius: 0,
                                  color:
                                    colours.textMuted,
                                  cursor: 'pointer',
                                  fontFamily:
                                    "'Inter', sans-serif",
                                  fontSize: '11px',
                                }}
                              >
                                <Trash2 size={12} />
                                Delete
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    )
                  },
                )}
              </tbody>
            </table>

            {filteredInvestigations.length ===
              0 && (
              <div
                style={{
                  padding: '24px',
                  borderTop: `1px solid ${colours.border}`,
                  color: colours.textMuted,
                  fontSize: '13px',
                }}
              >
                No investigations on this page match
                that filename filter.
              </div>
            )}
          </div>

          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: '20px',
              marginTop: '16px',
              flexWrap: 'wrap',
            }}
          >
            <div
              style={{
                color: colours.textMuted,
                fontSize: '12px',
              }}
            >
              Showing{' '}
              <span style={monoStyle}>{start}</span>
              {'–'}
              <span style={monoStyle}>{end}</span>{' '}
              of{' '}
              <span style={monoStyle}>{total}</span>{' '}
              investigations
            </div>

            {totalPages > 1 && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                }}
              >
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() =>
                    goToPage(page - 1)
                  }
                  aria-label="Previous page"
                  style={{
                    width: '32px',
                    height: '32px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: colours.card,
                    border: `1px solid ${colours.border}`,
                    borderRadius: 0,
                    color:
                      page <= 1
                        ? colours.textMuted
                        : colours.textSecondary,
                    cursor:
                      page <= 1
                        ? 'not-allowed'
                        : 'pointer',
                  }}
                >
                  <ChevronLeft size={14} />
                </button>

                {pageNumbers.map(
                  (pageNumber, index) => {
                    const previous =
                      pageNumbers[index - 1]

                    return (
                      <div
                        key={pageNumber}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '5px',
                        }}
                      >
                        {previous &&
                          pageNumber -
                            previous >
                            1 && (
                            <span
                              style={{
                                padding:
                                  '0 3px',
                                color:
                                  colours.textMuted,
                                fontSize:
                                  '12px',
                              }}
                            >
                              …
                            </span>
                          )}

                        <button
                          type="button"
                          onClick={() =>
                            goToPage(
                              pageNumber,
                            )
                          }
                          style={{
                            minWidth: '32px',
                            height: '32px',
                            padding: '0 7px',
                            background:
                              pageNumber === page
                                ? colours.accent
                                : colours.card,
                            border: `1px solid ${
                              pageNumber === page
                                ? colours.accent
                                : colours.border
                            }`,
                            borderRadius: 0,
                            color:
                              pageNumber === page
                                ? '#FFFFFF'
                                : colours.textSecondary,
                            cursor:
                              pageNumber === page
                                ? 'default'
                                : 'pointer',
                            fontFamily:
                              "'JetBrains Mono', monospace",
                            fontSize: '11px',
                          }}
                        >
                          {pageNumber}
                        </button>
                      </div>
                    )
                  },
                )}

                <button
                  type="button"
                  disabled={
                    page >= totalPages
                  }
                  onClick={() =>
                    goToPage(page + 1)
                  }
                  aria-label="Next page"
                  style={{
                    width: '32px',
                    height: '32px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: colours.card,
                    border: `1px solid ${colours.border}`,
                    borderRadius: 0,
                    color:
                      page >= totalPages
                        ? colours.textMuted
                        : colours.textSecondary,
                    cursor:
                      page >= totalPages
                        ? 'not-allowed'
                        : 'pointer',
                  }}
                >
                  <ChevronRight size={14} />
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}