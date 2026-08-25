import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import * as d3 from 'd3'

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
}

const nodeColours = {
  src_ip: '#1A1A2E',
  dst_ip: '#4A4A4A',
  user_account: '#D4A017',
  device_id: '#8A8A8A',
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

function graphErrorMessage(error) {
  if (error?.response?.status === 404) {
    return 'Investigation not found.'
  }

  if (error?.response?.status === 422) {
    return 'Invalid investigation identifier.'
  }

  if (error?.response?.status === 429) {
    return 'Too many requests. Please wait a moment and try again.'
  }

  return 'Unable to load attack graph. Please try again.'
}

function formatNodeType(type) {
  const labels = {
    src_ip: 'Source IP',
    dst_ip: 'Destination IP',
    user_account: 'User account',
    device_id: 'Device',
  }

  return labels[type] || type || 'Unknown'
}

function displayNodeId(id) {
  if (!id) {
    return 'Unknown'
  }

  const separatorIndex = id.indexOf(':')

  if (separatorIndex === -1) {
    return id
  }

  return id.slice(separatorIndex + 1)
}

function formatBytes(value) {
  const bytes = Number(value || 0)

  if (bytes >= 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }

  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`
  }

  return `${bytes.toFixed(0)} B`
}

function MetricRow({ label, value, monospace = true }) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'baseline',
        gap: '16px',
        padding: '11px 0',
        borderTop: `1px solid ${colours.border}`,
      }}
    >
      <span
        style={{
          color: colours.textSecondary,
          fontSize: '12px',
        }}
      >
        {label}
      </span>

      <span
        style={{
          ...(monospace ? monoStyle : {}),
          color: colours.textPrimary,
          fontSize: '12px',
          textAlign: 'right',
          overflowWrap: 'anywhere',
        }}
      >
        {value}
      </span>
    </div>
  )
}

function LegendItem({ colour, label, outlined = false }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        color: colours.textSecondary,
        fontSize: '11px',
        whiteSpace: 'nowrap',
      }}
    >
      <span
        style={{
          width: '10px',
          height: '10px',
          display: 'inline-block',
          background: outlined ? colours.card : colour,
          border: `2px solid ${colour}`,
          borderRadius: 0,
        }}
      />

      {label}
    </div>
  )
}

export default function Graph() {
  const { investigationId } = useParams()
  const navigate = useNavigate()

  const svgRef = useRef(null)
  const graphPanelRef = useRef(null)

  const [investigation, setInvestigation] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [retryCount, setRetryCount] = useState(0)
  const [dimensions, setDimensions] = useState({
    width: 760,
    height: 620,
  })

  useEffect(() => {
    let active = true

    async function loadInvestigation() {
      setLoading(true)
      setError('')

      try {
        const response = await api.get(
          `/api/investigations/${investigationId}`,
        )

        if (!active) {
          return
        }

        setInvestigation(response.data)
        setSelectedNode(null)
      } catch (requestError) {
        if (!active) {
          return
        }

        setInvestigation(null)
        setError(graphErrorMessage(requestError))
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    loadInvestigation()

    return () => {
      active = false
    }
  }, [investigationId, retryCount])

  useEffect(() => {
    const panel = graphPanelRef.current

    if (!panel || typeof ResizeObserver === 'undefined') {
      return undefined
    }

    const updateDimensions = () => {
      setDimensions({
        width: Math.max(480, Math.floor(panel.clientWidth)),
        height: Math.max(
          560,
          Math.min(720, window.innerHeight - 190),
        ),
      })
    }

    updateDimensions()

    const observer = new ResizeObserver(updateDimensions)
    observer.observe(panel)

    return () => {
      observer.disconnect()
    }
  }, [loading, error, investigation])

  const graphResult = investigation?.graph_result || {}

  const graphNodes = useMemo(
    () => (Array.isArray(graphResult.nodes) ? graphResult.nodes : []),
    [graphResult.nodes],
  )

  const graphEdges = useMemo(
    () => (Array.isArray(graphResult.edges) ? graphResult.edges : []),
    [graphResult.edges],
  )

  const attackClusters = useMemo(
    () =>
      Array.isArray(graphResult.attack_clusters)
        ? graphResult.attack_clusters
        : [],
    [graphResult.attack_clusters],
  )

  const graphSummary = graphResult.graph_summary || {}

  const hasGraphData = graphNodes.length > 0
  const showLabels = graphNodes.length < 50

  const selectedNodeEdges = useMemo(() => {
    if (!selectedNode) {
      return []
    }

    return graphEdges.filter((edge) => {
      const source =
        typeof edge.source === 'object'
          ? edge.source.id
          : edge.source

      const target =
        typeof edge.target === 'object'
          ? edge.target.id
          : edge.target

      return (
        source === selectedNode.id ||
        target === selectedNode.id
      )
    })
  }, [graphEdges, selectedNode])

  useEffect(() => {
    const svgElement = svgRef.current

    if (!svgElement || !hasGraphData) {
      return undefined
    }

    const svg = d3.select(svgElement)

    /*
     * Clear any previous graph before constructing the new simulation.
     * D3 mutates simulation nodes and links, so clone the API data rather
     * than allowing it to mutate React-owned investigation state.
     */
    svg.selectAll('*').remove()

    const nodes = graphNodes.map((node) => ({
      ...node,
    }))

    const edges = graphEdges.map((edge) => ({
      ...edge,
    }))

    const { width, height } = dimensions

    svg
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('width', '100%')
      .attr('height', height)
      .attr('role', 'img')
      .attr(
        'aria-label',
        'Interactive SENTINEL attack graph',
      )

    const root = svg.append('g')

    const edgeSelection = root
      .append('g')
      .attr('aria-hidden', 'true')
      .selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke', colours.border)
      .attr('stroke-opacity', 0.9)
      .attr('stroke-width', (edge) =>
        Number(edge.max_threat_score || 0) > 50 ? 2 : 1,
      )

    const nodeSelection = root
      .append('g')
      .selectAll('g')
      .data(nodes, (node) => node.id)
      .join('g')
      .style('cursor', 'pointer')

    nodeSelection
      .append('circle')
      .attr('r', (node) =>
        node.is_suspicious ? 12 : 8,
      )
      .attr(
        'fill',
        (node) =>
          nodeColours[node.type] || colours.textMuted,
      )
      .attr('stroke', (node) => {
        if (!node.is_suspicious) {
          return colours.card
        }

        if (node.max_threat_level === 'Critical') {
          return colours.critical
        }

        if (node.max_threat_level === 'High') {
          return colours.high
        }

        return colours.accent
      })
      .attr('stroke-width', (node) =>
        node.is_suspicious ? 3 : 1.5,
      )

    if (showLabels) {
      nodeSelection
        .append('text')
        .text((node) => displayNodeId(node.id))
        .attr('x', 15)
        .attr('y', 4)
        .attr(
          'font-family',
          "'JetBrains Mono', monospace",
        )
        .attr('font-size', '10px')
        .attr('fill', colours.textSecondary)
        .attr('pointer-events', 'none')
    }

    nodeSelection
      .append('title')
      .text(
        (node) =>
          `${formatNodeType(node.type)}: ${displayNodeId(node.id)}\n` +
          `Threat: ${node.max_threat_level} (${node.max_threat_score})\n` +
          `Events: ${node.event_count}`,
      )

    nodeSelection.on(
      'click.sentinel',
      (event, node) => {
        event.stopPropagation()

        setSelectedNode({
          id: node.id,
          type: node.type,
          is_suspicious: Boolean(node.is_suspicious),
          max_threat_score:
            Number(node.max_threat_score || 0),
          max_threat_level:
            node.max_threat_level || 'None',
          event_count: Number(node.event_count || 0),
        })
      },
    )

    svg.on('click.sentinel', () => {
      setSelectedNode(null)
    })

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        'link',
        d3
          .forceLink(edges)
          .id((node) => node.id)
          .distance(80),
      )
      .force(
        'charge',
        d3.forceManyBody().strength(-200),
      )
      .force(
        'centre',
        d3.forceCenter(width / 2, height / 2),
      )
      .force(
        'collision',
        d3.forceCollide().radius(20),
      )

    simulation.on('tick', () => {
      edgeSelection
        .attr('x1', (edge) => edge.source.x)
        .attr('y1', (edge) => edge.source.y)
        .attr('x2', (edge) => edge.target.x)
        .attr('y2', (edge) => edge.target.y)

      nodeSelection.attr(
        'transform',
        (node) =>
          `translate(${node.x ?? 0}, ${node.y ?? 0})`,
      )
    })

    const dragBehaviour = d3
      .drag()
      .on('start.sentinel', (event, node) => {
        if (!event.active) {
          simulation.alphaTarget(0.3).restart()
        }

        node.fx = node.x
        node.fy = node.y
      })
      .on('drag.sentinel', (event, node) => {
        node.fx = event.x
        node.fy = event.y
      })
      .on('end.sentinel', (event, node) => {
        if (!event.active) {
          simulation.alphaTarget(0)
        }

        node.fx = null
        node.fy = null
      })

    nodeSelection.call(dragBehaviour)

    /*
     * Phase 20 lifecycle requirement:
     * - stop the simulation
     * - detach namespaced D3 listeners
     * - clear rendered SVG contents
     *
     * This runs both when dependencies change and when the page unmounts.
     */
    return () => {
      simulation.stop()
      simulation.on('tick', null)

      nodeSelection.on('.sentinel', null)
      svg.on('.sentinel', null)

      svg.selectAll('*').on('.sentinel', null)
      svg.selectAll('*').remove()
    }
  }, [
    graphNodes,
    graphEdges,
    hasGraphData,
    showLabels,
    dimensions,
  ])

  if (loading) {
    return (
      <div
        style={{
          color: colours.textMuted,
          fontSize: '13px',
        }}
      >
        Loading attack graph...
      </div>
    )
  }

  if (error) {
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
          Attack graph
        </div>

        <div
          style={{
            marginBottom: '18px',
            color: colours.critical,
            fontSize: '13px',
          }}
        >
          {error}
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
          marginBottom: '24px',
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
            Attack Graph —{' '}
            {investigation?.filename || 'Investigation'}
          </h1>

          <div
            style={{
              marginTop: '6px',
              color: colours.textMuted,
              fontSize: '12px',
            }}
          >
            Interactive entity topology · select a node
            to inspect intelligence
          </div>
        </div>

        <div
          style={{
            ...monoStyle,
            maxWidth: '280px',
            color: colours.textMuted,
            fontSize: '11px',
            textAlign: 'right',
            overflowWrap: 'anywhere',
          }}
        >
          {investigationId}
        </div>
      </div>

      {!hasGraphData ? (
        <div
          style={{
            padding: '40px',
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
            Graph data unavailable
          </div>

          <div
            style={{
              maxWidth: '640px',
              color: colours.textSecondary,
              fontSize: '14px',
              lineHeight: 1.6,
            }}
          >
            This investigation does not contain
            persisted graph topology. It may have been
            created before attack graph detail was
            introduced. SENTINEL will not reconstruct or
            invent connections from summary counts.
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns:
                'repeat(3, minmax(0, 1fr))',
              maxWidth: '640px',
              marginTop: '24px',
              borderTop: `1px solid ${colours.border}`,
              borderLeft: `1px solid ${colours.border}`,
            }}
          >
            {[
              [
                'Recorded nodes',
                investigation?.graph_nodes ?? 0,
              ],
              [
                'Recorded edges',
                investigation?.graph_edges ?? 0,
              ],
              [
                'Recorded clusters',
                investigation?.attack_clusters ?? 0,
              ],
            ].map(([label, value]) => (
              <div
                key={label}
                style={{
                  padding: '16px',
                  borderRight: `1px solid ${colours.border}`,
                  borderBottom: `1px solid ${colours.border}`,
                }}
              >
                <div
                  style={{
                    ...sectionLabelStyle,
                    marginBottom: '8px',
                    fontSize: '10px',
                  }}
                >
                  {label}
                </div>

                <div
                  style={{
                    ...monoStyle,
                    color: colours.textPrimary,
                    fontSize: '18px',
                  }}
                >
                  {value}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns:
                'minmax(0, 1fr) 300px',
              gap: '16px',
              alignItems: 'stretch',
            }}
          >
            <div
              ref={graphPanelRef}
              style={{
                minWidth: 0,
                overflow: 'hidden',
                background: colours.card,
                border: `1px solid ${colours.border}`,
                borderRadius: 0,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '16px',
                  minHeight: '50px',
                  padding: '14px 16px',
                  borderBottom: `1px solid ${colours.border}`,
                  flexWrap: 'wrap',
                }}
              >
                <div style={sectionLabelStyle}>
                  Entity topology
                </div>

                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '14px',
                    flexWrap: 'wrap',
                  }}
                >
                  <LegendItem
                    colour={nodeColours.src_ip}
                    label="Source IP"
                  />

                  <LegendItem
                    colour={nodeColours.dst_ip}
                    label="Destination IP"
                  />

                  <LegendItem
                    colour={nodeColours.user_account}
                    label="User account"
                  />

                  <LegendItem
                    colour={nodeColours.device_id}
                    label="Device"
                  />

                  <LegendItem
                    colour={colours.high}
                    label="Suspicious"
                    outlined
                  />
                </div>
              </div>

              <svg
                ref={svgRef}
                style={{
                  display: 'block',
                  width: '100%',
                  background: colours.card,
                }}
              />
            </div>

            <aside
              style={{
                minWidth: 0,
                padding: '18px',
                background: colours.card,
                border: `1px solid ${colours.border}`,
                borderRadius: 0,
              }}
            >
              {selectedNode ? (
                <>
                  <div
                    style={{
                      ...sectionLabelStyle,
                      marginBottom: '12px',
                    }}
                  >
                    Selected node
                  </div>

                  <div
                    style={{
                      ...monoStyle,
                      marginBottom: '12px',
                      color: colours.textPrimary,
                      fontSize: '14px',
                      lineHeight: 1.5,
                      overflowWrap: 'anywhere',
                    }}
                  >
                    {displayNodeId(selectedNode.id)}
                  </div>

                  <ThreatBadge
                    level={
                      selectedNode.max_threat_level ||
                      'None'
                    }
                  />

                  <div style={{ marginTop: '18px' }}>
                    <MetricRow
                      label="Entity type"
                      value={formatNodeType(
                        selectedNode.type,
                      )}
                      monospace={false}
                    />

                    <MetricRow
                      label="Threat score"
                      value={
                        selectedNode.max_threat_score ?? 0
                      }
                    />

                    <MetricRow
                      label="Events"
                      value={selectedNode.event_count ?? 0}
                    />

                    <MetricRow
                      label="Suspicious"
                      value={
                        selectedNode.is_suspicious
                          ? 'Yes'
                          : 'No'
                      }
                      monospace={false}
                    />

                    <MetricRow
                      label="Connected edges"
                      value={selectedNodeEdges.length}
                    />
                  </div>

                  <button
                    type="button"
                    onClick={() =>
                      setSelectedNode(null)
                    }
                    style={{
                      width: '100%',
                      marginTop: '12px',
                      padding: '9px 12px',
                      background: colours.card,
                      border: `1px solid ${colours.border}`,
                      borderRadius: 0,
                      color: colours.textSecondary,
                      cursor: 'pointer',
                      fontFamily: "'Inter', sans-serif",
                      fontSize: '12px',
                      fontWeight: 400,
                    }}
                  >
                    Clear Selection
                  </button>
                </>
              ) : (
                <>
                  <div
                    style={{
                      ...sectionLabelStyle,
                      marginBottom: '12px',
                    }}
                  >
                    Graph summary
                  </div>

                  <div
                    style={{
                      marginBottom: '16px',
                      color: colours.textSecondary,
                      fontSize: '13px',
                      lineHeight: 1.55,
                    }}
                  >
                    Select a node to inspect its entity
                    type, threat state and event
                    activity.
                  </div>

                  <MetricRow
                    label="Total nodes"
                    value={
                      graphSummary.total_nodes ??
                      graphNodes.length
                    }
                  />

                  <MetricRow
                    label="Total edges"
                    value={
                      graphSummary.total_edges ??
                      graphEdges.length
                    }
                  />

                  <MetricRow
                    label="Suspicious nodes"
                    value={
                      graphSummary.suspicious_nodes ?? 0
                    }
                  />

                  <MetricRow
                    label="Attack clusters"
                    value={
                      graphSummary.attack_clusters_detected ??
                      attackClusters.length
                    }
                  />

                  <MetricRow
                    label="Max threat score"
                    value={
                      graphSummary.max_threat_score_in_graph ??
                      0
                    }
                  />
                </>
              )}
            </aside>
          </div>

          <section
            style={{
              marginTop: '16px',
              background: colours.card,
              border: `1px solid ${colours.border}`,
              borderRadius: 0,
            }}
          >
            <div
              style={{
                padding: '16px 18px',
              }}
            >
              <div
                style={{
                  ...sectionLabelStyle,
                  marginBottom:
                    attackClusters.length === 0
                      ? '10px'
                      : 0,
                }}
              >
                Attack clusters
              </div>

              {attackClusters.length === 0 && (
                <div
                  style={{
                    color: colours.textSecondary,
                    fontSize: '13px',
                  }}
                >
                  No attack clusters detected in this
                  investigation.
                </div>
              )}
            </div>

            {attackClusters.map((cluster) => (
              <div
                key={cluster.cluster_id}
                style={{
                  display: 'grid',
                  gridTemplateColumns:
                    '170px minmax(0, 1fr) 180px',
                  gap: '20px',
                  alignItems: 'start',
                  padding: '18px',
                  borderTop: `1px solid ${colours.border}`,
                }}
              >
                <div>
                  <div
                    style={{
                      ...monoStyle,
                      marginBottom: '9px',
                      color: colours.textPrimary,
                      fontSize: '13px',
                      fontWeight: 500,
                    }}
                  >
                    {cluster.cluster_id}
                  </div>

                  <ThreatBadge
                    level={
                      cluster.dominant_threat_level ||
                      'None'
                    }
                  />
                </div>

                <div>
                  <div
                    style={{
                      ...sectionLabelStyle,
                      marginBottom: '8px',
                    }}
                  >
                    Entities
                  </div>

                  <div
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '6px',
                    }}
                  >
                    {(cluster.nodes || []).map(
                      (nodeId) => (
                        <span
                          key={nodeId}
                          style={{
                            ...monoStyle,
                            padding: '3px 6px',
                            border: `1px solid ${colours.border}`,
                            borderRadius: 0,
                            color:
                              colours.textSecondary,
                            fontSize: '10px',
                          }}
                        >
                          {displayNodeId(nodeId)}
                        </span>
                      ),
                    )}
                  </div>

                  {(cluster.event_types || []).length >
                    0 && (
                    <>
                      <div
                        style={{
                          ...sectionLabelStyle,
                          marginTop: '14px',
                          marginBottom: '6px',
                        }}
                      >
                        Event types
                      </div>

                      <div
                        style={{
                          color:
                            colours.textSecondary,
                          fontSize: '12px',
                        }}
                      >
                        {cluster.event_types.join(', ')}
                      </div>
                    </>
                  )}
                </div>

                <div>
                  <MetricRow
                    label="Edges"
                    value={cluster.edge_count ?? 0}
                  />

                  <MetricRow
                    label="Total bytes"
                    value={formatBytes(
                      cluster.total_bytes,
                    )}
                  />

                  <MetricRow
                    label="Max threat"
                    value={
                      cluster.max_threat_score ?? 0
                    }
                  />
                </div>
              </div>
            ))}
          </section>
        </>
      )}
    </div>
  )
}