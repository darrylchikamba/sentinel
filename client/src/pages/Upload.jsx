import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import api from '../api/axiosConfig'
import { extractApiError } from '../utils/apiErrors'

const colours = {
  card: '#FFFFFF',
  border: '#D0D0C8',
  textPrimary: '#0E0E0E',
  textSecondary: '#4A4A4A',
  textMuted: '#8A8A8A',
  accent: '#1A1A2E',
  critical: '#C0392B',
  low: '#2E7D4F',
}

const MAX_FILE_SIZE = 10 * 1024 * 1024
const ACCEPTED_EXTENSIONS = ['.csv', '.xlsx', '.xls']
const STAGES = ['PARSE', 'DETECT', 'SCORE', 'REPORT']

function getExtension(filename) {
  const dotIndex = filename.lastIndexOf('.')
  return dotIndex >= 0 ? filename.slice(dotIndex).toLowerCase() : ''
}

export default function Upload() {
  const navigate = useNavigate()
  const fileInputRef = useRef(null)
  const intervalRef = useRef(null)

  const [selectedFile, setSelectedFile] = useState(null)
  const [rawText, setRawText] = useState('')
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [currentStage, setCurrentStage] = useState(-1)
  const [error, setError] = useState('')

  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [])

  const validateFile = (file) => {
    if (!file) return false

    const extension = getExtension(file.name)
    if (!ACCEPTED_EXTENSIONS.includes(extension)) {
      setError('Unsupported file type. Use .csv, .xlsx or .xls.')
      return false
    }

    if (file.size > MAX_FILE_SIZE) {
      setError('File exceeds 10 MB limit')
      return false
    }

    setError('')
    return true
  }

  const chooseFile = (file) => {
    if (validateFile(file)) setSelectedFile(file)
  }

  const startSimulatedProgress = () => {
    setCurrentStage(0)
    intervalRef.current = setInterval(() => {
      setCurrentStage((stage) => {
        if (stage >= STAGES.length - 1) {
          clearInterval(intervalRef.current)
          intervalRef.current = null
          return STAGES.length - 1
        }
        return stage + 1
      })
    }, 1000)
  }

  const stopSimulatedProgress = (successful) => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current)
      intervalRef.current = null
    }
    setCurrentStage(successful ? STAGES.length : -1)
  }

  const handleSubmit = async () => {
    if (!selectedFile && !rawText.trim()) return

    setError('')
    setLoading(true)
    startSimulatedProgress()

    try {
      let response

      if (selectedFile) {
        const formData = new FormData()
        formData.append('file', selectedFile)

        // No Content-Type header is set here. Axios/browser must create the
        // multipart/form-data boundary automatically.
        response = await api.post('/api/upload', formData)
      } else {
        response = await api.post('/api/upload', { raw_text: rawText.trim() })
      }

      stopSimulatedProgress(true)
      navigate(`/analysis/${response.data.investigation_id}`)
    } catch (requestError) {
      stopSimulatedProgress(false)
      const status = requestError?.response?.status

      if (status === 413) {
        setError('File exceeds 10 MB limit')
      } else if (status === 422) {
        setError(
          extractApiError(
            requestError,
            'The submitted log data could not be processed.',
          ),
        )
      } else if (status === 429) {
        setError('Too many investigations submitted. Please try again later.')
      } else {
        setError(
          extractApiError(requestError, 'Analysis failed. Please try again.'),
        )
      }
    } finally {
      setLoading(false)
    }
  }

  const bothProvided = Boolean(selectedFile && rawText.trim())
  const disabled = loading || (!selectedFile && !rawText.trim())

  return (
    <div style={{ color: colours.textPrimary }}>
      <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 500, lineHeight: 1.25 }}>
        New Investigation
      </h1>
      <div style={{ marginTop: '4px', marginBottom: '32px', color: colours.textMuted, fontSize: '13px' }}>
        Upload SIEM log data for analysis
      </div>

      <div style={{ display: 'flex', gap: '24px', alignItems: 'stretch', flexWrap: 'wrap' }}>
        <section style={{ flex: '1 1 360px', minWidth: 0, padding: '24px', background: colours.card, border: `1px solid ${colours.border}`, borderRadius: 0 }}>
          <div style={{ marginBottom: '12px', color: colours.textMuted, fontSize: '11px', fontWeight: 500, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            Upload file
          </div>

          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,.xlsx,.xls"
            onChange={(event) => chooseFile(event.target.files?.[0])}
            style={{ display: 'none' }}
          />

          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            onDragEnter={(event) => { event.preventDefault(); setDragging(true) }}
            onDragOver={(event) => { event.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => {
              event.preventDefault()
              setDragging(false)
              chooseFile(event.dataTransfer.files?.[0])
            }}
            style={{ width: '100%', height: '180px', padding: '16px', background: '#FAFAFA', border: `1px dashed ${dragging ? colours.accent : colours.border}`, borderRadius: 0, color: colours.textMuted, cursor: 'pointer', textAlign: 'center' }}
          >
            <div style={{ fontSize: '14px' }}>Drop CSV or Excel file here</div>
            <div style={{ marginTop: '6px', fontSize: '12px' }}>or click to browse</div>
          </button>

          {selectedFile && (
            <div title={selectedFile.name} style={{ marginTop: '10px', overflow: 'hidden', color: colours.textSecondary, fontSize: '12px', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {selectedFile.name}
            </div>
          )}

          <div style={{ marginTop: '8px', color: colours.textMuted, fontSize: '11px' }}>
            Supported: .csv, .xlsx, .xls — Maximum 10 MB
          </div>
        </section>

        <section style={{ flex: '1 1 360px', minWidth: 0, padding: '24px', background: colours.card, border: `1px solid ${colours.border}`, borderRadius: 0 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', marginBottom: '12px' }}>
            <div style={{ color: colours.textMuted, fontSize: '11px', fontWeight: 500, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
              Or paste log data
            </div>
            <div style={{ color: colours.textMuted, fontSize: '11px', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
              Raw data entry
            </div>
          </div>

          <textarea
            value={rawText}
            onChange={(event) => setRawText(event.target.value)}
            placeholder="timestamp,src_ip,dst_ip,event_type,bytes_transferred,..."
            style={{ width: '100%', minHeight: '180px', padding: '12px', resize: 'vertical', background: colours.card, border: `1px solid ${colours.border}`, borderRadius: 0, color: colours.textPrimary, fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', lineHeight: 1.5, outline: 'none' }}
          />
        </section>
      </div>

      {bothProvided && (
        <div style={{ marginTop: '10px', color: colours.textMuted, fontSize: '12px' }}>
          Selected file will be analysed; pasted text will be ignored.
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'flex-start', marginTop: '32px', padding: '20px 0' }}>
        {STAGES.map((stage, index) => {
          const complete = currentStage > index
          const active = currentStage === index
          const background = complete ? colours.low : active ? colours.accent : colours.card

          return (
            <div key={stage} style={{ display: 'flex', flex: 1, alignItems: 'flex-start' }}>
              <div style={{ display: 'flex', flex: 1, flexDirection: 'column', alignItems: 'center' }}>
                <div style={{ width: '20px', height: '20px', background, border: `1px solid ${complete ? colours.low : active ? colours.accent : colours.border}`, borderRadius: 0 }} />
                <div style={{ marginTop: '7px', color: complete || active ? colours.textPrimary : colours.textMuted, fontSize: '11px', fontWeight: 500, letterSpacing: '0.08em' }}>
                  {stage}
                </div>
              </div>
              {index < STAGES.length - 1 && (
                <div style={{ flex: 1, height: '1px', marginTop: '10px', background: currentStage > index ? colours.low : colours.border }} />
              )}
            </div>
          )
        })}
      </div>

      <div style={{ minHeight: '20px', marginBottom: '8px', color: error ? colours.critical : colours.textMuted, fontSize: '13px' }}>
        {error || (loading ? 'Processing investigation...' : '')}
      </div>

      <button
        type="button"
        disabled={disabled}
        onClick={handleSubmit}
        style={{ width: '100%', padding: '14px', background: colours.accent, border: 'none', borderRadius: 0, color: '#FFFFFF', cursor: disabled ? 'not-allowed' : 'pointer', fontSize: '14px', fontWeight: 500 }}
      >
        {loading ? 'Analysing...' : 'Run Analysis'}
      </button>
    </div>
  )
}
