import { History, LayoutDashboard, Upload } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const colours = {
  surface: '#EAEAE5',
  border: '#D0D0C8',
  primary: '#0E0E0E',
  muted: '#8A8A8A',
  accent: '#1A1A2E',
}

const navItems = [
  { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { label: 'Upload', path: '/upload', icon: Upload },
  { label: 'History', path: '/history', icon: History },
]

export default function Navbar() {
  const location = useLocation()
  const { user, logout } = useAuth()

  return (
    <aside
      style={{
        position: 'fixed',
        inset: '0 auto 0 0',
        width: '220px',
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        background: colours.surface,
        borderRight: `1px solid ${colours.border}`,
        zIndex: 10,
      }}
    >
      <div
        style={{
          padding: '24px',
          borderBottom: `1px solid ${colours.border}`,
        }}
      >
        <div
          style={{
            color: colours.primary,
            fontSize: '18px',
            fontWeight: 500,
            lineHeight: 1.2,
          }}
        >
          SENTINEL
        </div>
        <div
          style={{
            marginTop: '5px',
            color: colours.muted,
            fontSize: '11px',
            fontWeight: 400,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
          }}
        >
          by FINSIQ
        </div>
      </div>

      <nav style={{ paddingTop: '16px' }}>
        {navItems.map(({ label, path, icon: Icon }) => {
          const active = location.pathname === path

          return (
            <Link
              key={path}
              to={path}
              style={{
                height: '44px',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: active ? '0 20px 0 22px' : '0 20px 0 24px',
                color: active ? colours.accent : colours.primary,
                background: colours.surface,
                borderLeft: active
                  ? `2px solid ${colours.accent}`
                  : '0 solid transparent',
                textDecoration: 'none',
                fontSize: '14px',
                fontWeight: 500,
              }}
            >
              <Icon size={18} strokeWidth={1.7} aria-hidden="true" />
              <span>{label}</span>
            </Link>
          )
        })}
      </nav>

      <div
        style={{
          marginTop: 'auto',
          padding: '20px 24px 24px',
          borderTop: `1px solid ${colours.border}`,
        }}
      >
        <div
          style={{
            overflow: 'hidden',
            color: colours.muted,
            fontSize: '12px',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
          title={user?.username || ''}
        >
          {user?.username || 'SENTINEL user'}
        </div>

        <button
          type="button"
          onClick={logout}
          style={{
            marginTop: '10px',
            padding: 0,
            color: colours.muted,
            background: 'transparent',
            border: 0,
            borderRadius: 0,
            cursor: 'pointer',
            fontSize: '12px',
            fontWeight: 400,
            textAlign: 'left',
          }}
        >
          Sign Out
        </button>
      </div>
    </aside>
  )
}
