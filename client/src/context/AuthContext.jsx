import { createContext, useContext, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const AuthContext = createContext(null)

function readStoredSession() {
  const token = localStorage.getItem('sentinel_token')
  const rawUser = localStorage.getItem('sentinel_user')

  if (!token || !rawUser) {
    return { token: null, user: null }
  }

  try {
    const user = JSON.parse(rawUser)

    if (!user || typeof user !== 'object') {
      throw new Error('Stored SENTINEL user is invalid')
    }

    return { token, user }
  } catch {
    localStorage.removeItem('sentinel_token')
    localStorage.removeItem('sentinel_user')
    return { token: null, user: null }
  }
}

export function AuthProvider({ children }) {
  const navigate = useNavigate()
  const [session, setSession] = useState(readStoredSession)

  const login = (token, user) => {
    localStorage.setItem('sentinel_token', token)
    localStorage.setItem('sentinel_user', JSON.stringify(user))
    setSession({ token, user })
  }

  const logout = () => {
    localStorage.removeItem('sentinel_token')
    localStorage.removeItem('sentinel_user')
    setSession({ token: null, user: null })
    navigate('/login', { replace: true })
  }

  const value = useMemo(
    () => ({
      user: session.user,
      token: session.token,
      login,
      logout,
      isAuthenticated: Boolean(session.token && session.user),
    }),
    [session],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)

  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }

  return context
}
