import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';

import api from '../api/axiosConfig';
import { useAuth } from '../context/AuthContext';
import { extractApiError } from '../utils/apiErrors';

const colours = {
  canvas: '#F4F4F0',
  card: '#FFFFFF',
  border: '#D0D0C8',
  textPrimary: '#0E0E0E',
  textMuted: '#8A8A8A',
  accent: '#1A1A2E',
  accentHover: '#2A2A4E',
  critical: '#C0392B',
  low: '#2E7D4F',
};

const fieldLabelStyle = {
  display: 'block',
  marginBottom: '6px',
  color: colours.textMuted,
  fontSize: '11px',
  fontWeight: 500,
  letterSpacing: '0.1em',
  textTransform: 'uppercase',
};

function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [focusedField, setFocusedField] = useState('');
  const [buttonHovered, setButtonHovered] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const successMessage =
    typeof location.state?.message === 'string' ? location.state.message : '';

  const inputStyle = (field) => ({
    width: '100%',
    padding: '10px 12px',
    border: `1px solid ${
      focusedField === field ? colours.accent : colours.border
    }`,
    borderRadius: 0,
    background: colours.card,
    color: colours.textPrimary,
    fontFamily: "'Inter', sans-serif",
    fontSize: '14px',
    fontWeight: 400,
    outline: 'none',
  });

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await api.post('/api/auth/login', {
        email: email.trim(),
        password,
      });

      login(response.data.access_token, response.data.user);
      navigate('/dashboard', { replace: true });
    } catch (requestError) {
      const status = requestError?.response?.status;

      if (status === 401) {
        setError('Invalid email or password.');
      } else if (status === 429) {
        setError('Too many sign-in attempts. Please try again later.');
      } else if (status === 422) {
        setError(extractApiError(requestError, 'Please check your details and try again.'));
      } else {
        setError(extractApiError(requestError, 'Sign in failed. Please try again.'));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
        background: colours.canvas,
      }}
    >
      <div
        style={{
          width: '400px',
          maxWidth: 'calc(100vw - 32px)',
          background: colours.card,
          border: `1px solid ${colours.border}`,
          borderRadius: 0,
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
              color: colours.textPrimary,
              fontSize: '24px',
              fontWeight: 500,
              lineHeight: 1.2,
            }}
          >
            SENTINEL
          </div>
          <div
            style={{
              marginTop: '6px',
              color: colours.textMuted,
              fontSize: '11px',
              fontWeight: 400,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
            }}
          >
            by FINSIQ
          </div>
        </div>

        <form onSubmit={handleSubmit} style={{ padding: '24px' }}>
          {successMessage && (
            <div
              role="status"
              style={{
                marginBottom: '12px',
                color: colours.low,
                fontSize: '13px',
                lineHeight: 1.5,
              }}
            >
              {successMessage}
            </div>
          )}

          <div style={{ marginBottom: '16px' }}>
            <label htmlFor="login-email" style={fieldLabelStyle}>
              Email address
            </label>
            <input
              id="login-email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              onFocus={() => setFocusedField('email')}
              onBlur={() => setFocusedField('')}
              style={inputStyle('email')}
            />
          </div>

          <div>
            <label htmlFor="login-password" style={fieldLabelStyle}>
              Password
            </label>
            <input
              id="login-password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              onFocus={() => setFocusedField('password')}
              onBlur={() => setFocusedField('')}
              style={inputStyle('password')}
            />
          </div>

          {error && (
            <div
              role="alert"
              style={{
                marginTop: '8px',
                color: colours.critical,
                fontSize: '13px',
                lineHeight: 1.5,
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            onMouseEnter={() => setButtonHovered(true)}
            onMouseLeave={() => setButtonHovered(false)}
            style={{
              width: '100%',
              marginTop: '16px',
              padding: '12px',
              border: 'none',
              borderRadius: 0,
              background:
                buttonHovered && !loading ? colours.accentHover : colours.accent,
              color: '#FFFFFF',
              cursor: loading ? 'not-allowed' : 'pointer',
              fontFamily: "'Inter', sans-serif",
              fontSize: '14px',
              fontWeight: 500,
            }}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>

          <div
            style={{
              marginTop: '18px',
              color: colours.textMuted,
              fontSize: '12px',
              textAlign: 'center',
            }}
          >
            Need an analyst account?{' '}
            <Link
              to="/register"
              style={{
                color: colours.accent,
                fontWeight: 500,
                textDecoration: 'none',
              }}
            >
              Register
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}

export default Login;