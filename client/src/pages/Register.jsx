import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import api from '../api/axiosConfig';
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

function Register() {
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [focusedField, setFocusedField] = useState('');
  const [buttonHovered, setButtonHovered] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

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
      await api.post('/api/auth/register', {
        username: username.trim(),
        email: email.trim(),
        password,
      });

      navigate('/login', {
        replace: true,
        state: { message: 'Account created. Please sign in.' },
      });
    } catch (requestError) {
      const status = requestError?.response?.status;

      if (status === 409) {
        setError('Username or email already in use.');
      } else if (status === 429) {
        setError('Too many registration attempts. Please try again later.');
      } else if (status === 422) {
        setError(extractApiError(requestError, 'Please check your details and try again.'));
      } else {
        setError(
          extractApiError(requestError, 'Registration failed. Please try again.'),
        );
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
            Analyst Registration
          </div>
        </div>

        <form onSubmit={handleSubmit} style={{ padding: '24px' }}>
          <div style={{ marginBottom: '16px' }}>
            <label htmlFor="register-username" style={fieldLabelStyle}>
              Username
            </label>
            <input
              id="register-username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              onFocus={() => setFocusedField('username')}
              onBlur={() => setFocusedField('')}
              style={inputStyle('username')}
            />
          </div>

          <div style={{ marginBottom: '16px' }}>
            <label htmlFor="register-email" style={fieldLabelStyle}>
              Email
            </label>
            <input
              id="register-email"
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
            <label htmlFor="register-password" style={fieldLabelStyle}>
              Password
            </label>
            <input
              id="register-password"
              type="password"
              autoComplete="new-password"
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
            {loading ? 'Creating account...' : 'Create Account'}
          </button>

          <div
            style={{
              marginTop: '18px',
              color: colours.textMuted,
              fontSize: '12px',
              textAlign: 'center',
            }}
          >
            Already registered?{' '}
            <Link
              to="/login"
              style={{
                color: colours.accent,
                fontWeight: 500,
                textDecoration: 'none',
              }}
            >
              Sign in
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}

export default Register;