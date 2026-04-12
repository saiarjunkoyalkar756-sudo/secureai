import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldAlert, Eye, EyeOff, ArrowRight, Loader2 } from 'lucide-react';
import { useAuth } from '../lib/auth-context';
import './Auth.css';

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!email.trim() || !apiKey.trim()) {
      setError('Please fill in all fields');
      return;
    }

    setLoading(true);
    const result = await login(email.trim(), apiKey.trim());
    setLoading(false);

    if (result.success) {
      navigate('/dashboard');
    } else {
      setError(result.error || 'Authentication failed');
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-glow auth-glow--1" />
      <div className="auth-glow auth-glow--2" />

      <div className="auth-card">
        <div className="auth-card__header">
          <Link to="/" className="auth-logo">
            <ShieldAlert size={28} color="#818cf8" />
            <span>SecureAI</span>
          </Link>
          <h1 className="auth-title">Welcome back</h1>
          <p className="auth-subtitle">Sign in to the Security Console</p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="auth-field">
            <label htmlFor="login-email" className="auth-label">Email</label>
            <input
              id="login-email"
              type="email"
              className="auth-input"
              placeholder="admin@company.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              autoComplete="email"
              autoFocus
            />
          </div>

          <div className="auth-field">
            <label htmlFor="login-apikey" className="auth-label">API Key</label>
            <div className="auth-input-wrap">
              <input
                id="login-apikey"
                type={showKey ? 'text' : 'password'}
                className="auth-input auth-input--key"
                placeholder="sk_live_••••••••••••"
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                autoComplete="current-password"
              />
              <button
                type="button"
                className="auth-eye"
                onClick={() => setShowKey(!showKey)}
                tabIndex={-1}
                aria-label={showKey ? 'Hide key' : 'Show key'}
              >
                {showKey ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {error && (
            <div className="auth-error" role="alert">
              {error}
            </div>
          )}

          <button
            type="submit"
            id="login-submit"
            className="auth-submit"
            disabled={loading}
          >
            {loading ? (
              <><Loader2 size={16} className="spin" /> Authenticating…</>
            ) : (
              <>Sign In <ArrowRight size={16} /></>
            )}
          </button>
        </form>

        <div className="auth-footer">
          <p>Don't have an account? <Link to="/signup" className="auth-link">Create one</Link></p>
        </div>

        <div className="auth-demo-hint">
          <p>Demo: use any email + key starting with <code>sk_</code></p>
        </div>
      </div>
    </div>
  );
};
