import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldAlert, ArrowRight, Loader2, Copy, CheckCircle } from 'lucide-react';
import { useAuth } from '../lib/auth-context';
import './Auth.css';

export const SignupPage: React.FC = () => {
  const { signup, login } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [orgName, setOrgName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [generatedKey, setGeneratedKey] = useState('');
  const [copied, setCopied] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!email.trim() || !orgName.trim()) {
      setError('Please fill in all fields');
      return;
    }

    setLoading(true);
    const result = await signup(email.trim(), orgName.trim());
    setLoading(false);

    if (result.success && result.apiKey) {
      setGeneratedKey(result.apiKey);
    } else {
      setError(result.error || 'Registration failed');
    }
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(generatedKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleContinue = async () => {
    await login(email, generatedKey);
    navigate('/dashboard');
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
          <h1 className="auth-title">Create your account</h1>
          <p className="auth-subtitle">Start sandboxing AI code in minutes</p>
        </div>

        {!generatedKey ? (
          <form onSubmit={handleSubmit} className="auth-form">
            <div className="auth-field">
              <label htmlFor="signup-email" className="auth-label">Work Email</label>
              <input
                id="signup-email"
                type="email"
                className="auth-input"
                placeholder="you@company.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                autoComplete="email"
                autoFocus
              />
            </div>

            <div className="auth-field">
              <label htmlFor="signup-org" className="auth-label">Organization Name</label>
              <input
                id="signup-org"
                type="text"
                className="auth-input"
                placeholder="Acme Inc."
                value={orgName}
                onChange={e => setOrgName(e.target.value)}
              />
            </div>

            {error && (
              <div className="auth-error" role="alert">
                {error}
              </div>
            )}

            <button
              type="submit"
              id="signup-submit"
              className="auth-submit"
              disabled={loading}
            >
              {loading ? (
                <><Loader2 size={16} className="spin" /> Creating Account…</>
              ) : (
                <>Create Account <ArrowRight size={16} /></>
              )}
            </button>
          </form>
        ) : (
          <div className="auth-key-reveal">
            <div className="auth-key-reveal__icon">
              <CheckCircle size={32} color="var(--dash-green)" />
            </div>
            <h3 className="auth-key-reveal__title">Your API Key</h3>
            <p className="auth-key-reveal__desc">Copy this now — it won't be shown again.</p>
            
            <div className="auth-key-reveal__box">
              <code>{generatedKey}</code>
              <button onClick={handleCopy} className="auth-key-reveal__copy">
                {copied ? <><CheckCircle size={14} /> Copied!</> : <><Copy size={14} /> Copy</>}
              </button>
            </div>

            <button
              onClick={handleContinue}
              className="auth-submit"
              id="signup-continue"
            >
              Continue to Dashboard <ArrowRight size={16} />
            </button>
          </div>
        )}

        <div className="auth-footer">
          <p>Already have an account? <Link to="/login" className="auth-link">Sign in</Link></p>
        </div>
      </div>
    </div>
  );
};
