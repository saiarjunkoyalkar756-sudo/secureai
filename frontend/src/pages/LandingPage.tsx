import { Hero }     from '../components/Hero';
import { Features }  from '../components/Features';
import { Playground } from '../components/Playground';
import { Pricing }   from '../components/Pricing';
import { ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '../lib/auth-context';
import '../components/Landing.css';

export const LandingPage = () => {
  const { isAuthenticated } = useAuth();

  return (
    <>
      <nav className="landing-nav">
        <div className="landing-nav__logo">
          <ShieldAlert className="text-accent" color="#6366F1" size={22} /> SecureAI
        </div>
        <div className="landing-nav__links">
          <a href="#features" className="landing-nav__link">Features</a>
          <a href="#playground" className="landing-nav__link">Playground</a>
          <a href="#pricing" className="landing-nav__link">Pricing</a>
          {isAuthenticated ? (
            <Link to="/dashboard" className="landing-nav__cta" id="nav-dashboard-link">
              Dashboard →
            </Link>
          ) : (
            <>
              <Link to="/login" className="landing-nav__link landing-nav__link--signin" id="nav-signin-link">
                Sign In
              </Link>
              <Link to="/signup" className="landing-nav__cta" id="nav-signup-link">
                Get Started →
              </Link>
            </>
          )}
        </div>
      </nav>

      <main>
        <Hero />
        <Features />
        <Playground />
        <Pricing />
      </main>

      <footer className="landing-footer">
        <div className="landing-footer__inner">
          <div className="landing-footer__brand">
            <ShieldAlert size={16} color="#6366F1" />
            <span>SecureAI</span>
          </div>
          <p>© 2026 SecureAI. Deploy AI agents with confidence.</p>
          <div className="landing-footer__links">
            <a href="https://github.com/saiarjunkoyalkar756-sudo/secureai" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="#features">Docs</a>
            <a href="#pricing">Pricing</a>
          </div>
        </div>
      </footer>
    </>
  );
};
