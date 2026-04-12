import { Hero } from '../components/Hero';
import { Features } from '../components/Features';
import { Playground } from '../components/Playground';
import { Pricing } from '../components/Pricing';
import { WaitlistModal } from '../components/WaitlistModal';
import { ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '../lib/auth-context';
import { useState } from 'react';
import '../components/Landing.css';

export const LandingPage = () => {
  const { isAuthenticated } = useAuth();
  const [isWaitlistOpen, setIsWaitlistOpen] = useState(false);
  const [selectedTier, setSelectedTier] = useState('Free');

  const openWaitlist = (tier: string = 'Free') => {
    setSelectedTier(tier);
    setIsWaitlistOpen(true);
  };

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
              <button 
                onClick={() => openWaitlist('Free')} 
                className="landing-nav__cta" 
                id="nav-signup-link"
              >
                Get Started →
              </button>
            </>
          )}
        </div>
      </nav>

      <main>
        <Hero onCtaClick={() => openWaitlist('Free')} />
        <Features />
        <Playground />
        <Pricing onPlanSelect={openWaitlist} />
      </main>

      <WaitlistModal 
        isOpen={isWaitlistOpen} 
        onClose={() => setIsWaitlistOpen(false)} 
        selectedTier={selectedTier} 
      />

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
