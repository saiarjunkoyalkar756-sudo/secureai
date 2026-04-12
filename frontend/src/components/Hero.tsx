import React from 'react';
import { Button } from './ui/Button';
import { Badge } from './ui/Badge';
import { TerminalMock } from './TerminalMock';
import { ChevronRight, ShieldCheck } from 'lucide-react';
import './Hero.css';

interface HeroProps {
  onCtaClick: () => void;
}

export const Hero: React.FC<HeroProps> = ({ onCtaClick }) => {
  return (
    <section className="hero-section">
      <div className="hero-container">
        <div className="hero-content">
          <Badge variant="info" className="mb-6 animate-fade-in">
            <span className="flex-align gap-2">
              <span className="pulse-dot"></span> 
              v1.0.0 Now Available
            </span>
          </Badge>
          
          <h1 className="hero-title animate-slide-up">
            Execute AI-Generated Code <br />
            <span className="text-gradient-accent">Without the Risk.</span>
          </h1>
          
          <p className="hero-subtitle animate-slide-up-delayed">
            The enterprise-grade sandbox platform for teams building with AI agents. 
            Stop worrying about dropped databases and leaked secrets.
          </p>
          
          <div className="hero-actions animate-slide-up-delayed-2">
            <Button size="lg" icon={<ChevronRight size={20} />} onClick={onCtaClick}>
              Start Sandboxing
            </Button>
            <Button variant="secondary" size="lg" icon={<ShieldCheck size={20} />}>
              Read Security Whitepaper
            </Button>
          </div>
          
          <div className="hero-proof animate-fade-in-delayed">
            Built for teams who can't afford to trust blindly.
          </div>
        </div>
        
        <div className="hero-visual animate-float">
          <div className="glow-backdrop"></div>
          <TerminalMock />
        </div>
      </div>
    </section>
  );
};
