import React from 'react';
import { Card } from './ui/Card';
import { Button } from './ui/Button';
import { Check } from 'lucide-react';
import './Pricing.css';

interface PricingProps {
  onPlanSelect: (tier: string) => void;
}

const pricingPlans = [
  {
    name: "Free",
    price: "$0",
    period: "/mo",
    description: "Perfect for exploring SecureAI's core safety capabilities.",
    features: [
      "100 executions / month",
      "1 API key",
      "Community support",
      "Standard audit logs"
    ],
    buttonText: "Join Waitlist",
    variant: "secondary" as const,
    glow: false
  },
  {
    name: "Pro",
    price: "$49",
    period: "/mo",
    description: "For professional developers and scaling AI applications.",
    features: [
      "10,000 executions / month",
      "5 API keys",
      "Email support",
      "HITL Approvals",
      "Advanced compliance"
    ],
    buttonText: "Get Pro Access",
    variant: "primary" as const,
    glow: true,
    badge: "Best Value"
  },
  {
    name: "Enterprise",
    price: "Custom",
    period: "",
    description: "Industrial-grade security for teams running millions of jobs.",
    features: [
      "Unlimited executions",
      "SSO & Directory Sync",
      "SOC2 / HIPAA Reports",
      "Dedicated 24/7 SLA"
    ],
    buttonText: "Contact Sales",
    variant: "secondary" as const,
    glow: false
  }
];

export const Pricing: React.FC<PricingProps> = ({ onPlanSelect }) => {
  return (
    <section className="pricing-section" id="pricing">
      <div className="section-header">
        <h2 className="section-title">Transparent pricing for <br/> <span className="text-gradient">secure scaling.</span></h2>
      </div>
      
      <div className="pricing-grid">
        {pricingPlans.map((plan, i) => (
          <Card key={i} className={`pricing-card ${plan.glow ? 'pricing-highlight' : ''}`} glow={plan.glow}>
            {plan.badge && <div className="pricing-badge">{plan.badge}</div>}
            
            <h3 className="plan-name">{plan.name}</h3>
            <div className="plan-price-wrapper">
              <span className="plan-price">{plan.price}</span>
              <span className="plan-period">{plan.period}</span>
            </div>
            <p className="plan-description">{plan.description}</p>
            
            <Button 
              variant={plan.variant} 
              className="w-full mb-8"
              onClick={() => onPlanSelect(plan.name)}
            >
              {plan.buttonText}
            </Button>
            
            <ul className="plan-features">
              {plan.features.map((feat, j) => (
                <li key={j}>
                  <Check size={18} className="text-success" />
                  <span>{feat}</span>
                </li>
              ))}
            </ul>
          </Card>
        ))}
      </div>
    </section>
  );
};
