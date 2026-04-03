import React from 'react';
import { Card } from './ui/Card';
import { Button } from './ui/Button';
import { Check } from 'lucide-react';
import './Pricing.css';

const pricingPlans = [
  {
    name: "Beta Trial",
    price: "$1,250",
    period: "/mo",
    description: "Limited time beta pricing for early adopters.",
    features: [
      "50K executions / month",
      "Email support",
      "Basic audit logs",
      "3-month minimum commitment"
    ],
    buttonText: "Join Beta",
    variant: "secondary" as const,
    glow: false
  },
  {
    name: "Starter",
    price: "$2,500",
    period: "/mo",
    description: "For teams deploying their first AI agents into production.",
    features: [
      "50K executions / month",
      "Email support",
      "Advanced compliance reports",
      "SLA guarantees"
    ],
    buttonText: "Schedule Demo",
    variant: "primary" as const,
    glow: true,
    badge: "Most Popular"
  },
  {
    name: "Enterprise",
    price: "Custom",
    period: "",
    description: "For organizations running millions of automated workflows.",
    features: [
      "Unlimited executions",
      "Dedicated 24/7 support",
      "Custom sandbox integrations",
      "On-premise deployment options"
    ],
    buttonText: "Contact Sales",
    variant: "secondary" as const,
    glow: false
  }
];

export const Pricing: React.FC = () => {
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
            
            <Button variant={plan.variant} className="w-full mb-8">
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
