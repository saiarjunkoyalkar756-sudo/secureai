import React from 'react';
import { Card } from './ui/Card';
import { Shield, Server, Box, Activity, Lock, Search } from 'lucide-react';
import './Features.css';

const featureList = [
  {
    icon: <Box size={24} className="text-accent" />,
    title: "Multi-layer Sandboxing",
    description: "Code runs fully isolated in a restricted compute environment with truncated stdout and hard memory caps."
  },
  {
    icon: <Shield size={24} className="text-accent" />,
    title: "SOC2 Ready Logging",
    description: "Cryptographically chained, immutable audit logs containing granular execution tracing for every API request."
  },
  {
    icon: <Lock size={24} className="text-accent" />,
    title: "Permission Workflows",
    description: "Require human-in-the-loop admin approval before any potentially dangerous code snippet is allowed to execute."
  },
  {
    icon: <Search size={24} className="text-accent" />,
    title: "Static Threat Analysis",
    description: "Regex pattern-matching catches destructive reverse-shells, fork bombs, and root-level commands instantly."
  },
  {
    icon: <Server size={24} className="text-accent" />,
    title: "Multi-Language Support",
    description: "Execute Python, Node.js, Go, and Bash natively without rewriting standard machine-tooling pipelines."
  },
  {
    icon: <Activity size={24} className="text-accent" />,
    title: "HIPAA Compliant",
    description: "Built-in middleware automatically masks Phone Numbers, SSNs, and Credit Cards from API responses."
  }
];

export const Features: React.FC = () => {
  return (
    <section className="features-section" id="features">
      <div className="section-header">
        <h2 className="section-title">Everything you need to <span className="text-gradient">build safely.</span></h2>
        <p className="section-subtitle">A comprehensive security layer sitting between your LLM outputs and your servers.</p>
      </div>
      
      <div className="features-grid">
        {featureList.map((f, i) => (
          <Card key={i} className="feature-card relative-hover">
            <div className="feature-icon-wrapper">
              {f.icon}
            </div>
            <h3 className="feature-title">{f.title}</h3>
            <p className="feature-description">{f.description}</p>
          </Card>
        ))}
      </div>
    </section>
  );
};
