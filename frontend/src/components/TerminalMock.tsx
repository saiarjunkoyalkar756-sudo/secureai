import React, { useState, useEffect } from 'react';
import './Terminal.css';
import { Terminal as TerminalIcon, ShieldAlert } from 'lucide-react';

export const TerminalMock: React.FC = () => {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const sequence = [
      () => setStep(1), // Show typing
      () => setStep(2), // Show command
      () => setStep(3)  // Show blocked
    ];
    
    const delays = [1000, 2500, 3500];
    const timers = delays.map((d, i) => setTimeout(sequence[i], d));
    
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="terminal-window glass-panel">
      <div className="terminal-header">
        <div className="terminal-dots">
          <span className="dot dot-red"></span>
          <span className="dot dot-yellow"></span>
          <span className="dot dot-green"></span>
        </div>
        <div className="terminal-title">
          <TerminalIcon size={14} /> secureai-sandbox
        </div>
      </div>
      <div className="terminal-content">
        <div className="terminal-line">
          <span className="terminal-prompt">admin@secureai:~$</span> 
          <span className="terminal-command">
            {step === 0 && <span className="cursor blink"></span>}
            {step >= 1 && "curl -X POST /v1/execute \\"}
          </span>
        </div>
        
        {step >= 1 && (
          <div className="terminal-line indent">
            <span className="terminal-command">
              -d '{`{"code": "require('child_process').exec('rm -rf /')"}`}'
              {step === 1 && <span className="cursor blink"></span>}
            </span>
          </div>
        )}

        {step >= 2 && (
          <div className="terminal-line mt-4">
            <span className="terminal-output muted">Analyzing static payload...</span>
          </div>
        )}

        {step >= 3 && (
          <div className="terminal-line mt-2 text-danger flex-align">
            <ShieldAlert size={16} className="mr-2" />
            <span className="font-bold">[ERR_THREAT_DETECTED]</span> &nbsp;Execution explicitly blocked.
          </div>
        )}
        
        {step >= 3 && (
          <div className="terminal-line mt-1 indent text-danger-muted">
            Pattern matching flagged rule: "destructive_command" (Risk Score: 80)
          </div>
        )}
      </div>
    </div>
  );
};
