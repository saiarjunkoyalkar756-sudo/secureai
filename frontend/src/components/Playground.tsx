import React, { useState } from 'react';
import { Card } from './ui/Card';
import { Button } from './ui/Button';
import { Play, Loader2, AlertCircle } from 'lucide-react';
import './Playground.css';

export const Playground: React.FC = () => {
  const [code, setCode] = useState("console.log('Testing deep space backend connection...');");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const runCode = async () => {
    setLoading(true);
    setResult(null);
    try {
      // Connecting specifically to the live Railway backend the user deployed earlier
      const res = await fetch('https://secureai-production-bf5b.up.railway.app/v1/execute', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer sk_test_admin_123456' // Using the newly hashed seeded key
        },
        body: JSON.stringify({ code, language: 'node20' })
      });
      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setResult({ status: 'error', message: err.message || 'Network error reaching API.' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="playground-section" id="playground">
      <div className="section-header">
        <h2 className="section-title">Test the <span className="text-gradient">Sandbox</span> live.</h2>
        <p className="section-subtitle">Connected directly to the production API on Railway. Try throwing an `rm -rf` at it.</p>
      </div>

      <div className="playground-container">
        <Card className="playground-card" glow={true}>
          <div className="editor-header">
            <span>index.js</span>
            <div className="editor-actions">
              <Button size="sm" variant="primary" onClick={runCode} disabled={loading} icon={loading ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}>
                {loading ? 'Executing...' : 'Run Code'}
              </Button>
            </div>
          </div>
          
          <textarea 
            className="code-editor" 
            value={code} 
            onChange={e => setCode(e.target.value)}
            spellCheck="false"
          />

          {result && (
            <div className={`result-box result-${result.status}`}>
              <div className="result-header">
                {result.status === 'success' ? 'Execution Result:' : result.status === 'blocked' ? 'Threat Blocked:' : 'Error:'}
              </div>
              <pre className="result-content">
                {result.status === 'success' ? result.stdout || '(No Output)' : result.message}
              </pre>
              {result.riskScore !== undefined && (
                <div className="result-meta flex-align gap-2 mt-2">
                  <AlertCircle size={14} /> Risk Score: {result.riskScore}/100
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </section>
  );
};
