import React, { useState } from 'react';
import { Play, Loader2, AlertCircle, CheckCircle, XCircle, Clock, Cpu } from 'lucide-react';
import { executeCode } from '../../../lib/api';
import type { ExecResult } from '../../../lib/api';
import './DashPlayground.css';

const LANGUAGES = ['node20', 'python3'];

const HISTORY_DEFAULT: { code: string; lang: string; result: ExecResult }[] = [];

const STARTER: Record<string, string> = {
  node20: `// SecureAI Sandbox — node20\nconsole.log("Hello from the sandbox!");\nconsole.log("Process:", process.version);`,
  python3: `# SecureAI Sandbox — python3\nprint("Hello from the sandbox!")\nimport sys\nprint("Python:", sys.version)`,
};

export const DashPlayground: React.FC = () => {
  const [lang, setLang] = useState('node20');
  const [code, setCode] = useState(STARTER['node20']);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ExecResult | null>(null);
  const [history, setHistory] = useState(HISTORY_DEFAULT);

  const run = async () => {
    setLoading(true);
    setResult(null);
    const res = await executeCode(code, lang);
    setResult(res.data);
    setHistory(prev => [{ code, lang, result: res.data }, ...prev].slice(0, 5));
    setLoading(false);
  };

  const loadHistory = (item: typeof history[0]) => {
    setCode(item.code);
    setLang(item.lang);
    setResult(item.result);
  };

  return (
    <div className="dplay-panel">
      <div className="panel-header-row">
        <h2 className="panel-title">Code Playground</h2>
        <select
          id="dplay-lang-select"
          className="lang-select"
          value={lang}
          onChange={e => { setLang(e.target.value); setCode(STARTER[e.target.value] || ''); setResult(null); }}
        >
          {LANGUAGES.map(l => <option key={l} value={l}>{l}</option>)}
        </select>
      </div>

      <div className="dplay-layout">
        <div className="dplay-main">
          <div className="editor-chrome">
            <div className="editor-chrome__top">
              <div className="editor-dots">
                <span /><span /><span />
              </div>
              <span className="editor-filename">{lang === 'node20' ? 'index.js' : 'main.py'}</span>
              <button
                id="dplay-run-btn"
                className="run-btn"
                onClick={run}
                disabled={loading}
              >
                {loading
                  ? <><Loader2 size={14} className="spin" /> Running…</>
                  : <><Play size={14} /> Run Code</>
                }
              </button>
            </div>
            <div className="editor-line-wrap">
              <div className="editor-lines">
                {code.split('\n').map((_, i) => <div key={i}>{i + 1}</div>)}
              </div>
              <textarea
                id="dplay-code-editor"
                className="dplay-editor"
                value={code}
                onChange={e => setCode(e.target.value)}
                spellCheck={false}
                autoComplete="off"
              />
            </div>
          </div>

          {result && (
            <div className={`dplay-result result-${result.status}`}>
              <div className="dplay-result__header">
                {result.status === 'success' && <><CheckCircle size={14} /> Execution Successful</>}
                {result.status === 'blocked' && <><XCircle size={14} /> Threat Blocked</>}
                {result.status === 'error' && <><AlertCircle size={14} /> Error</>}
                <div className="result-meta">
                  {result.riskScore !== undefined && (
                    <span><AlertCircle size={12} /> Risk: <strong>{result.riskScore}/100</strong></span>
                  )}
                  {result.executionTime !== undefined && (
                    <span><Clock size={12} /> {result.executionTime}ms</span>
                  )}
                  {result.memoryUsed !== undefined && (
                    <span><Cpu size={12} /> {result.memoryUsed}MB</span>
                  )}
                </div>
              </div>
              <pre className="dplay-result__body">
                {result.status === 'success' ? (result.stdout || '(no output)') : (result.message || result.stderr || 'Unknown error')}
              </pre>
            </div>
          )}
        </div>

        {history.length > 0 && (
          <div className="dplay-history">
            <div className="history-title">Recent Runs</div>
            {history.map((item, i) => (
              <button
                key={i}
                className={`history-item status-${item.result.status}`}
                onClick={() => loadHistory(item)}
              >
                <span className="history-lang">{item.lang}</span>
                <span className="history-snippet">{item.code.split('\n')[0].slice(0, 40)}</span>
                <span className={`history-status ${item.result.status}`}>
                  {item.result.status}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
