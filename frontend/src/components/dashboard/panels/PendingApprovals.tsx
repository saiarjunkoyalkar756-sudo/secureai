import React, { useEffect, useState } from 'react';
import { CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react';
import { getApprovals, approveRequest, denyRequest } from '../../../lib/api';
import type { Approval } from '../../../lib/api';
import './PendingApprovals.css';

function riskColor(score: number) {
  if (score >= 70) return 'risk-high';
  if (score >= 30) return 'risk-med';
  return 'risk-low';
}

function timeAgo(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export const PendingApprovals: React.FC = () => {
  const [items, setItems] = useState<Approval[]>([]);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);

  useEffect(() => {
    getApprovals().then(r => { setItems(r.data); setLoading(false); });
  }, []);

  const handle = async (id: string, action: 'approve' | 'deny') => {
    setActing(id);
    try {
      if (action === 'approve') await approveRequest(id);
      else await denyRequest(id);
      setItems(prev => prev.filter(i => i.id !== id));
    } finally {
      setActing(null);
    }
  };

  return (
    <div className="approvals-panel">
      <div className="panel-header-row">
        <h2 className="panel-title">Pending Approvals</h2>
        <span className="panel-count">{items.length} pending</span>
      </div>

      {loading && <div className="panel-loading">Loading approvals…</div>}

      {!loading && items.length === 0 && (
        <div className="approvals-empty">
          <CheckCircle size={40} color="var(--dash-green)" />
          <p>No pending approvals — all clear.</p>
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="approvals-table-wrap">
          <table className="approvals-table">
            <thead>
              <tr>
                <th>Code Hash</th>
                <th>Language</th>
                <th>Submitted By</th>
                <th>Risk Score</th>
                <th>Time</th>
                <th>Preview</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map(item => (
                <tr key={item.id} className={acting === item.id ? 'row-acting' : ''}>
                  <td><span className="mono-sm">{item.codeHash}</span></td>
                  <td><span className="lang-badge">{item.language}</span></td>
                  <td><span className="actor-text">{item.submittedBy}</span></td>
                  <td>
                    <span className={`risk-badge ${riskColor(item.riskScore)}`}>
                      {item.riskScore >= 70 && <AlertTriangle size={11} />}
                      {item.riskScore}/100
                    </span>
                  </td>
                  <td>
                    <span className="time-text">
                      <Clock size={12} /> {timeAgo(item.submittedAt)}
                    </span>
                  </td>
                  <td>
                    <code className="code-snippet">{item.snippet.split('\n')[0]}</code>
                  </td>
                  <td>
                    <div className="action-btns">
                      <button
                        id={`approve-${item.id}`}
                        className="btn-approve"
                        disabled={!!acting}
                        onClick={() => handle(item.id, 'approve')}
                      >
                        <CheckCircle size={14} /> Approve
                      </button>
                      <button
                        id={`deny-${item.id}`}
                        className="btn-deny"
                        disabled={!!acting}
                        onClick={() => handle(item.id, 'deny')}
                      >
                        <XCircle size={14} /> Deny
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
