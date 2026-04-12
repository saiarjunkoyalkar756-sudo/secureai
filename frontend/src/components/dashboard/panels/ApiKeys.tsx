import React, { useEffect, useState } from 'react';
import { Plus, Copy, Trash2, CheckCircle, Clock } from 'lucide-react';
import { getApiKeys, createApiKey, revokeApiKey } from '../../../lib/api';
import type { ApiKey } from '../../../lib/api';
import './ApiKeys.css';

function statusLabel(s: ApiKey['status']) {
  if (s === 'active')  return <span className="key-status status-active">Active</span>;
  if (s === 'expired') return <span className="key-status status-expired">Expired</span>;
  return <span className="key-status status-revoked">Revoked</span>;
}

function fmtDate(iso: string | null) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export const ApiKeys: React.FC = () => {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);

  useEffect(() => {
    getApiKeys().then(r => { setKeys(r.data); setLoading(false); });
  }, []);

  const handleCreate = async () => {
    if (!newName.trim()) return;
    setCreating(true);
    const res = await createApiKey(newName.trim());
    setKeys(prev => [res.data, ...prev]);
    setNewSecret(res.data.secret || null);
    setNewName('');
    setCreating(false);
  };

  const handleCopy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRevoke = async (id: string) => {
    setRevoking(id);
    await revokeApiKey(id);
    setKeys(prev => prev.map(k => k.id === id ? { ...k, status: 'revoked' as const } : k));
    setRevoking(null);
    setConfirmRevoke(null);
  };

  return (
    <div className="apikeys-panel">
      <div className="panel-header-row">
        <h2 className="panel-title">API Keys</h2>
        <button id="create-key-btn" className="create-key-btn" onClick={() => setNewSecret(null)}>
          <Plus size={14} /> New Key
        </button>
      </div>

      {/* Create form */}
      <div className="create-form">
        <input
          id="new-key-name-input"
          className="key-name-input"
          placeholder="Key name (e.g. Production Agent)"
          value={newName}
          onChange={e => setNewName(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleCreate()}
        />
        <button
          id="create-key-submit"
          className="create-btn"
          disabled={creating || !newName.trim()}
          onClick={handleCreate}
        >
          {creating ? 'Creating…' : 'Create'}
        </button>
      </div>

      {newSecret && (
        <div className="secret-reveal">
          <CheckCircle size={14} color="var(--dash-green)" />
          <span>Key created — copy it now, it won't be shown again:</span>
          <code className="secret-value">{newSecret}</code>
          <button className="copy-btn" onClick={() => handleCopy(newSecret)}>
            {copied ? <CheckCircle size={13} /> : <Copy size={13} />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
      )}

      {loading && <div className="panel-loading">Loading API keys…</div>}

      {!loading && (
        <div className="keys-table-wrap">
          <table className="keys-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Key Prefix</th>
                <th>Created</th>
                <th>Last Used</th>
                <th>Expires</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map(key => (
                <tr key={key.id} className={key.status !== 'active' ? 'row-inactive' : ''}>
                  <td className="key-name">{key.name}</td>
                  <td>
                    <span className="key-prefix">
                      {key.prefix}••••••••
                      {key.status === 'active' && (
                        <button className="inline-copy" onClick={() => handleCopy(key.prefix)} title="Copy prefix">
                          <Copy size={11} />
                        </button>
                      )}
                    </span>
                  </td>
                  <td className="meta-cell"><Clock size={11} /> {fmtDate(key.createdAt)}</td>
                  <td className="meta-cell">{fmtDate(key.lastUsed)}</td>
                  <td className="meta-cell">{fmtDate(key.expiresAt)}</td>
                  <td>{statusLabel(key.status)}</td>
                  <td>
                    {key.status === 'active' && (
                      confirmRevoke === key.id ? (
                        <div className="confirm-row">
                          <span className="confirm-text">Revoke?</span>
                          <button className="btn-confirm-yes" onClick={() => handleRevoke(key.id)} disabled={revoking === key.id}>Yes</button>
                          <button className="btn-confirm-no" onClick={() => setConfirmRevoke(null)}>No</button>
                        </div>
                      ) : (
                        <button
                          id={`revoke-${key.id}`}
                          className="revoke-btn"
                          onClick={() => setConfirmRevoke(key.id)}
                        >
                          <Trash2 size={13} /> Revoke
                        </button>
                      )
                    )}
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
