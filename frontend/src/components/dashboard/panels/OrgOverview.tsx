import React, { useEffect, useState } from 'react';
import { TrendingUp, TrendingDown, Zap, ShieldOff, Key, ScrollText } from 'lucide-react';
import { getOrgStats } from '../../../lib/api';
import type { OrgStats } from '../../../lib/api';
import './OrgOverview.css';

function StatCard({ label, value, delta, icon, color }: {
  label: string; value: number; delta: number; icon: React.ReactNode; color: string;
}) {
  const positive = delta >= 0;
  return (
    <div className="stat-card">
      <div className="stat-card__icon" style={{ color }}>{icon}</div>
      <div className="stat-card__value">{value.toLocaleString()}</div>
      <div className="stat-card__label">{label}</div>
      <div className={`stat-card__delta ${positive ? 'up' : 'down'}`}>
        {positive ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
        {Math.abs(delta)}% this week
      </div>
    </div>
  );
}

export const OrgOverview: React.FC = () => {
  const [stats, setStats] = useState<OrgStats | null>(null);

  useEffect(() => {
    getOrgStats().then(r => setStats(r.data));
  }, []);

  if (!stats) return <div className="panel-loading">Loading overview…</div>;

  const usedPct = Math.round((stats.executionUsed / stats.executionQuota) * 100);

  return (
    <div className="overview-panel">
      <h2 className="panel-title">Organization Overview</h2>

      <div className="stat-grid">
        <StatCard label="Total Executions" value={stats.totalExecutions} delta={stats.executionDelta} icon={<Zap size={20} />} color="var(--dash-cyan)" />
        <StatCard label="Blocked Threats" value={stats.blockedThreats} delta={stats.blockedDelta} icon={<ShieldOff size={20} />} color="var(--dash-red)" />
        <StatCard label="Active API Keys" value={stats.activeApiKeys} delta={0} icon={<Key size={20} />} color="var(--dash-amber)" />
        <StatCard label="Audit Events" value={stats.auditEvents} delta={8} icon={<ScrollText size={20} />} color="var(--dash-green)" />
      </div>

      <div className="quota-section">
        <div className="quota-header">
          <span className="quota-label">Execution Quota</span>
          <span className="quota-numbers">
            <span className="quota-used">{stats.executionUsed.toLocaleString()}</span>
            <span className="quota-sep"> / </span>
            <span className="quota-total">{stats.executionQuota.toLocaleString()}</span>
          </span>
        </div>
        <div className="quota-bar-track">
          <div
            className="quota-bar-fill"
            style={{
              width: `${usedPct}%`,
              background: usedPct > 85 ? 'var(--dash-red)' : usedPct > 65 ? 'var(--dash-amber)' : 'var(--dash-cyan)',
            }}
          />
        </div>
        <div className="quota-pct">{usedPct}% used</div>
      </div>

      <div className="sparkline-section">
        <div className="sparkline-header">Execution Activity — Last 7 Days</div>
        <div className="sparkline-bars">
          {[38, 55, 42, 70, 61, 88, 74].map((h, i) => (
            <div key={i} className="sparkline-col">
              <div className="sparkline-bar" style={{ height: `${h}%` }} />
              <div className="sparkline-day">{['M','T','W','T','F','S','S'][i]}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
