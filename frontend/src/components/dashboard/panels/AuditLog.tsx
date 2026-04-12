import React, { useEffect, useState, useRef, useCallback } from 'react';
import { RefreshCw } from 'lucide-react';
import { getAuditLogs } from '../../../lib/api';
import type { AuditEvent } from '../../../lib/api';
import './AuditLog.css';

const EVENT_COLORS: Record<AuditEvent['eventType'], string> = {
  EXECUTION:   'evt-cyan',
  BLOCKED:     'evt-red',
  KEY_CREATED: 'evt-green',
  KEY_REVOKED: 'evt-amber',
  LOGIN:       'evt-gray',
  DENIED:      'evt-red',
};

type FilterType = 'all' | 'BLOCKED' | 'EXECUTION' | 'KEY_CREATED' | 'KEY_REVOKED';

function formatTs(iso: string) {
  return new Date(iso).toISOString().replace('T',' ').replace('Z','').slice(0,19);
}

export const AuditLog: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [filter, setFilter] = useState<FilterType>('all');
  const [isLive, setIsLive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refresh = useCallback(() => setTick(t => t + 1), []);

  // Fetch data on mount and whenever tick changes (manual refresh or interval)
  useEffect(() => {
    let cancelled = false;
    getAuditLogs().then(res => {
      if (cancelled) return;
      setEvents(res.data);
      setIsLive(res.live);
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [tick]);

  // Auto-refresh every 15 seconds
  useEffect(() => {
    intervalRef.current = setInterval(refresh, 15000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [refresh]);

  const filtered = filter === 'all' ? events : events.filter(e => e.eventType === filter);

  return (
    <div className="audit-panel">
      <div className="panel-header-row">
        <h2 className="panel-title">
          Audit Log
          <span className={`live-dot ${isLive ? 'pulsing' : ''}`} />
          {isLive ? 'Live' : 'Mock'}
        </h2>
        <button id="audit-refresh-btn" className="refresh-btn" onClick={refresh}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      <div className="audit-filters">
        {(['all','BLOCKED','EXECUTION','KEY_CREATED','KEY_REVOKED'] as FilterType[]).map(f => (
          <button
            key={f}
            id={`audit-filter-${f}`}
            className={`filter-pill ${filter === f ? 'active' : ''}`}
            onClick={() => setFilter(f)}
          >
            {f === 'all' ? 'All Events' : f.replace('_',' ')}
          </button>
        ))}
      </div>

      {loading && <div className="panel-loading">Loading audit log…</div>}

      {!loading && (
        <div className="audit-feed">
          {filtered.map(evt => (
            <div key={evt.id} className="audit-row">
              <span className="audit-ts">{formatTs(evt.timestamp)}</span>
              <span className={`audit-type ${EVENT_COLORS[evt.eventType]}`}>{evt.eventType}</span>
              <span className="audit-actor">{evt.actor}</span>
              <span className="audit-resource">{evt.resource}</span>
              <span className="audit-ip">{evt.ip}</span>
              <span className="audit-org">{evt.orgId}</span>
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="audit-empty">No events match this filter.</div>
          )}
        </div>
      )}
    </div>
  );
};
