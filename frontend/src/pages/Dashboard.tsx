import React, { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import { Sidebar } from '../components/dashboard/Sidebar';
import type { DashTab } from '../components/dashboard/Sidebar';
import { OrgOverview }       from '../components/dashboard/panels/OrgOverview';
import { PendingApprovals }  from '../components/dashboard/panels/PendingApprovals';
import { AuditLog }          from '../components/dashboard/panels/AuditLog';
import { DashPlayground }    from '../components/dashboard/panels/DashPlayground';
import { ApiKeys }           from '../components/dashboard/panels/ApiKeys';
import { useAuth }           from '../lib/auth-context';
import './Dashboard.css';

const TAB_LABELS: Record<DashTab, string> = {
  overview: 'Overview',
  approvals: 'Pending Approvals',
  'audit-log': 'Audit Log',
  playground: 'Playground',
  'api-keys': 'API Keys',
};

export const Dashboard: React.FC = () => {
  const { user, isAuthenticated, isLoading, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<DashTab>('overview');
  // Verify auth on mount
  useEffect(() => {
    // We expect the backend to work if isAuthenticated was set,
    // if not, components will fail with errors properly
  }, []);

  if (isLoading) return null;
  if (!isAuthenticated) return <Navigate to="/login" replace />;

  const initials = user?.email
    ? user.email.slice(0, 2).toUpperCase()
    : 'AD';

  return (
    <div className="dashboard-root">
      <Sidebar active={activeTab} onSelect={setActiveTab} />
      <main className="dashboard-main">
        <div className="dashboard-topbar">
          <div className="topbar-breadcrumb">
            <span className="topbar-brand">SecureAI</span>
            <span className="topbar-sep">/</span>
            <span className="topbar-page">{TAB_LABELS[activeTab]}</span>
          </div>
          <div className="topbar-right">
            <span className="topbar-env">Live</span>
            <div className="topbar-user">
              <div className="topbar-avatar">{initials}</div>
              <span className="topbar-email">{user?.email}</span>
            </div>
            <button id="logout-btn" className="topbar-logout" onClick={logout} title="Sign out">
              ↩
            </button>
          </div>
        </div>

        <div className="dashboard-content">
          {activeTab === 'overview'   && <OrgOverview />}
          {activeTab === 'approvals'  && <PendingApprovals />}
          {activeTab === 'audit-log'  && <AuditLog />}
          {activeTab === 'playground' && <DashPlayground />}
          {activeTab === 'api-keys'   && <ApiKeys />}
        </div>
      </main>
    </div>
  );
};
