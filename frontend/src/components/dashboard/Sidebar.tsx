import React from 'react';
import { LayoutDashboard, ShieldAlert, ScrollText, Terminal, Key, Wifi, ArrowLeft, LogOut } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../lib/auth-context';
import './Sidebar.css';

export type DashTab = 'overview' | 'approvals' | 'audit-log' | 'playground' | 'api-keys';

interface SidebarProps {
  active: DashTab;
  onSelect: (tab: DashTab) => void;
}

const NAV_ITEMS: { id: DashTab; label: string; icon: React.ReactNode; badge?: number }[] = [
  { id: 'overview',   label: 'Overview',         icon: <LayoutDashboard size={18} /> },
  { id: 'approvals',  label: 'Pending Approvals', icon: <ShieldAlert size={18} />,  badge: 4 },
  { id: 'audit-log',  label: 'Audit Log',         icon: <ScrollText size={18} /> },
  { id: 'playground', label: 'Playground',        icon: <Terminal size={18} /> },
  { id: 'api-keys',   label: 'API Keys',          icon: <Key size={18} /> },
];

export const Sidebar: React.FC<SidebarProps> = ({ active, onSelect }) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <aside className="dash-sidebar">
      <div className="dash-sidebar__logo">
        <div className="dash-sidebar__logo-icon">
          <ShieldAlert size={20} color="#818cf8" />
        </div>
        <div>
          <div className="dash-sidebar__brand">SecureAI</div>
          <div className="dash-sidebar__sub">Security Console</div>
        </div>
      </div>

      <nav className="dash-sidebar__nav">
        {NAV_ITEMS.map(item => (
          <button
            key={item.id}
            id={`sidebar-${item.id}`}
            className={`dash-sidebar__item ${active === item.id ? 'active' : ''}`}
            onClick={() => onSelect(item.id)}
          >
            <span className="dash-sidebar__item-icon">{item.icon}</span>
            <span className="dash-sidebar__item-label">{item.label}</span>
            {item.badge !== undefined && (
              <span className="dash-sidebar__badge">{item.badge}</span>
            )}
          </button>
        ))}
      </nav>

      <div className="dash-sidebar__footer">
        {user && (
          <div className="dash-sidebar__user">
            <div className="dash-sidebar__user-avatar">
              {user.email.charAt(0).toUpperCase()}
            </div>
            <div className="dash-sidebar__user-info">
              <div className="dash-sidebar__user-email">{user.email}</div>
              <div className="dash-sidebar__user-role">{user.role}</div>
            </div>
            <button onClick={handleLogout} className="dash-sidebar__logout" title="Sign out" id="sidebar-logout">
              <LogOut size={15} />
            </button>
          </div>
        )}
        <Link to="/" className="dash-sidebar__back" id="sidebar-back-home">
          <ArrowLeft size={14} />
          <span>Back to Homepage</span>
        </Link>
        <div className="dash-sidebar__status">
          <><Wifi size={13} className="status-icon live" /> <span className="live">Live Data</span></>
        </div>
      </div>
    </aside>
  );
};
