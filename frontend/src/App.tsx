import { Hero } from './components/Hero'
import { Features } from './components/Features'
import { Playground } from './components/Playground'
import { Pricing } from './components/Pricing'
import { ShieldAlert } from 'lucide-react'
import './index.css'

function App() {
  return (
    <>
      <nav style={{ padding: '24px 40px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--glass-border)', background: 'var(--bg-secondary)', position: 'sticky', top: 0, zIndex: 100 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 'bold', fontSize: '1.2rem', color: 'var(--text-primary)' }}>
          <ShieldAlert className="text-accent" color="#6366F1" /> SecureAI
        </div>
        <div style={{ display: 'flex', gap: '24px', color: 'var(--text-secondary)', fontSize: '0.9rem', fontWeight: 500 }}>
          <a href="#features" style={{ textDecoration: 'none', color: 'inherit' }}>Features</a>
          <a href="#playground" style={{ textDecoration: 'none', color: 'inherit' }}>Playground</a>
          <a href="#pricing" style={{ textDecoration: 'none', color: 'inherit' }}>Pricing</a>
        </div>
      </nav>

      <main>
        <Hero />
        <Features />
        <Playground />
        <Pricing />
      </main>

      <footer style={{ padding: '60px 24px', textAlign: 'center', borderTop: '1px solid var(--glass-border)', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
        <p>&copy; 2026 SecureAI. Build safely.</p>
      </footer>
    </>
  )
}

export default App
