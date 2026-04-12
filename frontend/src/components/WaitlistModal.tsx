import React, { useState } from 'react';
import { X, Loader2, CheckCircle } from 'lucide-react';
import { Button } from './ui/Button';
import './WaitlistModal.css';

interface WaitlistModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedTier: string;
}

export const WaitlistModal: React.FC<WaitlistModalProps> = ({ isOpen, onClose, selectedTier }) => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'https://secureai-production-bf5b.up.railway.app';
      const res = await fetch(`${apiUrl}/v1/waitlist`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, tier: selectedTier })
      });

      if (!res.ok) throw new Error('Failed to join waitlist');
      
      setSuccess(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content animate-scale-in" onClick={e => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>
          <X size={20} />
        </button>

        {!success ? (
          <>
            <h2 className="modal-title">Join the <span className="text-gradient">{selectedTier}</span> Waitlist</h2>
            <p className="modal-description">
              SecureAI is currently in early access. Enter your email to secure your spot in the queue for the {selectedTier} tier.
            </p>

            <form onSubmit={handleSubmit} className="modal-form">
              <input
                type="email"
                placeholder="you@company.com"
                className="modal-input"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoFocus
              />
              {error && <p className="modal-error">{error}</p>}
              <Button 
                type="submit" 
                className="w-full" 
                disabled={loading}
                icon={loading ? <Loader2 className="animate-spin" size={18} /> : null}
              >
                {loading ? 'Joining...' : 'Secure My Spot'}
              </Button>
            </form>
          </>
        ) : (
          <div className="modal-success animate-fade-in">
            <CheckCircle size={64} className="text-success mb-6" />
            <h2 className="modal-title">You're on the list!</h2>
            <p className="modal-description">
              We've sent a confirmation email to <strong>{email}</strong>. We'll reach out as soon as a spot opens up for you.
            </p>
            <Button variant="secondary" onClick={onClose} className="w-full">
              Close
            </Button>
          </div>
        )}
      </div>
    </div>
  );
};
