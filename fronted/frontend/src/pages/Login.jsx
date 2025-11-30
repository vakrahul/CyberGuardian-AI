import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    // Simulate network delay for "Hacker" feel
    setTimeout(() => {
      if (username === 'ADMIN_01' && password === 'admin123') {
        login(username);
        navigate('/dashboard');
      } else {
        setError('ACCESS DENIED: INVALID CREDENTIALS');
        setIsLoading(false);
      }
    }, 1000);
  };

  return (
    <div className="login-screen">
      <div className="login-box">
        <h2 className="glow-text">SECURE LOGIN</h2>
        
        <form onSubmit={handleLogin}>
          <div style={{marginBottom: '20px'}}>
            <label style={{display:'block', marginBottom:'5px', fontSize:'0.8rem', color:'#00ff41'}}>OPERATOR ID</label>
            <input 
              type="text" 
              placeholder="ENTER ID..." 
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={isLoading}
            />
          </div>

          <div style={{marginBottom: '30px'}}>
            <label style={{display:'block', marginBottom:'5px', fontSize:'0.8rem', color:'#00ff41'}}>ACCESS KEY</label>
            <input 
              type="password" 
              placeholder="••••••••" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isLoading}
            />
          </div>

          {error && (
            <div style={{
              color: '#ff3333', 
              textAlign: 'center', 
              marginBottom: '15px', 
              fontSize: '0.9rem', 
              border: '1px solid #ff3333',
              padding: '5px'
            }}>
              ⚠️ {error}
            </div>
          )}

          <button type="submit" disabled={isLoading}>
            {isLoading ? "AUTHENTICATING..." : "AUTHENTICATE"}
          </button>
        </form>
        
        <div style={{marginTop: '20px', textAlign: 'center', fontSize: '0.7rem', opacity: 0.6, color: '#00ff41'}}>
          * UNAUTHORIZED ACCESS IS A FEDERAL OFFENSE
        </div>
      </div>
    </div>
  );
}