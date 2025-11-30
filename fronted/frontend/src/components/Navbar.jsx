import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <header className="hud-header">
      <div>
        <h1 className="glow-text">CYBER_GUARDIAN <span>v1.0</span></h1>
        {user && (
          <div style={{ fontSize: '0.7rem', color: '#00ff41', marginTop: '5px' }}>
             OPERATOR: {user.name} | STATUS: ONLINE
          </div>
        )}
      </div>
      
      <div className="nav-deck">
        {user ? (
          <>
            <button 
              className={location.pathname === '/dashboard' ? 'active' : ''} 
              onClick={() => navigate('/dashboard')}
            >
              HOME <span>(DASHBOARD)</span>
            </button>
            
            <button 
              className={location.pathname === '/about' ? 'active' : ''} 
              onClick={() => navigate('/about')}
            >
              ABOUT <span>(MISSION DATA)</span>
            </button>
            
            <button 
              onClick={handleLogout} 
              style={{ borderColor: '#ff3333', color: '#ff3333' }}
            >
              LOGOUT <span>(TERMINATE)</span>
            </button>
          </>
        ) : (
          <button className="active" style={{ cursor: 'default' }}>
            LOGIN <span>(AUTH REQUIRED)</span>
          </button>
        )}
      </div>
    </header>
  );
}