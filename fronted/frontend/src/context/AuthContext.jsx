import { createContext, useState, useContext } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem('cyber_user');
    return savedUser ? JSON.parse(savedUser) : null;
  });

  // Initial Logs
  const [globalLogs, setGlobalLogs] = useState([
    `[${new Date().toLocaleTimeString('en-US', {hour12:false})}] SYSTEM: Security Console Initialized.`,
    `[${new Date().toLocaleTimeString('en-US', {hour12:false})}] SYSTEM: Awaiting log data stream...`
  ]);

  const [globalThreats, setGlobalThreats] = useState([]);

  const login = (username) => {
    const userData = { name: username, role: 'COMMANDER' };
    setUser(userData);
    localStorage.setItem('cyber_user', JSON.stringify(userData));
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('cyber_user');
  };

  // --- FIX: APPEND TO END (Bottom) INSTEAD OF TOP ---
  const addLog = (message, sender="OPERATOR") => {
    const time = new Date().toLocaleTimeString('en-US', {hour12:false});
    const newLog = `[${time}] ${sender}: ${message}`;
    
    setGlobalLogs(prev => [...prev, newLog]); // <--- This makes it flow Top-to-Bottom
  };

  const addThreat = (threatData, originalLogText) => {
    const time = new Date().toLocaleTimeString('en-US', {hour12:false});
    // Threats also go Top-to-Bottom in the feed list
    setGlobalThreats(prev => [...prev, {
      time,
      type: threatData.threat_name || "ANOMALY DETECTED",
      severity: threatData.severity,
      fix: threatData.fix,
      log_content: originalLogText
    }]);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, globalLogs, addLog, globalThreats, addThreat }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);