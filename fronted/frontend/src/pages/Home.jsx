import { useState, useEffect, Suspense } from 'react';
import CyberScene from '../components/CyberModel';
import { useAuth } from '../context/AuthContext'; 

export default function Home() {
  const { addLog, addThreat } = useAuth(); 
  const [logInput, setLogInput] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [decodeText, setDecodeText] = useState('');

  useEffect(() => {
    if (loading) {
      const messages = ["Initializing Vector Search...", "Parsing Log Syntax...", "Connecting to Cosdata Node..."];
      let i = 0;
      const interval = setInterval(() => {
        setDecodeText(messages[i % messages.length] + ` [${Math.random().toFixed(5)}]`);
        i++;
      }, 150);
      return () => clearInterval(interval);
    }
  }, [loading]);

  const handleAnalyze = async () => {
    if (!logInput) return;
    setLoading(true);
    setResult(null);

    addLog(`Initiating scan on log segment...`, "SYSTEM");

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch('http://127.0.0.1:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: logInput }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      const data = await response.json();
      setResult(data);

      if (data.detected) {
        // --- UPDATED: PASS THE LOG INPUT TO MEMORY ---
        addThreat(data, logInput); 
        addLog(`THREAT DETECTED: ${data.threat_name}`, "AI_CORE");
      } else {
        addLog(`Scan complete. System Secure.`, "AI_CORE");
      }

    } catch (error) {
      setResult({ error: "CONNECTION FAILURE: Backend Offline" });
      addLog(`Scan failed: Connection Refused`, "ERROR");
    }
    
    setLoading(false);
  };

  return (
    <div className="main-dashboard" style={{border:'none', height:'100%', padding:0}}>
      <div className="frame-label">MAIN DASHBOARD</div>
      <div className="grid-layout">
        
        {/* LEFT PANEL */}
        <div className="subject-viewer" style={{justifyContent: 'center', alignItems: 'center'}}>
          <div className="panel-title" style={{alignSelf: 'flex-start'}}>// SUBJECT_VIEWER</div>
          <div className="model-container" style={{width: '100%', height: '100%'}}>
            <Suspense fallback={<div style={{padding:'20px', color:'#00ff41'}}>LOADING ASSETS...</div>}>
               <CyberScene />
            </Suspense>
          </div>
        </div>

        {/* RIGHT PANEL */}
        <div className="ops-panel">
          <div className="logs-container">
            <div className="panel-title">// INPUT_SERVER_LOGS</div>
            <textarea 
              placeholder="> AWAITING LOG INPUT..."
              value={logInput}
              onChange={(e) => setLogInput(e.target.value)}
            />
            {result && (
              <div style={{marginTop:'15px', borderTop:'1px dashed #00ff41', paddingTop:'15px', color: result.detected ? '#ff3333' : '#00ff41', fontFamily: 'monospace'}}>
                {result.error ? <h3 style={{color:'red'}}>❌ {result.error}</h3> : (
                  <>
                    <h3 style={{margin:0}}>{result.detected ? `🚨 THREAT DETECTED: ${result.severity}` : "✅ SYSTEM SECURE"}</h3>
                    <p style={{margin:'5px 0', color: '#ccc'}}>SIGNATURE: {result.threat_name}</p>
                    {result.fix && <div style={{background:'rgba(0,0,0,0.5)', padding:'10px', borderLeft:'3px solid ' + (result.detected ? '#ff3333' : '#00ff41'), marginTop:'10px'}}>
                      <strong style={{color:'white'}}>RECOMMENDED ACTION:</strong>
                      <div style={{color:'white', marginTop:'5px'}}>{"> " + result.fix}</div>
                      {result.commands && result.commands.map((cmd, i) => <div key={i} style={{color:'#ffcc00', fontSize:'0.8rem'}}>$ {cmd}</div>)}
                    </div>}
                  </>
                )}
              </div>
            )}
          </div>
          
          {loading && <div className="decoding-text">{decodeText}</div>}
          
          <div className="action-deck">
            <button className="scan-btn" onClick={handleAnalyze} disabled={loading}>
              {loading ? "[ PROCESSING... ]" : "[ INITIATE THREAT SCAN ]"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}