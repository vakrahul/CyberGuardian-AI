import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';

// --- GAUGE COMPONENT ---
const Gauge = ({ value, label }) => {
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;
  return (
    <div style={{display:'flex', flexDirection:'column', alignItems:'center', width:'45%'}}>
      <div style={{position:'relative', width:'80px', height:'80px'}}>
        <svg width="80" height="80" style={{transform: 'rotate(-90deg)'}}>
          <circle cx="40" cy="40" r={radius} stroke="#0a3a00" strokeWidth="8" fill="transparent" />
          <circle cx="40" cy="40" r={radius} stroke="#00ff41" strokeWidth="8" fill="transparent" strokeDasharray={circumference} strokeDashoffset={offset} style={{transition: 'stroke-dashoffset 0.5s ease'}} />
        </svg>
        <div style={{position:'absolute', top:'0', left:'0', width:'100%', height:'100%', display:'flex', justifyContent:'center', alignItems:'center', color:'#00ff41', fontWeight:'bold'}}>{Math.round(value)}%</div>
      </div>
      <span style={{fontSize:'0.7rem', color:'#00ff41', marginTop:'5px', textTransform:'uppercase'}}>{label}</span>
    </div>
  );
};

// --- GRAPH COMPONENT ---
const ActivityGraph = ({ data }) => {
  const points = data.map((val, i) => `${i * (100 / (data.length - 1))},${100 - val}`).join(' ');
  return (
    <div style={{width:'100%', height:'100%', position:'relative', overflow:'hidden'}}>
      <div style={{position:'absolute', top:0, left:0, right:0, bottom:0, backgroundImage: 'linear-gradient(#00ff4133 1px, transparent 1px), linear-gradient(90deg, #00ff4133 1px, transparent 1px)', backgroundSize: '20px 20px', opacity: 0.2}}></div>
      <svg width="100%" height="100%" viewBox="0 0 100 100" preserveAspectRatio="none" style={{position:'relative', zIndex:2}}>
        <polyline points={points} fill="none" stroke="#00ff41" strokeWidth="2" vectorEffect="non-scaling-stroke" />
        <linearGradient id="grad" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="#00ff41" stopOpacity="0.4"/>
          <stop offset="100%" stopColor="#00ff41" stopOpacity="0"/>
        </linearGradient>
        <polygon points={`0,100 ${points} 100,100`} fill="url(#grad)" />
      </svg>
    </div>
  );
};

// --- SMART AI BRAIN ---
const generateAIResponse = (input, threats) => {
  const query = input.toLowerCase();
  const lastThreat = threats.length > 0 ? threats[0] : null;

  // 1. Analyze Specific Threat
  if (lastThreat) {
    if (query.includes("explain") || query.includes("what") || query.includes("report")) {
      let analysis = `REPORT: Detected "${lastThreat.type}" (Severity: ${lastThreat.severity}). `;
      
      // Detailed Context Logic
      const sig = lastThreat.type.toLowerCase();
      if (sig.includes("sql")) analysis += "Attacker attempted to inject malicious SQL queries to bypass authentication. ";
      else if (sig.includes("ransom")) analysis += "File system monitoring detected encryption behavior similar to WannaCry/LockBit. ";
      else if (sig.includes("shell") || sig.includes("backdoor")) analysis += "A reverse connection was attempted. This grants the attacker remote terminal access. ";
      else if (sig.includes("s3") || sig.includes("aws")) analysis += "Cloud logs indicate unauthorized data movement from S3 buckets. ";
      else analysis += "The anomaly vector score exceeded the safety threshold (90%+). ";

      return analysis + "Immediate containment advised.";
    }
    if (query.includes("fix") || query.includes("action")) {
      return `PROTOCOL: ${lastThreat.fix || "Isolate Host. Block IP. Reset Credentials."}`;
    }
  }

  // 2. General Commands
  if (query.includes("status")) return "SYSTEM STATUS: All defense nodes active. CPU nominal. Network traffic stable.";
  if (query.includes("hello")) return "CyberGuardian AI Online. Ready for analysis.";
  
  return "Command not recognized. Try 'Explain Threat', 'Fix Issue', or 'Run Diagnostics'.";
};

export default function About() {
  const { globalLogs, addLog, globalThreats } = useAuth();
  const [chatInput, setChatInput] = useState("");
  const [cpu, setCpu] = useState(45);
  const [ram, setRam] = useState(62);
  const [graphData, setGraphData] = useState(new Array(20).fill(50));
  const chatEndRef = useRef(null);

  // Auto-scroll chat
  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [globalLogs]);

  // Animation Loop
  useEffect(() => {
    const interval = setInterval(() => {
      setCpu(prev => Math.min(100, Math.max(0, prev + (Math.random() * 10 - 5))));
      setRam(prev => Math.min(100, Math.max(0, prev + (Math.random() * 5 - 2))));
      setGraphData(prev => {
        const newData = [...prev.slice(1), Math.random() * 100];
        return newData;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // --- BUTTON ACTIONS ---
  
  const runDiagnostics = () => {
    addLog("INITIATING SYSTEM DIAGNOSTICS...", "OPERATOR");
    setTimeout(() => addLog("Checking File Integrity... [OK]", "SYSTEM"), 800);
    setTimeout(() => addLog("Scanning Open Ports... [22, 80, 443 OPEN]", "SYSTEM"), 1600);
    setTimeout(() => addLog("Verifying Firewall Rules... [UPDATED]", "SYSTEM"), 2400);
    setTimeout(() => addLog("DIAGNOSTIC COMPLETE. SYSTEM GREEN.", "SYSTEM"), 3200);
  };

  const viewRawLogs = () => {
    addLog("REQUEST: PULL RAW SYSTEM LOGS", "OPERATOR");
    setTimeout(() => {
        addLog(`[RAW] ${new Date().toISOString()} kern.info: device eth0 entered promiscuous mode`, "KERNEL");
        addLog(`[RAW] ${new Date().toISOString()} auth.err: invalid user admin from 192.168.1.55`, "AUTH");
        addLog(`[RAW] ${new Date().toISOString()} daemon.warn: systemd-resolved: clock skew detected`, "DAEMON");
    }, 1000);
  };

  const handleChatSubmit = (e) => {
    if (e.key === 'Enter' && chatInput.trim()) {
      const msg = chatInput.trim();
      addLog(msg); 
      setChatInput("");

      setTimeout(() => {
        const response = generateAIResponse(msg, globalThreats);
        addLog(response, "AI_CORE");
      }, 700);
    }
  };

  return (
    <div className="main-dashboard" style={{border:'none', height:'100%', padding:'0', display:'grid', gridTemplateRows:'1fr 1fr', gap:'20px'}}>
      
      <div style={{display:'grid', gridTemplateColumns:'1fr 2fr 1fr', gap:'20px'}}>
        
        {/* LEFT: SYSTEM HEALTH */}
        <div style={{border:'2px solid #0a3a00', background:'rgba(0,20,0,0.6)', padding:'10px', display:'flex', flexDirection:'column'}}>
          <div className="panel-title" style={{fontSize:'0.8rem'}}>SYSTEM HEALTH</div>
          <div style={{display:'flex', flexWrap:'wrap', justifyContent:'space-around', height:'100%', alignContent:'center'}}>
            <Gauge value={cpu} label="CPU LOAD" />
            <Gauge value={ram} label="RAM USAGE" />
          </div>
        </div>

        {/* CENTER: AI CHATBOT */}
        <div style={{border:'2px solid #0a3a00', background:'rgba(0,20,0,0.6)', padding:'10px', position:'relative', overflow:'hidden', display:'flex', flexDirection:'column'}}>
          <div className="panel-title" style={{fontSize:'0.8rem'}}>// AI_AGENT_CHATBOT</div>
          
          <div style={{flexGrow:1, overflowY:'auto', fontFamily:'monospace', fontSize:'0.85rem', color:'#ccc', marginBottom:'30px', paddingRight:'5px'}}>
            {globalLogs.map((log, i) => (
              <div key={i} style={{marginBottom:'5px', color: log.includes("OPERATOR") ? '#fff' : (log.includes("THREAT") ? '#ff3333' : (log.includes("AI_CORE") ? '#00ff41' : (log.includes("RAW") ? '#ffaa00' : '#aaa')))}}>
                {log}
              </div>
            ))}
            <div ref={chatEndRef} />
          </div>

          <div style={{position:'absolute', bottom:'0', left:'0', width:'100%', borderTop:'1px solid #0a3a00', padding:'10px', background:'black', display:'flex'}}>
            <span style={{color:'#00ff41', marginRight:'10px'}}>{">"}</span>
            <input 
              type="text" 
              placeholder="Ask AI... (e.g. 'Explain threat')" 
              style={{background:'transparent', border:'none', color:'white', width:'100%', outline:'none', fontFamily:'monospace'}}
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={handleChatSubmit}
            />
          </div>
        </div>

        {/* RIGHT: LIVE THREAT FEED */}
        <div style={{border:'2px solid #0a3a00', background:'rgba(0,20,0,0.6)', padding:'10px', overflowY:'auto'}}>
          <div className="panel-title" style={{fontSize:'0.8rem'}}>LIVE THREAT FEED</div>
          <div style={{fontSize:'0.7rem', color:'#00ff41'}}>
            {globalThreats.length === 0 ? (
              <div style={{padding:'10px', opacity:0.5, fontStyle:'italic'}}>WAITING FOR SCANS...</div>
            ) : (
              globalThreats.map((t, i) => (
                <div key={i} style={{marginBottom:'8px', borderBottom:'1px dashed #0a3a00', paddingBottom:'4px'}}>
                  <span style={{color:'#ccc'}}>[{t.time}]</span> <strong style={{color: t.severity === 'Critical' ? '#ff3333' : '#ffaa00'}}>{t.type}</strong>
                  <br/>
                  <span style={{opacity:0.7}}>SEV: {t.severity}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div style={{display:'grid', gridTemplateColumns:'2fr 1fr', gap:'20px'}}>
        {/* GRAPH */}
        <div style={{border:'2px solid #0a3a00', background:'rgba(0,20,0,0.6)', padding:'10px', display:'flex', flexDirection:'column'}}>
          <div className="panel-title" style={{fontSize:'0.8rem'}}>NETWORK ACTIVITY</div>
          <div style={{flexGrow:1, padding:'0', background:'rgba(0,0,0,0.3)', border:'1px solid #0a3a00', height:'100px'}}>
            <ActivityGraph data={graphData} />
          </div>
        </div>
        
        {/* ACTION BUTTONS (Now Working) */}
        <div style={{border:'2px solid #0a3a00', background:'rgba(0,20,0,0.6)', padding:'10px'}}>
          <div className="panel-title" style={{fontSize:'0.8rem'}}>QUICK ACTIONS</div>
          <div style={{display:'flex', flexDirection:'column', gap:'10px', marginTop:'10px'}}>
            <button 
              onClick={runDiagnostics}
              style={{background:'transparent', border:'1px solid #00ff41', color:'#00ff41', padding:'15px', fontSize:'0.8rem', cursor:'pointer', fontWeight:'bold', letterSpacing:'1px', transition:'0.2s', textTransform:'uppercase'}}>
              RUN DIAGNOSTICS
            </button>
            <button 
              onClick={viewRawLogs}
              style={{background:'transparent', border:'1px solid #00ff41', color:'#00ff41', padding:'15px', fontSize:'0.8rem', cursor:'pointer', fontWeight:'bold', letterSpacing:'1px', transition:'0.2s', textTransform:'uppercase'}}>
              VIEW RAW LOGS
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}