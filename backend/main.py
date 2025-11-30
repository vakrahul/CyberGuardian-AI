from fastapi import FastAPI
from pydantic import BaseModel
from cosdata import Client
from sentence_transformers import SentenceTransformer
from fastapi.middleware.cors import CORSMiddleware
import json

# --- CONFIGURATION ---
ADMIN_KEY = "admin123"
HOST_URL = "http://localhost:8443"
COLLECTION_NAME = "cyber_threats_v2"

app = FastAPI(title="CyberGuardian MITRE Engine")

app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_methods=["*"], 
    allow_headers=["*"]
)

print("⏳ Initializing MITRE ATT&CK Matrix & Neural Engine...")
try:
    model = SentenceTransformer('all-MiniLM-L6-v2')
    client = Client(host=HOST_URL, username="admin", password=ADMIN_KEY, verify=False)
    collection = client.get_collection(COLLECTION_NAME)
except:
    print("⚠️ Warning: Database offline. Running in Rule-Only Mode.")
    model = None
    collection = None

class Query(BaseModel):
    text: str 

# ==============================================================================
# 1. THREAT INTELLIGENCE DATABASE (The "Brain")
# ==============================================================================
# Maps keywords to MITRE T-Codes, Categories, and SOC Commands.

THREAT_DB = [
    # --- RANSOMWARE & DESTRUCTION ---
    {
        "keywords": ["encryptor.exe", ".locked", "wannacry", "ryuk"],
        "category": "Ransomware",
        "technique": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "severity": "Critical",
        "fix": "ISOLATE HOST. Do not reboot. Identify encryption source.",
        "commands": ["taskkill /F /IM encryptor.exe", "netsh advfirewall set allprofiles state on"]
    },
    {
        "keywords": ["vssadmin", "delete shadows", "wbadmin delete backup"],
        "category": "Defense Evasion",
        "technique": "T1490",
        "technique_name": "Inhibit System Recovery",
        "severity": "Critical",
        "fix": "STOP PROCESS. Ransomware is attempting to prevent recovery.",
        "commands": ["vssadmin list shadows", "Stop-Computer -Force"]
    },
    {
        "keywords": ["rm -rf", "wipefiles", "shred", "format c:"],
        "category": "Impact",
        "technique": "T1485",
        "technique_name": "Data Destruction",
        "severity": "Critical",
        "fix": "TERMINATE SESSION. Restore data from immutable backup.",
        "commands": ["killall -9 rm", "systemctl isolate rescue.target"]
    },

    # --- CREDENTIAL THEFT ---
    {
        "keywords": ["lsass.exe", "procdump", "mimikatz", "sekurlsa"],
        "category": "Credential Access",
        "technique": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "severity": "Critical",
        "fix": "Isolate workstation. Reset Admin passwords. Enable Credential Guard.",
        "commands": ["Stop-Process -Name lsass -Force", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1"]
    },
    {
        "keywords": ["/etc/shadow", "/etc/passwd", "sam system security"],
        "category": "Credential Access",
        "technique": "T1003.008",
        "technique_name": "OS Credential Dumping: /etc/passwd",
        "severity": "High",
        "fix": "Check file permissions. Audit user access.",
        "commands": ["ausearch -f /etc/shadow", "ls -l /etc/shadow"]
    },

    # --- WEB EXPLOITATION ---
    {
        "keywords": ["union select", "or 1=1", "or '1'='1", "sql syntax"],
        "category": "Web Exploitation",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application (SQLi)",
        "severity": "Critical",
        "fix": "Block Source IP. Sanitize Input parameters.",
        "commands": ["fail2ban-client set nginx-botsearch banip <IP>", "grep 'UNION' /var/log/nginx/access.log"]
    },
    {
        "keywords": ["filename=shell.php", "upload.php", "c99.php", "r57.php"],
        "category": "Web Exploitation",
        "technique": "T1505.003",
        "technique_name": "Server Software Component: Web Shell",
        "severity": "Critical",
        "fix": "Quarantine Web Server. Delete malicious file.",
        "commands": ["find /var/www -name '*.php' -mmin -60", "rm /var/www/uploads/shell.php"]
    },

    # --- PERSISTENCE & C2 ---
    {
        "keywords": ["nc -e", "/bin/bash", "netcat", "powercat"],
        "category": "Command & Control",
        "technique": "T1059",
        "technique_name": "Command and Scripting Interpreter (Reverse Shell)",
        "severity": "Critical",
        "fix": "Kill Process. Check Cron/Registry for persistence.",
        "commands": ["killall -9 nc", "netstat -antp | grep ESTABLISHED"]
    },
    {
        "keywords": ["/etc/rc.local", "chkconfig", "startup folder"],
        "category": "Persistence",
        "technique": "T1053",
        "technique_name": "Scheduled Task/Job",
        "severity": "High",
        "fix": "Remove malicious entry from startup configuration.",
        "commands": ["sed -i '/nc -e/d' /etc/rc.local"]
    },

    # --- CLOUD / AWS ---
    {
        "keywords": ["s3", "getobject", "secrets", "salary"],
        "category": "Exfiltration",
        "technique": "T1530",
        "technique_name": "Data from Cloud Storage Object",
        "severity": "Critical",
        "fix": "Revoke S3 Public Access. Rotate IAM Keys.",
        "commands": ["aws s3api put-public-access-block", "aws iam update-access-key --status Inactive"]
    },
    {
        "keywords": ["xmrig", "minerd", "stratum+tcp"],
        "category": "Resource Hijacking",
        "technique": "T1496",
        "technique_name": "Resource Hijacking (Crypto Mining)",
        "severity": "Critical",
        "fix": "Stop Instance / Process. Check Billing.",
        "commands": ["pkill -f xmrig", "aws ec2 stop-instances --instance-ids <ID>"]
    }
]

# --- SAFE WHITELIST ---
SAFE_KEYWORDS = [
    "accepted password", "login successful", "session opened",
    "backup completed", "transaction success", "status: healthy",
    "rotate log files", "systemd: finished", "usb device found",
    "vpc-flow-log: accept ok", "get /index.html", "google chrome"
]

# ==============================================================================
# 2. MULTI-STAGE KILL-CHAIN ENGINE
# ==============================================================================
def analyze_kill_chain(log_text):
    """
    Detects if multiple distinct attack stages are present in the log.
    Returns a comprehensive Threat Object if a chain is found.
    """
    log_lower = log_text.lower()
    chain_hits = []
    
    # 1. Execution Phase
    if "encryptor.exe" in log_lower or "xmrig" in log_lower:
        chain_hits.append("Execution (T1204)")
    
    # 2. Defense Evasion Phase
    if "vssadmin" in log_lower or "delete shadows" in log_lower:
        chain_hits.append("Inhibit Recovery (T1490)")
    if "log cleared" in log_lower or "rm -rf /var/log" in log_lower:
        chain_hits.append("Indicator Removal (T1070)")
        
    # 3. Persistence/Privilege Phase
    if "rc.local" in log_lower or "registry run" in log_lower:
        chain_hits.append("Persistence (T1547)")
        
    # 4. Exfiltration Phase
    if "upload" in log_lower or "s3" in log_lower or "ftp" in log_lower:
        chain_hits.append("Exfiltration (T1048)")

    # DECISION: If 2 or more stages are detected, it's a confirmed Kill Chain.
    if len(chain_hits) >= 2:
        return {
            "detected": True,
            "severity": "Critical",
            "threat_name": f"[CHAIN] Multi-Stage Attack Detected",
            "technique": "Kill Chain Confirmed",
            "fix": "FULL SOC RESPONSE: 1. Isolate. 2. Contain. 3. Eradicate.",
            "commands": [f"DETECTED STAGES: {', '.join(chain_hits)}", "initiate_lockdown_protocol.sh"],
            "confidence": 1.0
        }
    return None

# ==============================================================================
# 3. MAIN ANALYSIS LOGIC
# ==============================================================================
@app.post("/analyze")
async def analyze(data: Query):
    log_text = data.text
    log_lower = log_text.lower()
    print(f"🔍 Analyzing: {log_text[:50]}...")

    # --- STEP 1: WHITELIST CHECK ---
    # Safe keywords override everything UNLESS a critical keyword is also present
    is_safe = any(safe in log_lower for safe in SAFE_KEYWORDS)
    # Check if ANY critical keyword exists in the log
    is_critical = any(k in log_lower for entry in THREAT_DB for k in entry["keywords"])
    
    if is_safe and not is_critical:
        return {
            "detected": False, "severity": "Safe", 
            "threat_name": "Authorized System Activity", 
            "fix": "None", "confidence": 1.0,
            "message": "Activity allowed by safety whitelist."
        }

    # --- STEP 2: KILL CHAIN ANALYSIS ---
    chain_result = analyze_kill_chain(log_text)
    if chain_result:
        print(f"🚨 KILL CHAIN: {chain_result['commands'][0]}")
        return chain_result

    # --- STEP 3: MITRE SIGNATURE MATCHING ---
    for entry in THREAT_DB:
        # Check if ANY keyword from the entry matches
        if any(k in log_lower for k in entry["keywords"]):
            print(f"🚨 SIGNATURE MATCH: {entry['technique_name']}")
            
            # Format the output for the Frontend
            display_name = f"[{entry['technique']}] {entry['technique_name']}"
            
            return {
                "detected": True,
                "severity": entry['severity'],
                "threat_name": display_name,
                "fix": entry['fix'],
                "commands": entry['commands'],
                "confidence": 1.0
            }

    # --- STEP 4: AI VECTOR SEARCH (Fallback) ---
    if model and collection:
        try:
            vector = model.encode(log_text).tolist()
            response = collection.search.dense(query_vector=vector, top_k=1, return_raw_text=True)

            if response and 'results' in response and len(response['results']) > 0:
                result = response["results"][0]
                score = result.get("score", 0.0)
                
                # Unpack Metadata
                meta = result.get("metadata", {})
                if isinstance(meta, str): 
                    try: 
                        meta = json.loads(meta)
                    except: 
                        meta = {}
                
                # Extract fields
                tech_id = meta.get("technique", "T????")
                tech_name = meta.get("text", "Suspicious Activity")
                threat_display = f"[{tech_id}] {tech_name}"
                
                fix = meta.get("fix", "Investigate Logs")
                severity = meta.get("severity", "Medium")
                commands = meta.get("commands", ["View Security Logs"])

                # AI Threshold
                if score < 0.45:
                    return {"detected": False, "message": f"System Normal (Similarity: {int(score*100)}%)"}

                return {
                    "detected": True,
                    "severity": severity,
                    "threat_name": threat_display,
                    "fix": fix,
                    "commands": commands,
                    "confidence": score
                }
        except Exception as e:
            print(f"AI Error: {e}")

    return {"detected": False, "message": "No threat patterns matched."}