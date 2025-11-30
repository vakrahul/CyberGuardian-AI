# 🛡️ CYBER_GUARDIAN 

> **"The Future of Autonomous Threat Detection"** > An Enterprise-Grade Security Operations Center (SOC) Agent powered by **Vector AI**, **MITRE ATT&CK Mapping**, and **3D Visualization**.

![Project Status](https://img.shields.io/badge/STATUS-OPERATIONAL-brightgreen) ![Tech](https://img.shields.io/badge/AI-VECTOR%20RAG-blue) ![Security](https://img.shields.io/badge/SECURITY-HYBRID%20ENGINE-red)


## 🚀 What It Does
Traditional security tools rely on static signatures. If a hacker changes one line of code, they bypass detection.  
**CyberGuardian v5.0** uses a **Hybrid Neural Engine** to detect threats based on *behavior* and *context*, not just keywords.

### 🔥 Key Capabilities
1.  **🧠 Vector RAG AI:** Uses `Cosdata OSS` + `MiniLM-L6-v2` to understand the *meaning* of logs (e.g., detecting "High CPU" as "Crypto Mining").
2.  **🛡️ Hybrid Decision Engine:** Combines **Deterministic Rules** (for critical kill-switches like Ransomware) with **Probabilistic AI** (for unknown zero-days).
3.  **☁️ Cloud Native Defense:** Native support for **AWS S3 Exfiltration**, **EC2 Hijacking**, and **IAM Abuse**.
4.  **⚔️ Multi-Stage Kill Chain:** Detects complex attack stories (Login $\rightarrow$ Sudo $\rightarrow$ Download $\rightarrow$ Wipe Logs).
5.  **🧊 3D Holographic HUD:** A React-Three-Fiber interface for real-time immersive monitoring.

---

## 🛠️ Tech Stack
* **Frontend:** React (Vite), SCSS (Military HUD Theme), React-Three-Fiber (3D).
* **Backend:** Python FastAPI, Uvicorn (Async Server).
* **AI Engine:** Sentence-Transformers (Local LLM), Cosdata Vector DB (Docker).
* **Security:** MITRE ATT&CK Framework Integration.

---

## ⚡ How to Run Locally

### 1. Prerequisites
* Docker Desktop (Running)
* Node.js & Python 3.10+

### 2. Start the Vector Database (Memory)
```bash
docker run -it -p 8443:8443 -p 50051:50051 -v cosdata-data:/opt/cosdata/data cosdataio/cosdata:latest
ADMIN:ADMIN_01
# Admin Key: admin123

npm install
npm run dev
