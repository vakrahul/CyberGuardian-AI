# CYBER_GUARDIAN v1.0

> **"The Future of Autonomous Threat Detection"** > An Enterprise-Grade **Hybrid AI Security Operations Center (SOC) Agent** powered by **Vector AI**, **MITRE ATT&CK Mapping**, and **3D Visualization**.

![Status](https://img.shields.io/badge/STATUS-OPERATIONAL-brightgreen?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-VECTOR%20RAG-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/SECURITY-HYBRID%20ENGINE-red?style=for-the-badge)
![Stack](https://img.shields.io/badge/STACK-MERN%20%2B%20PYTHON-orange?style=for-the-badge)

---

##  Project Overview

###  The Problem
Traditional security tools rely on static signatures.  
A minor modification—such as renaming `virus.exe` to `notepad.exe`—can bypass detection entirely.  
Security analysts are overwhelmed by millions of logs, making real-time ransomware or data-exfiltration prevention nearly impossible.

###  The Solution — CyberGuardian v1.0
CyberGuardian is built on a **Hybrid Neural Defense Engine** that identifies threats based on **behavior, intent, and contextual similarity**, not just keywords or hashes.

It closes the gap between:
- Slow, manual human investigation  
- Instant, autonomous machine response  

---

##  Tech Stack

### Frontend
- **Framework:** React (Vite)
- **Styling:** SCSS (Military-grade HUD Theme)
- **Visuals:** React-Three-Fiber (3D Visualization)

### Backend
- **API:** Python (FastAPI)
- **Server:** Uvicorn (Async ASGI Server)
- **ML Engine:** Sentence-Transformers

### Database
- **Vector Store:** Cosdata OSS (Dockerized Vector Database)

### Security Intelligence
- **Framework:** MITRE ATT&CK Integration

---

##  Installation & Setup

### 1️⃣ Prerequisites
- Docker Desktop (must be running)
- Node.js (v18+ recommended)
- Python 3.10+

### 2️⃣ Start the Vector Database (Memory Layer)
Run the following command to spin up the vector store:

```bash
docker run -it \
  -p 8443:8443 \
  -p 50051:50051 \
  -v cosdata-data:/opt/cosdata/data \
  cosdataio/cosdata:latest
Admin Credentials: > Admin Key: admin123
```
### 3 Start the Backend (Brain Layer)
```bash
cd backend
pip install -r requirements.txt\

# Load threat intelligence (run once)\
python ingest.py\

# Start the API server\
uvicorn main:app --reload\
```
### 4️⃣ Start the Frontend (Interface Layer)
```bash
cd frontend
npm install
npm run dev
```
##  System Architecture

We use a **4-Layer Defense** approach to balance speed and intelligence.

```mermaid
graph TD;
    User[Analyst / Dashboard] -->|Log Input| API[FastAPI Backend];
    API -->|Layer 1: Speed| Whitelist[Safe Traffic Filter];
    API -->|Layer 2: Logic| Chain[Multi-Stage Kill Chain Detector];
    API -->|Layer 3: Rules| Rules[Critical Kill-Switch Engine];
    API -->|Layer 4: AI| VectorAI[Vector RAG Neural Engine];
    VectorAI <-->|Semantic Search| DB[(Cosdata Vector DB)];
    Rules -->|Critical Alert| UI[React 3D HUD];
    VectorAI -->|Contextual Alert| UI;
    KillSwitch -->|Critical Alert| UI[React 3D HUD];
    VectorAI -->|Contextual Alert| UI;

