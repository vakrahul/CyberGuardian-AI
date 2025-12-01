# 🛡️ CYBER_GUARDIAN v1.0

> **"The Future of Autonomous Threat Detection"**
> An Enterprise-Grade Hybrid AI Security Operations Center (SOC) Agent powered by **Vector AI**, **MITRE ATT&CK Mapping**, and **3D Visualization**.

![Status](https://img.shields.io/badge/STATUS-OPERATIONAL-brightgreen?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-VECTOR%20RAG-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/SECURITY-HYBRID%20ENGINE-red?style=for-the-badge)
![Stack](https://img.shields.io/badge/STACK-MERN%20%2B%20PYTHON-orange?style=for-the-badge)

## 🚀 Project Overview

### The Problem
Traditional security tools rely on static signatures. If a hacker changes one line of code (e.g., renaming `virus.exe` to `notepad.exe`), they bypass detection. Human analysts are overwhelmed by millions of logs and cannot react fast enough to stop ransomware or data exfiltration in real-time.

### The Solution: CyberGuardian v5.0
A **Hybrid Neural Engine** that detects threats based on *behavior* and *context*, not just keywords. It bridges the gap between slow human analysis and instant automated response.

---
## 🛠️ Tech Stack
Frontend: React (Vite), SCSS (Military HUD Theme), React-Three-Fiber (3D).

Backend: Python FastAPI, Uvicorn (Async Server), Sentence-Transformers.

Database: Cosdata OSS (Dockerized Vector Search).

Security: MITRE ATT&CK Framework Integration.
---

## ⚡ Installation & Setup
1️⃣ Prerequisites
Docker Desktop (Must be running)

Node.js & Python 3.10+

2️⃣ Start the Vector Database (The Memory)
Open a terminal and run the Cosdata container:

Bash

docker run -it -p 8443:8443 -p 50051:50051 -v cosdata-data:/opt/cosdata/data cosdataio/cosdata:latest
🔑 Admin Key: admin123 (Enter this when prompted)

3️⃣ Start the Backend (The Brain)


Open a new terminal:

Bash

cd backend
pip install -r requirements.txt

# Load Threat Intelligence (Run once to train the AI)
python ingest.py

# Start the API Server
uvicorn main:app --reload
4️⃣ Start the Frontend (The Interface)
Open a new terminal:

Bash

## cd frontend
## npm install
## npm run dev
🔐 Access Credentials
Open your browser at: http://localhost:5173

## 🧠 System Architecture

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

