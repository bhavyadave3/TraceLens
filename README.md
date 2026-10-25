# TraceLens — Digital Forensics Analyzer

TraceLens is a lightweight digital forensics analyzer that examines cloud activity logs and identifies potentially suspicious events.

## Features
- CSV log analysis
- SHA-256 file hashing
- Suspicious-event detection
- Event correlation and risk scoring
- Investigation history using SQLite
- CSV report export

## Tech Stack
- **Frontend:** React
- **Backend:** Python, FastAPI
- **Database:** SQLite

## Run Locally

**1. Start the backend**
```bash
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

**2. Start the frontend** in a separate terminal:
```bash
npm install
npm run dev
```

Open the local URL displayed by Vite, usually `http://localhost:5173`.

## Note
TraceLens uses rule-based detection and correlation scoring. Its findings are investigation leads, not proof of malicious activity.
