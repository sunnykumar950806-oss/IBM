# 🛡 MITRE ATT&CK Alert Mapper

A **defensive cybersecurity tool** that automatically maps security alerts and log events to relevant [MITRE ATT&CK®](https://attack.mitre.org) Enterprise tactics and techniques — with explanation, confidence scoring, and investigation guidance for SOC analysts and students.

> ⚠️ **This project is for defensive purposes only** — security monitoring, threat detection, and incident investigation. It does not implement or assist with attacks, exploitation, or malware.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Alert Analysis** | Submit plain-text or JSON alerts for instant MITRE mapping |
| **Indicator Extraction** | Automatically extracts IPs, usernames, processes, commands, filenames |
| **MITRE ATT&CK Mapping** | Maps to tactics, techniques, and sub-techniques with confidence scores |
| **Explanation** | Explains *why* each technique was matched with keywords found |
| **Investigation Steps** | Provides defensive investigation guidance per technique |
| **Sigma Rules** | Associates relevant Sigma detection rules with each alert |
| **SOC Dashboard** | Live stats: total alerts, confidence distribution, top tactics/techniques |
| **Alert History** | Searchable and filterable alert log with full detail pages |
| **Technique Browser** | Browse all supported MITRE ATT&CK techniques and sub-techniques |
| **REST API** | Full FastAPI backend with Swagger UI at `/docs` |
| **Sample Data** | 12 pre-loaded realistic security alert examples |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or newer
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/mitre-alert-mapper.git
cd mitre-alert-mapper

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the application
uvicorn app.main:app --reload
```

The application will be available at **http://localhost:8000**

On first startup, 12 sample alerts are automatically seeded into the database.

---

## 🖥 Pages

| URL | Page |
|---|---|
| `http://localhost:8000/` | Dashboard — stats, charts, recent alerts |
| `http://localhost:8000/analyze` | Analyze an alert (text or JSON) |
| `http://localhost:8000/history` | Alert history with search & filter |
| `http://localhost:8000/techniques` | Browse MITRE ATT&CK techniques |
| `http://localhost:8000/alert/{id}` | Full alert detail page |
| `http://localhost:8000/about` | About page with API reference |
| `http://localhost:8000/docs` | Swagger UI (interactive API docs) |
| `http://localhost:8000/redoc` | ReDoc API documentation |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/alerts/analyze` | Analyze and map a new security alert |
| `GET` | `/api/alerts` | List all analyzed alerts (paginated) |
| `GET` | `/api/alerts/{id}` | Get full details of a single alert |
| `GET` | `/api/alerts/search` | Search and filter alerts |
| `GET` | `/api/tactics` | List all MITRE ATT&CK tactics |
| `GET` | `/api/techniques` | List all techniques with sub-techniques |
| `GET` | `/api/techniques/{id}` | Get a single technique by ID |
| `GET` | `/api/dashboard` | Dashboard statistics |

### Example: Analyze an Alert

```bash
curl -X POST http://localhost:8000/api/alerts/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "raw_input": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
    "input_format": "text"
  }'
```

**Response:**
```json
{
  "id": 1,
  "alert_type": "PowerShell Execution",
  "process_name": "powershell.exe",
  "mapping_count": 2,
  "top_confidence": "High",
  "mappings": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactic_name": "Execution",
      "confidence": "High",
      "confidence_score": 0.65,
      "explanation": "This alert was mapped to T1059.001 – PowerShell with High confidence...",
      "investigation_steps": [
        "Examine the full PowerShell command line arguments.",
        "Check if encoded commands (-EncodedCommand) were used and decode them.",
        ...
      ]
    }
  ]
}
```

---

## 🗂 Project Structure

```
mitre-alert-mapper/
├── app/
│   ├── main.py                  # FastAPI application entry point
│   ├── database.py              # SQLAlchemy DB config and session
│   ├── api/
│   │   ├── alerts.py            # Alert endpoints (analyze, list, search, get)
│   │   ├── mitre.py             # Tactic and technique reference endpoints
│   │   └── dashboard.py         # Dashboard statistics endpoint
│   ├── models/
│   │   ├── db_models.py         # SQLAlchemy ORM models (Alert, MitreMapping, SigmaMatch)
│   │   └── schemas.py           # Pydantic request/response schemas
│   ├── services/
│   │   ├── alert_parser.py      # Extracts indicators from text/JSON alerts
│   │   ├── mitre_mapper.py      # MITRE technique scoring and mapping engine
│   │   ├── sigma_matcher.py     # Sigma rule keyword matching
│   │   └── analyzer.py          # Orchestrates parsing → mapping → persistence
│   └── data/
│       ├── mitre_data.json      # Local MITRE ATT&CK Enterprise data
│       ├── sigma_rules.json     # Local Sigma rule library
│       └── sample_data.py       # Sample alert seeder
├── frontend/
│   ├── static/
│   │   ├── css/app.css          # Global dark SOC-style stylesheet
│   │   └── js/app.js            # Shared JavaScript utilities
│   └── templates/
│       ├── index.html           # Dashboard page
│       ├── analyze.html         # Analyze alert page
│       ├── history.html         # Alert history page
│       ├── techniques.html      # MITRE techniques browser
│       ├── alert_detail.html    # Alert detail page
│       └── about.html           # About + API reference page
├── tests/
│   └── test_app.py              # Comprehensive unit and API tests
├── requirements.txt
└── README.md
```

---

## 🗄 Database Schema

### `alerts` table

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment primary key |
| `raw_input` | TEXT | Original alert text |
| `input_format` | VARCHAR(20) | "text" or "json" |
| `alert_type` | VARCHAR(100) | Classified alert type |
| `timestamp` | DATETIME | When the alert was received |
| `analyzed_at` | DATETIME | When analysis completed |
| `username` | VARCHAR(200) | Extracted username |
| `source_ip` | VARCHAR(100) | Extracted source IP |
| `destination_ip` | VARCHAR(100) | Extracted destination IP |
| `process_name` | VARCHAR(200) | Extracted process name |
| `command_line` | TEXT | Extracted command line |
| `file_name` | VARCHAR(300) | Extracted file name |
| `hostname` | VARCHAR(200) | Extracted hostname |
| `is_analyzed` | BOOLEAN | Whether analysis ran |
| `mapping_count` | INTEGER | Number of techniques mapped |
| `top_confidence` | VARCHAR(20) | Highest confidence level found |

### `mitre_mappings` table

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment primary key |
| `alert_id` | INTEGER FK | Foreign key → alerts.id |
| `technique_id` | VARCHAR(20) | MITRE technique ID (e.g. T1059.001) |
| `technique_name` | VARCHAR(200) | Technique name |
| `tactic_id` | VARCHAR(20) | MITRE tactic ID |
| `tactic_name` | VARCHAR(100) | Tactic name |
| `is_subtechnique` | BOOLEAN | Whether it's a sub-technique |
| `confidence` | VARCHAR(20) | High / Medium / Low |
| `confidence_score` | FLOAT | Numeric score (0.0–1.0) |
| `matched_keywords` | TEXT | JSON list of matched keywords |
| `explanation` | TEXT | Human-readable explanation |
| `investigation_steps` | TEXT | JSON list of investigation steps |

---

## 🎯 Supported MITRE Techniques

| ID | Name | Tactic |
|---|---|---|
| T1059 | Command and Scripting Interpreter | Execution |
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1059.005 | Visual Basic | Execution |
| T1059.006 | Python | Execution |
| T1053 | Scheduled Task/Job | Execution, Persistence |
| T1053.005 | Scheduled Task | Execution, Persistence |
| T1078 | Valid Accounts | Initial Access, Persistence |
| T1003 | OS Credential Dumping | Credential Access |
| T1003.001 | LSASS Memory | Credential Access |
| T1087 | Account Discovery | Discovery |
| T1087.001 | Local Account | Discovery |
| T1087.002 | Domain Account | Discovery |
| T1016 | System Network Configuration Discovery | Discovery |
| T1049 | System Network Connections Discovery | Discovery |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1110 | Brute Force | Credential Access |
| T1110.001 | Password Guessing | Credential Access |
| T1136 | Create Account | Persistence |
| T1136.001 | Local Account | Persistence |
| T1021 | Remote Services | Lateral Movement |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1071 | Application Layer Protocol | Command and Control |
| T1204 | User Execution | Execution |

---

## 🧪 Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --tb=short

# Run a specific test class
pytest tests/test_app.py::TestMitreMapper -v
```

---

## 📋 Example Alert Inputs

### PowerShell (plain text)
```
Process Creation | Host: WORKSTATION-42 | User: jsmith | Image: powershell.exe |
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA |
ParentImage: winword.exe | Timestamp: 2024-01-15T09:23:11Z
```

### Account Creation (JSON)
```json
{
  "event_type": "user_created",
  "event_id": 4720,
  "host": "FILESERVER-01",
  "created_by": "DOMAIN\\svc_backup",
  "new_account": "support_temp",
  "group_memberships": ["Administrators"],
  "timestamp": "2024-01-15T11:30:00Z"
}
```

### Credential Dumping (plain text)
```
Sysmon Event 10 | SourceImage: C:\Windows\Temp\svhost.exe |
TargetImage: lsass.exe | GrantedAccess: 0x1fffff |
CallTrace: mimikatz.exe | User: DOMAIN\hacker
```

---

## 🔮 Future Improvements

- [ ] Real-time MITRE ATT&CK data sync via TAXII/STIX
- [ ] YARA rule matching
- [ ] Threat intelligence feed integration (VirusTotal, AbuseIPDB)
- [ ] Exportable reports (PDF/CSV)
- [ ] Alert correlation across multiple events
- [ ] User authentication and role-based access
- [ ] Docker deployment support
- [ ] Webhook alerts for high-confidence mappings
- [ ] SIEM integration (Splunk, Elastic)
- [ ] ATT&CK Navigator heatmap export

---

## 🏗 Architecture

```
Browser (HTML/CSS/JS)
        │
        │  HTTP
        ▼
FastAPI Application (app/main.py)
   ├── API Routers (app/api/)
   │     ├── alerts.py    → POST /api/alerts/analyze
   │     ├── mitre.py     → GET  /api/techniques, /api/tactics
   │     └── dashboard.py → GET  /api/dashboard
   │
   ├── Services (app/services/)
   │     ├── alert_parser.py   → Extract indicators from text/JSON
   │     ├── mitre_mapper.py   → Score & rank MITRE techniques
   │     ├── sigma_matcher.py  → Match Sigma detection rules
   │     └── analyzer.py       → Orchestrate the full pipeline
   │
   ├── Models (app/models/)
   │     ├── db_models.py  → SQLAlchemy ORM
   │     └── schemas.py    → Pydantic v2 validation
   │
   └── Data (app/data/)
         ├── mitre_data.json   → Local MITRE ATT&CK Enterprise data
         ├── sigma_rules.json  → Local Sigma rule library
         └── sample_data.py    → DB seeder
         
SQLite Database (mitre_alerts.db)
   ├── alerts
   ├── mitre_mappings
   └── sigma_matches
```

---

## 📜 License

This project is for educational and defensive security purposes.
MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
