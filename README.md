# Agentic AI Email Security system

Production-grade **Agentic AI Cybersecurity System** for **Phishing Email Detection** using multiple independent AI agents, designed for deployment on **Docker** with **Azure OpenAI** for reasoning.

---

## System Overview

The system uses **7 independent AI agents** that run in parallel to analyze different components of an email and collectively determine whether it is malicious.

### Agents

| Agent | Purpose |
|---|---|
| **Header Analysis** | Validates email headers, SPF/DKIM/DMARC, routing anomalies |
| **Content Phishing Detection** | NLP-based analysis of email body for phishing patterns |
| **URL Reputation** | Checks embedded URLs against threat databases and heuristics |
| **Attachment Static Analysis** | Static analysis of attachments for malware signatures |
| **Sandbox Behavior** | Dynamic behavioral analysis references for attachments |
| **Threat Intelligence** | Cross-references indicators with threat intelligence feeds |
| **User Behavior** | Estimates click susceptibility and user-targeting risk context |

### Architecture

The system follows a **3-layer architecture**:

```

The orchestrator uses a **LangGraph state graph** to execute decisioning nodes in order:

1. Score normalization
2. Threat correlation
3. Verdict/action selection
4. Azure OpenAI explanation
5. Conditional Garuda investigation
6. Report persistence + action dispatch

This provides explicit state transitions, structured inputs/outputs per node, and auditable decision flow.
┌─────────────────────────────────────────────┐
│              Decision Layer                  │
│   7 Independent AI Agents (parallel)         │
├─────────────────────────────────────────────┤
│              Analysis Layer                  │
│   Threat Correlation │ Scoring Engine        │
├─────────────────────────────────────────────┤
│               Action Layer                   │
│   Quarantine │ Alerting │ Investigation      │
└─────────────────────────────────────────────┘
```

---

## Project Structure

```
email_security/
├── agents/                        # Independent AI analysis agents
│   ├── header_agent/              #   Email header analysis
│   ├── content_agent/             #   Content phishing detection
│   ├── url_agent/                 #   URL reputation analysis
│   ├── attachment_agent/          #   Attachment static analysis
│   ├── sandbox_agent/             #   Sandbox behavior analysis
│   ├── threat_intel_agent/        #   Threat intelligence lookups
│   ├── user_behavior_agent/       #   User interaction/click-risk analysis
│
├── orchestrator/                  # Agent coordination & scoring
│   ├── decision_engine/           #   Final threat determination
│   ├── threat_correlation/        #   Cross-agent correlation
│   └── scoring_engine/            #   Weighted threat scoring
│
├── api/                           # FastAPI REST service
├── services/                      # Shared services (logging, etc.)
├── configs/                       # Configuration management
├── preprocessing/                 # Data preprocessing pipelines
├── datasets/                      # Raw training datasets
├── datasets_processed/            # Processed/feature-engineered data
├── models/                        # Trained ML models
├── threat_intelligence/           # Threat intel feeds & IOC data
├── sandbox/                       # Sandbox integration modules
├── docker/                        # Dockerfile & docker-compose
├── scripts/                       # Setup & utility scripts
├── tests/                         # Test suite
├── logs/                          # Application logs (gitignored)
└── docs/                          # Documentation
```

Each agent directory contains:

- `agent.py` – Main `analyze(data)` entry point
- `model_loader.py` – ML model loading and caching
- `feature_extractor.py` – Feature engineering from raw data
- `inference.py` – Model inference and prediction

---

## Development Setup

### Prerequisites

- **Python 3.10+**
- **Linux** (tested on Kali Linux / Ubuntu)
- **Docker & Docker Compose** (optional, for containerized deployment)

### Quick Start

```bash
# 1. Clone the repository
git clone <repository-url>
cd email_security

# 2. Run the setup script
chmod +x scripts/setup_env.sh
./scripts/setup_env.sh

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Edit configuration
nano .env   # Add your API keys and connection strings

# 5. Start the API server
uvicorn email_security.api.main:app --reload --host 0.0.0.0 --port 8000
```

### Manual Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.template .env
```

### Docker

```bash
cd docker
docker-compose up --build
```

### Ubuntu Deployment Setup (Recommended)

For Ubuntu runtime parity, use Python 3.11+ and run:

```bash
chmod +x scripts/setup_ubuntu.sh
./scripts/setup_ubuntu.sh
```

This script installs required system packages, creates `venv`, installs Python dependencies, and prepares `.env`/runtime directories.

After setup, validate end-to-end on Ubuntu:

```bash
source venv/bin/activate
pytest tests/
cd docker && docker compose up --build
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/analyze-email` | Submit email for phishing analysis |

### Example Request

```bash
curl -X POST http://localhost:8000/analyze-email \
  -H "Content-Type: application/json" \
  -d '{
    "headers": {
      "sender": "suspicious@example.com",
      "subject": "Urgent: Verify Your Account"
    },
    "body": "Click here to verify your account immediately.",
    "urls": ["http://phishing-site.example.com/verify"],
    "attachments": []
  }'
```

---

## Configuration

Configuration is managed via environment variables with a `.env` file. See `.env.template` for all available options.

Key configuration areas:

- **Azure OpenAI** – Endpoint, deployment, API key, and API version
- **Threat Intelligence** – VirusTotal, Google Safe Browsing, OpenPhish, URLhaus, OTX, AbuseIPDB, MalwareBazaar
- **External Lookup Controls** – `ENABLE_*` provider toggles, request timeout, and IOC lookup limits
- **Model Paths** – Per-agent model directory paths
- **Database** – PostgreSQL connection URL
- **Redis** – Temporary orchestration state cache
- **RabbitMQ** – Event and result messaging configuration
- **Logging** – Log level, format, rotation, retention

---

## Technology Stack

| Category | Technologies |
|---|---|
| **ML / AI** | PyTorch, Transformers, scikit-learn, XGBoost, LightGBM |
| **NLP** | spaCy, NLTK |
| **Security** | YARA, ssdeep, oletools, pefile, tldextract |
| **API** | FastAPI, Uvicorn |
| **Agentic Orchestration** | LangGraph |
| **LLM Reasoning** | Azure OpenAI |
| **Database** | PostgreSQL |
| **Queue** | RabbitMQ |
| **Cache** | Redis |
| **Containerization** | Docker, Docker Compose |
| **Logging** | Loguru (JSON structured) |
| **Config** | Pydantic Settings, python-dotenv |

---

## License

This project is proprietary. All rights reserved.
