# AI Incident Analyzer

An AI-powered security incident analysis tool that classifies alerts, extracts Indicators of Compromise (IOCs), maps incidents to the MITRE ATT&CK framework, and generates structured analysis reports.

Built for security analysts and incident responders who want to accelerate triage workflows using AI.

## Features

- **AI-Powered Classification** — Automatically classifies incidents (phishing, malware, brute force, etc.) with confidence scoring
- **IOC Extraction** — Regex-based extraction of IPs, domains, URLs, hashes (MD5/SHA1/SHA256), emails, filenames, and CVEs
- **MITRE ATT&CK Mapping** — Maps incidents to specific tactics and techniques
- **Log Format Detection** — Recognizes syslog, CEF, JSON, key-value, and free-text formats
- **Severity Scoring** — Deterministic baseline scoring combined with AI assessment
- **Sample Data** — Built-in sample alerts for phishing, brute force, and malware scenarios

## Architecture

```
┌─────────────────┐     ┌──────────────────────────────────┐
│   Browser UI     │────▶│  FastAPI Backend                  │
│   (HTML/JS/CSS) │◀────│                                    │
└─────────────────┘     │  ┌─────────────┐ ┌─────────────┐ │
                        │  │ Log Parser   │ │ IOC Extract  │ │
                        │  └──────┬──────┘ └──────┬──────┘ │
                        │         ▼                ▼        │
                        │  ┌──────────────────────────────┐ │
                        │  │  Severity Scoring Engine      │ │
                        │  └──────────────┬───────────────┘ │
                        │                 ▼                  │
                        │  ┌──────────────────────────────┐ │
                        │  │  Claude API (AI Classifier)   │ │
                        │  └──────────────────────────────┘ │
                        └──────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Python 3.10+
- An Anthropic API key ([get one here](https://console.anthropic.com/))

### Setup

```bash
# Clone the repo
git clone https://github.com/yourusername/ai-incident-analyzer.git
cd ai-incident-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# Run the app
python run.py
```

Open http://localhost:8000 in your browser.

### Running Without an API Key

The app works in **mock mode** without an API key — IOC extraction, log parsing, and severity scoring all run locally. Only the AI classification falls back to simple keyword matching.

### Running Tests

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

## Project Structure

```
incident-analyzer/
├── app/
│   ├── api/           # API route handlers
│   ├── core/          # Security logic (IOC extraction, log parsing, severity)
│   ├── models/        # Pydantic data models
│   ├── services/      # External integrations (Claude API)
│   ├── static/        # CSS, JS, images
│   └── templates/     # Jinja2 HTML templates
├── tests/             # Unit and integration tests
├── data/samples/      # Sample log files for testing
└── docs/              # Architecture documentation
```

## Tech Stack

- **Backend**: Python, FastAPI, Pydantic
- **AI**: Anthropic Claude API
- **Frontend**: Vanilla HTML/CSS/JS, Jinja2 templates
- **Fonts**: JetBrains Mono, IBM Plex Sans

## Roadmap

- [ ] **Phase 2**: Incident timeline generation + NIST 800-61 response playbooks
- [ ] **Phase 3**: IOC enrichment via VirusTotal / AbuseIPDB
- [ ] **Phase 4**: PDF report export
- [ ] **Phase 5**: Deployment (Docker, Vercel/Railway)

## License

MIT
