# AI Incident Analyzer — Project Structure

```
incident-analyzer/
│
├── app/                          # Main application package
│   ├── __init__.py               # App factory
│   ├── main.py                   # FastAPI app entry point, route registration
│   ├── config.py                 # Configuration & environment variables
│   │
│   ├── api/                      # API route handlers
│   │   ├── __init__.py
│   │   ├── analyze.py            # POST /api/analyze — core analysis endpoint
│   │   ├── health.py             # GET  /api/health  — health check
│   │   └── history.py            # GET  /api/history  — past incidents (Phase 2+)
│   │
│   ├── core/                     # Core security logic (non-AI)
│   │   ├── __init__.py
│   │   ├── ioc_extractor.py      # Regex-based IOC extraction (IPs, domains, hashes, emails, URLs)
│   │   ├── log_parser.py         # Normalize raw logs into structured format
│   │   └── severity.py           # Severity scoring logic
│   │
│   ├── services/                 # External service integrations
│   │   ├── __init__.py
│   │   ├── ai_analyzer.py        # Claude API integration — incident classification & analysis
│   │   └── enrichment.py         # IOC enrichment via threat intel APIs (Phase 3)
│   │
│   ├── models/                   # Data models
│   │   ├── __init__.py
│   │   ├── incident.py           # Incident data model
│   │   └── ioc.py                # IOC data model
│   │
│   ├── templates/                # Jinja2 HTML templates
│   │   ├── base.html             # Base layout
│   │   ├── index.html            # Main analysis page
│   │   ├── results.html          # Analysis results view (Phase 2+)
│   │   └── partials/
│   │       ├── header.html       # Nav header
│   │       └── footer.html       # Footer
│   │
│   └── static/                   # Frontend assets
│       ├── css/
│       │   └── style.css         # Main stylesheet
│       ├── js/
│       │   └── app.js            # Frontend logic — form submission, results rendering
│       └── images/
│
├── tests/                        # Test suite
│   ├── __init__.py
│   ├── test_ioc_extractor.py     # Unit tests for IOC extraction
│   ├── test_log_parser.py        # Unit tests for log parsing
│   └── test_api.py               # Integration tests for API endpoints
│
├── data/
│   └── samples/                  # Sample log files for testing & demos
│       ├── phishing_alert.txt
│       ├── brute_force_log.txt
│       └── malware_alert.txt
│
├── docs/
│   └── architecture.md           # Architecture decisions & design notes
│
├── .env.example                  # Environment variable template
├── .gitignore
├── requirements.txt
├── README.md
└── run.py                        # Dev server entry point
```

## Phase Plan

- **Phase 1**: main.py, config, api/analyze, core/ioc_extractor, core/log_parser, services/ai_analyzer, models, templates, static, sample data, tests
- **Phase 2**: api/history, results template, timeline generation, NIST playbook mapping
- **Phase 3**: services/enrichment, IOC dashboard visualizations
- **Phase 4**: PDF report export
- **Phase 5**: Deployment config, README, architecture docs
