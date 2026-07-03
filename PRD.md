# Product Requirements Document (PRD): DevOps Network Monitoring Agent

## 1. Overview

**Project Name**: DevOps Network Monitoring Agent  
**Framework Foundation**: AutoAgents (Rust multi-agent framework)  
**Primary Goal**: Automate DevOps network monitoring tasks by analyzing Traefik logs in Elasticsearch/Kibana, detecting threats (primarily secrets scanning at high rates), and making deterministic recommendations or actions via Kubernetes API.  

**Key Capabilities**:
- Localized SQLite database for state management (allowlist, incidents, actions)
- Configurable operating modes (auto, review, disabled)
- Multi-turn LLM-driven Elasticsearch query flow for dynamic threat detection
- Traefik-first Kubernetes pattern inspection and blocking
- Simple SPA for review mode approval workflow (no auth)

---

## 2. Goals & Non-Goals

### Goals
- Detect secrets scanning activity via high-rate 401/403 responses to sensitive paths with suspicious user-agents
- Maintain a SQLite-backed allowlist to prevent blocking expected IPs
- Inspect existing Kubernetes/Traefik blocking patterns and match them deterministically
- Support configurable LLM service (URL-based or API key-based)
- Provide `auto`, `review`, and `disabled` operating modes
- Deliver a simple vanilla HTML/CSS/JS SPA for review mode incident approval

### Non-Goals
- Complex SPA framework setup (no React/Vue/Svelte build steps)
- Authentication/authorization for the initial SPA version
- Cloud-only LLM defaults (LLM service always uses configured URL or CLI-specified URL)
- Generic log analysis (focus is primarily on secrets scanning indicators)

---

## 3. Architecture & Components

### 3.1 Core Modules

| Module | Responsibility |
|--------|----------------|
| `config/` | Configuration loading and validation (YAML) |
| `db/` | SQLite database operations (allowlist, incidents, actions) |
| `llm/` | Unified LLM provider abstraction (URL or API key + provider) |
| `elasticsearch/` | ES client with LLM-driven DSL query execution |
| `k8s/` | Kubernetes client for Traefik CRD discovery and pattern matching |
| `agent/` | ReAct executor with tool registry and guardrails hooks |
| `tools/` | Agent tools (query_logs, check_allowlist, inspect_patterns, apply_block) |
| `models/` | Data models (Incident, Recommendation, Action) |
| `web/` | axum HTTP server serving SPA static files and API endpoints |

---

## 4. Configuration & LLM Service

### 4.1 Configuration Schema (`config.yaml`)

```yaml
# LLM Service Configuration
llm:
  service_type: "url"  # "url" or "api_key"
  url: "http://localhost:11434/api/generate"  # For Ollama/local
  # OR
  # provider: "openai"
  # api_key: "${OPENAI_API_KEY}"
  model: "llama3"  # or "gpt-4o"
  temperature: 0.2

# Operating Mode
mode: "review"  # "auto", "review", or "disabled"

# Elasticsearch/Kibana Configuration
elasticsearch:
  url: "https://es-cluster:9200"
  username: "${ES_USER}"
  password: "${ES_PASSWORD}"
  index_pattern: "traefik-logs-*"

# Kubernetes Configuration
kubernetes:
  context: "${KUBE_CONTEXT}"

# Database Configuration
database:
  path: "./data/devops-agent.db"

# Guardrails Configuration
guardrails:
  enabled: true
  input_policy: "sanitize"
  output_policy: "audit"
```

### 4.2 LLM Service URL Concept
- Always uses configured URL or CLI-specified `--llm-url` flag
- Supports both `url` (e.g., Ollama at `http://localhost:11434/api/generate`) and `api_key` + `provider` (OpenAI, Anthropic, etc.)
- CLI override: `--llm-url <url>` or `--llm-provider <provider> --llm-api-key <key>`

---

## 5. Elasticsearch Multi-Turn Flow

### 5.1 Detection Focus: Secrets Scanning at High Rates
Indicators include:
- High volume of `401 Unauthorized` or `403 Forbidden` responses
- Specific paths: `/.env`, `/wp-config.php`, `/config.xml`, `/.git/config`, `/api/v1/secrets`
- User-Agent patterns: `gitleaks`, `trufflehog`, `secretsniffer`, `nuclei`
- Time-windowed rate analysis (e.g., >50 requests/minute to sensitive paths)

### 5.2 Multi-Turn LLM-Driven Flow
1. Initial query: Fetch Traefik logs for time window with 401/403 status codes
2. Analyze results: Identify path patterns, user-agents, IP sources
3. Refine query: LLM dynamically generates follow-up Elasticsearch DSL queries
4. Rate analysis: Calculate request volumes per IP/time-window
5. Pattern confirmation: LLM confirms if behavior matches secrets scanning indicators

---

## 6. Kubernetes Pattern Inspection (Traefik Priority)

### 6.1 Discovery Priority Order
1. **Traefik Middleware** resources (`Middleware`, `MiddlewareTCP`) with IP whitelisting/blacklisting
2. **Traefik CRDs**: `IngressRoute`, `IngressRouteTCP`, `TraefikService` with IP-based routing
3. **ConfigMaps/Secrets** consumed by Traefik pods (e.g., custom IP block lists)
4. **NetworkPolicy** resources (fallback native K8s blocking)

### 6.2 Discovery Method
- Agent uses `kube` crate to discover Traefik CRDs
- Equivalent to: `kubectl get middleware,ingressroute,traefikservice -A`

---

## 7. Operating Modes

| Mode | Behavior |
|------|----------|
| `auto` | Agent executes `apply_network_block` deterministically |
| `review` | Agent creates `recommendation` record, requires human approval via SPA before `apply_network_block` |
| `disabled` | Read-only: only queries logs, checks allowlist, creates incident records |

---

## 8. Allowlist Mechanism

### 8.1 Database Schema (SQLite)

**Tables:**
- `allowlist_ips`: `id`, `ip_or_cidr`, `description`, `created_at`, `expires_at`
- `incidents`: `id`, `ip_address`, `threat_type`, `severity`, `detected_at`, `status`
- `actions`: `id`, `incident_id`, `action_type`, `mode`, `applied_at`, `approved_by`

### 8.2 Workflow
1. When threat is detected, check IP against SQLite allowlist
2. If IP is in allowlist, skip blocking and log as allowed
3. If not in allowlist, create incident record and proceed to recommendation

---

## 9. Review Mode Approval Workflow (Simple SPA)

### 9.1 SPA Architecture
- Vanilla HTML/CSS/JS served via Rust `axum` static files
- No build steps, no Node.js dependencies
- Python-friendly structure: clean separation of HTML (structure), CSS (styling), JS (API calls)
- No authentication for initial version

### 9.2 API Endpoints
- `GET /api/incidents` - List detected incidents
- `GET /api/incidents/{id}/recommendation` - View LLM recommendation
- `POST /api/incidents/{id}/approve` - Approve blocking action
- `POST /api/incidents/{id}/reject` - Reject blocking action

---

## 10. LLM Guardrails Integration

Where guardrails make sense:
- **Input validation**: Sanitize ES query results before passing to LLM (remove PII, limit token count)
- **Output validation**: Ensure recommendations/commands are well-formed and safe
- **Audit policy**: Log all LLM interactions for compliance

Uses AutoAgents' `autoagents-guardrails` crate with:
- `Block` policy for malicious input patterns
- `Sanitize` policy for log data redaction
- `Audit` policy for action recommendations

---

## 11. CLI Interface

```bash
devops-agent --config config.yaml \
             --mode review \
             --serve-spa \
             --llm-url http://localhost:11434/api/generate \
             # OR --llm-provider openai --llm-api-key <key>
```

### CLI Flags
- `--config <file>`: Path to configuration file
- `--mode <auto|review|disabled>`: Operating mode override
- `--serve-spa`: Enable SPA web server
- `--llm-url <url>`: LLM service URL override
- `--llm-provider <provider>`: LLM provider (openai, anthropic, etc.)
- `--llm-api-key <key>`: LLM API key

---

## 12. Project Structure

```
devops-agent/
├── Cargo.toml
├── config/
│   └── default.yaml
├── src/
│   ├── main.rs                 # CLI entry point (clap)
│   ├── config/
│   │   ├── mod.rs
│   │   └── models.rs
│   ├── db/
│   │   ├── mod.rs
│   │   ├── schema.rs
│   │   └── queries.rs
│   ├── llm/
│   │   ├── mod.rs              # URL/API key factory
│   │   └── provider.rs
│   ├── elasticsearch/
│   │   ├── mod.rs
│   │   └── queries.rs          # LLM-generated DSL execution
│   ├── k8s/
│   │   ├── mod.rs
│   │   ├── inspector.rs        # Traefik CRD discovery via kube crate
│   │   └── blocker.rs
│   ├── agent/
│   │   ├── mod.rs              # ReAct executor + tools
│   │   └── hooks.rs            # Guardrails
│   ├── tools/
│   │   ├── mod.rs
│   │   ├── query_logs.rs
│   │   ├── check_allowlist.rs
│   │   ├── inspect_patterns.rs
│   │   └── apply_block.rs
│   ├── models/
│   │   ├── incident.rs
│   │   ├── recommendation.rs
│   │   └── action.rs
│   └── web/
│       ├── mod.rs              # axum server setup
│       ├── api.rs              # REST endpoints
│       └── static/
│           ├── index.html
│           ├── app.js
│           └── styles.css
└── config.yaml.example
```

---

## 13. Key Dependencies

```toml
[dependencies]
autoagents = { version = "0.5", features = ["full"] }
autoagents-guardrails = "0.5"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
serde_json = "1"
sqlx = { version = "0.7", features = ["sqlite", "runtime-tokio", "macros"] }
kube = { version = "0.88", features = ["client", "derive", "rustls-tls"] }
reqwest = { version = "0.11", features = ["json", "rustls-tls"] }
axum = "0.7"
tracing = "0.1"
tracing-subscriber = "0.3"
clap = { version = "4", features = ["derive"] }
```

---

## 14. Implementation Phases

| Phase | Task |
|-------|------|
| 1 | Project init, Cargo.toml, CLI parsing (`clap`), config loading |
| 2 | SQLite DB setup (allowlist, incidents, actions tables) |
| 3 | LLM provider abstraction (URL + API key factory) |
| 4 | Elasticsearch client (LLM-generated DSL execution) |
| 5 | Kubernetes client (Traefik CRD discovery via `kube` crate) |
| 6 | Agent tools + ReAct executor + guardrails integration |
| 7 | Web server + SPA (vanilla JS via `axum`) |
| 8 | Testing and documentation |

---

## 15. Next Steps

Upon PRD approval, implementation will begin with:
1. Project initialization and Cargo.toml setup
2. CLI parsing and configuration loading
3. SQLite database schema and operations
4. LLM provider abstraction
