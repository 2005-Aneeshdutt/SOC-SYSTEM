# AI-Powered SOC Log Intelligence System

A production-grade Security Operations Center (SOC) log intelligence platform that ingests security logs, detects anomalies using machine learning, correlates events into incidents, and provides explainable alerts mapped to MITRE ATT&CK techniques.

## 🎯 Features

- **Multi-Source Log Ingestion**: Supports authentication, network, and process/command logs
- **ML-Based Anomaly Detection**: Uses Isolation Forest, LSTM Autoencoder, and Dense Autoencoder
- **Intelligent Incident Correlation**: Groups alerts by entity (user/IP) and time window
- **MITRE ATT&CK Mapping**: Automatically maps detections to adversary tactics and techniques
- **Explainable AI**: Provides feature attribution with percentiles and z-scores
- **SOC Workflow Support**: Incident status tracking, analyst notes, and investigation tools
- **Real-Time Dashboard**: Streamlit-based visualization with interactive investigation views

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Raw Log Sources                          │
│  (Auth, Network, Process/Command Logs - Zeek, Suricata, etc.)   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Ingestion Layer                       │
│                    POST /ingest/logs                            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│              Log Processing & Normalization                       │
│  • Parse raw logs → structured JSON                              │
│  • Normalize timestamps, users, IPs                              │
│  • Sessionize events by user/IP (gap-based)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Feature Engineering                           │
│  ┌──────────────────┐         ┌──────────────────┐            │
│  │ Window Features  │         │ Sequence Features│            │
│  │ • Event frequency│         │ • Token sequences │            │
│  │ • Rare commands  │         │ • Order patterns  │            │
│  │ • Login deviation│         │ • Sequence length │            │
│  └────────┬─────────┘         └────────┬─────────┘            │
└───────────┼────────────────────────────┼───────────────────────┘
            │                            │
            ▼                            ▼
┌──────────────────────┐    ┌──────────────────────┐
│  Isolation Forest     │    │  LSTM Autoencoder    │
│  (Point Anomalies)    │    │  (Sequence Anomalies)│
└──────────┬───────────┘    └──────────┬───────────┘
           │                            │
           └────────────┬───────────────┘
                        ▼
            ┌──────────────────────┐
            │  Dense Autoencoder   │
            │  (Reconstruction)    │
            └──────────┬───────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │   Detection & Classification  │
        │  • Score fusion (window+seq)  │
        │  • Detection type mapping     │
        │  • MITRE ATT&CK assignment    │
        └──────────┬───────────────────┘
                   │
                   ▼
        ┌──────────────────────────────┐
        │   Incident Correlation       │
        │  • Group by entity+time      │
        │  • Severity assignment       │
        │  • Risk score normalization  │
        └──────────┬───────────────────┘
                   │
                   ▼
        ┌──────────────────────────────┐
        │   Alert Storage & API         │
        │  • SQLite database           │
        │  • REST endpoints            │
        │  • Incident lifecycle        │
        └──────────┬───────────────────┘
                   │
                   ▼
        ┌──────────────────────────────┐
        │   Streamlit Dashboard        │
        │  • Alert timeline            │
        │  • Investigation views       │
        │  • Analytics & metrics       │
        └──────────────────────────────┘
```

## 🔬 Machine Learning Models

### 1. Isolation Forest
- **Purpose**: Detects rare point anomalies in window-based features
- **Input**: 13-dimensional feature vectors (auth failures, port counts, bytes, etc.)
- **Output**: Anomaly score [0, 1] indicating how isolated a window is

### 2. LSTM Autoencoder
- **Purpose**: Detects abnormal behavior sequences
- **Input**: Tokenized event sequences (max length: 50)
- **Architecture**: Encoder (LSTM) → Latent → Decoder (LSTM)
- **Output**: Reconstruction error as anomaly score

### 3. Dense Autoencoder
- **Purpose**: Detects reconstruction-based anomalies in window features
- **Input**: Same 13-dimensional window features as Isolation Forest
- **Architecture**: 13 → 8 → 4 → 8 → 13 (bottleneck)
- **Output**: Reconstruction error as anomaly score

### Score Fusion
Final risk score combines all three models:
```
final_risk = 0.6 * window_score + 0.4 * sequence_score
```
Where `window_score` blends Isolation Forest and Dense AE scores.

## 📊 Detection Pipeline

### 1. Log Ingestion
- Accepts NDJSON format logs via `POST /ingest/logs`
- Supports multiple sources: `auth`, `network`, `process`
- Normalizes timestamps, extracts entities (user, IP, host)

### 2. Feature Extraction

**Window Features** (5-minute windows):
- `auth_failures`: Count of failed login attempts
- `auth_successes`: Count of successful logins
- `distinct_users_in_window`: Unique users in window
- `distinct_dst_ips`: Unique destination IPs
- `distinct_dst_ports`: Unique destination ports
- `deny_rate`: Network deny rate
- `bytes_sum`: Total bytes transferred
- `process_exec_count`: Process execution count
- `rare_command_count`: Commands seen ≤3 times globally
- `max_rare_command_rarity`: Maximum rarity score
- `login_hour_deviation_z`: Z-score of login hour vs. user profile
- `event_sequence_len`: Length of event sequence
- `distinct_sources`: Number of distinct log sources

**Sequence Features**:
- Tokenized event sequences (one-hot encoded)
- Sequence length and ordering patterns

### 3. Anomaly Detection
- Models score each window/sequence
- Signals generated if score > threshold (default: 0.25)
- Signals include evidence (raw events) and feature vectors

### 4. Detection Classification
Maps anomalies to specific security detections:
- `brute_force_login`: Multiple failed logins from same IP
- `credential_stuffing`: 15+ authentication failures
- `port_scan`: Many distinct ports, low bytes
- `lateral_movement_attempt`: Multiple IPs with admin ports
- `exfil_spike`: Large data transfer spike
- `abnormal_service_usage`: Service account with unusual activity
- `anomalous_behavior`: Generic fallback

### 5. Incident Correlation
- Groups signals by entity (user OR IP) within time window (default: 15 min)
- Creates incidents when ≥2 signals correlate
- Assigns severity using quantile-based distribution
- Applies logistic scaling to avoid score saturation (range: 0.4-0.95)

### 6. MITRE ATT&CK Mapping
Automatically maps detection types to MITRE techniques:
- `bruteforce` → T1110 (Brute Force)
- `valid_accounts` → T1078 (Valid Accounts)
- `port_scan` → T1046 (Network Service Scanning)
- `remote_services` → T1021 (Remote Services)
- `ingress_tool_transfer` → T1105 (Ingress Tool Transfer)

##  Quick Start

### Prerequisites
- Python 3.10+
- Virtual environment (recommended)

### Installation

1. **Clone and setup**:
```bash
cd "SOC SYSTEM"
python -m venv .venv
.\.venv\Scripts\activate  # Windows
# or: source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

2. **Generate sample logs**:
```bash
python -m soclsim.generate --out data/raw --days 7 --seed 7
```

3. **Train models**:
```bash
python -m soclsim.train --raw data/raw --artifacts artifacts --epochs 8
```

4. **Start API server** (Terminal 1):
```bash
uvicorn soclsim.api.main:app --host 127.0.0.1 --port 8000
```

5. **Ingest logs and start dashboard** (Terminal 2):
```bash
python -m soclsim.ingest_file --api http://127.0.0.1:8000 --raw data/raw --batch 500
streamlit run soclsim/dashboard/app.py
```

6. **Access dashboard**: Open `http://localhost:8501` in your browser

## 📡 API Endpoints

### `POST /ingest/logs`
Ingest raw security logs.

**Request**:
```json
{
  "source": "auth",
  "events": [
    {"ts": "2026-01-15T08:00:00Z", "user": "alice", "ip": "10.0.1.5", ...}
  ]
}
```

**Response**:
```json
{
  "ingested": 500,
  "new_alerts": 3
}
```

### `GET /alerts`
Retrieve alerts with filtering.

**Query Parameters**:
- `min_severity`: `low`, `medium`, or `high` (default: `low`)
- `limit`: Max results (default: 100)
- `user`: Filter by username
- `ip`: Filter by IP address

### `GET /incidents`
List all incidents.

**Query Parameters**:
- `limit`: Max results (default: 100)

### `GET /incidents/{incident_id}`
Get incident details with associated alerts.

### `PATCH /incidents/{incident_id}`
Update incident status or analyst notes.

**Query Parameters**:
- `status`: `open`, `investigating`, or `resolved`
- `analyst_notes`: Free-text notes

### `GET /stats`
Get system statistics and top risk entities.

## 🎨 Dashboard Features

### Alerts Timeline
- Interactive scatter plot showing alerts over time
- Color-coded by severity
- Hover for details

### Incident Management
- List all incidents with summary information
- Select incident to view details
- Update status and add analyst notes
- View all alerts within an incident

### Alert Investigation
Collapsible sections:
- **Risk Score Breakdown**: Final risk, window score, sequence score, model agreement
- **Detection Information**: Severity, detection type, category
- **MITRE ATT&CK Mapping**: Mapped techniques with tactic icons
- **Top Contributing Features**: Feature attribution with percentiles
- **Evidence Timeline**: All correlated log events (expandable)
- **Related Alerts**: Previous alerts for same IP/user
- **Incident Context**: Timeline of alerts within incident

### Analytics
- **Severity Distribution**: Bar chart of alert severities
- **Detection Category Distribution**: Bar chart of detection types
- **Alerts per Hour**: Histogram showing alert frequency over time

### Top Risk Entities
- **Users**: Weighted risk score (max score × 0.4 + incidents × 0.3 + severity × 0.2 + recency × 0.1)
- **IPs**: Same weighted calculation
- Shows alert count and incident count

## ⚙️ Configuration

Environment variables (with defaults):

```bash
# Time windows
SOCLSIM_SESSION_GAP_MINUTES=30      # Session inactivity gap
SOCLSIM_WINDOW_MINUTES=5            # Feature window size
SOCLSIM_CORRELATION_WINDOW_MINUTES=15  # Incident grouping window

# Detection thresholds
SOCLSIM_SIGNAL_MIN_SCORE=0.25       # Minimum score to create signal
SOCLSIM_INCIDENT_MIN_SIGNALS=2      # Signals needed for incident

# Severity thresholds
SOCLSIM_SEVERITY_MEDIUM=0.5         # Medium severity threshold
SOCLSIM_SEVERITY_HIGH=0.8           # High severity threshold

# Sequence length
SOCLSIM_MAX_SEQUENCE_LEN=50         # Max sequence tokens
```

## 📁 Project Structure

```
soclsim/
├── api/              # FastAPI application
│   └── main.py       # REST endpoints
├── correlation/      # Incident correlation engine
│   ├── correlate.py  # Signal grouping logic
│   └── mitre.py      # MITRE ATT&CK mappings
├── dashboard/        # Streamlit dashboard
│   └── app.py        # UI components
├── detection/        # Detection classification
│   └── classify.py   # Detection type mapping
├── features/         # Feature engineering
│   ├── windows.py    # Window-based features
│   └── sequences.py  # Sequence features
├── logs/             # Log processing
│   ├── parsers.py    # Log parsing
│   ├── sessionize.py # Sessionization
│   └── generate.py   # Sample log generator
├── models/           # ML models
│   ├── isoforest.py  # Isolation Forest
│   ├── torch_models.py # PyTorch models
│   ├── train_torch.py # Training scripts
│   └── scoring.py    # Inference & explainability
├── runtime/          # Runtime components
│   ├── artifacts.py  # Model artifact loading
│   ├── engine.py     # Detection engine
│   └── state.py      # In-memory state
├── db.py             # Database models & operations
├── schemas.py        # Pydantic schemas
├── config.py         # Configuration
└── train.py          # Main training script
```

## 🔧 Development

### Running Tests
```bash
python -m pytest tests/
```

### Code Quality
```bash
black soclsim/
flake8 soclsim/
mypy soclsim/
```

### Adding New Log Sources
1. Add parser in `soclsim/logs/parsers.py`
2. Update `parse_any()` function
3. Regenerate training data
4. Retrain models

## 📈 Performance

- **Ingestion**: ~1000 events/second
- **Detection Latency**: <100ms per batch
- **Dashboard Load Time**: <2s for 10k alerts

## 🔒 Security Considerations

- All timestamps normalized to UTC
- SQL injection protection via SQLModel
- Input validation via Pydantic
- Rate limiting recommended for production

## 📝 License

MIT License

