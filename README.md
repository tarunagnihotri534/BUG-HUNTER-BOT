# 🛡️ Website Security Health-Check Bot (Telegram Assistant)

An asynchronous Telegram bot assistant that coordinates routine **security health checks** on pre-authorized domains using established open-source tools (OWASP ZAP, Nuclei, SSL/TLS, Nikto, Gitleaks, HaveIBeenPwned). It parses and groups findings into clear, prioritized reports, dispatches immediate alerts for critical issues, and strictly enforces a hard authorization allowlist.

---

## 🔒 Security Architecture & Guardrails

### 1. Hard Authorization Allowlist (`approved_sites`)
- Every target domain must be explicitly added to the local SQLite `approved_sites` table via `/addsite <domain> <note>`.
- The bot normalizes every target domain (stripping `http://`, `https://`, ports, URL paths, and query parameters) before checking authorization.
- **Zero Bypass / No Override**: If a domain is not in the allowlist, the scan request is immediately rejected and an audit entry is recorded in `audit_logs`.
- Scans are non-destructive health checks (software versions, TLS posture, exposed files, security headers). Custom exploit payloads and brute force scripts are strictly forbidden.

### 2. Telegram User ID Restriction
- Access to the bot is strictly restricted to authorized Telegram user IDs configured in `ALLOWED_TELEGRAM_USER_IDS`.
- Any command invoked by an unauthorized user is blocked and recorded in the audit trail.

### 3. Immediate Alerts vs Routine Summaries
- **Immediate Alert**: Flagged urgently if `CRITICAL` findings are detected (e.g., exposed `.env` files, leaked API keys in git, open admin portals).
- **Consolidated Summary**: Delivered upon scan completion, categorized into:
  - 🚨 **Needs attention now (Critical)**
  - ⚠️ **Should fix soon (High)**
  - 🔶 **Minor (Medium)**
  - ℹ️ **Informational (Low / Info)**
- Full raw scanner JSON outputs are archived in `data/scans/<scan_id>_raw.json` and accessible via `/history_detail <scan_id>`.

---

## 📁 Project Structure

```
d:\TELEGRAM AGENT\
├── run_bot.py                # Bot launcher script
├── requirements.txt          # Python dependencies
├── pytest.ini                # Pytest configuration
├── .env.example              # Configuration template
├── src/
│   ├── config.py             # Settings and environment loader
│   ├── database/
│   │   ├── db.py             # Async SQLite interface (aiosqlite)
│   │   └── models.py         # Data models (Finding, Severity, ScanRecord, etc.)
│   ├── security/
│   │   ├── allowlist.py      # Domain normalization & allowlist enforcement
│   │   └── auth_filter.py    # Telegram User ID access control decorator
│   ├── scanners/
│   │   ├── base.py           # Scanner base class
│   │   ├── tls_scanner.py    # TLS/SSL validity, expiry, and HSTS checks
│   │   ├── nuclei_scanner.py # Nuclei template runner & parser
│   │   ├── zap_scanner.py    # OWASP ZAP REST API client
│   │   ├── nikto_scanner.py  # Nikto web server scanner
│   │   ├── gitleaks_scanner.py # Git repository secret exposure checker
│   │   └── hibp_scanner.py   # HaveIBeenPwned breach verification
│   ├── core/
│   │   ├── orchestrator.py   # Async background scan coordinator
│   │   └── formatter.py      # Severity grouping & Telegram message builder
│   └── bot/
│       ├── handlers.py       # Telegram command handlers
│       └── main.py           # Application lifecycle
└── tests/                    # Comprehensive unit and integration test suite
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- Your numeric Telegram User ID (from [@userinfobot](https://t.me/userinfobot))

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Edit `.env` with your values:
```env
# Required
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ
ALLOWED_TELEGRAM_USER_IDS=123456789

# Local Storage
DB_PATH=data/security_bot.db
RAW_OUTPUT_DIR=data/scans

# Optional: Scanners
ZAP_BASE_URL=http://localhost:8080
ZAP_API_KEY=
NUCLEI_BIN=
NIKTO_BIN=
GITLEAKS_BIN=
HIBP_API_KEY=
```

### 3. Run the Bot
```powershell
.\.venv\Scripts\python run_bot.py
```

---

## 💬 Bot Commands Reference

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `/help` or `/start` | None | Shows help manual and your authenticated user ID. |
| `/check` or `/scan` | `<domain>` | Validates domain against allowlist and triggers background scan. |
| `/status` | None | Displays currently active background scans and elapsed time. |
| `/history` | `<domain>` | Displays past 5 scans for the domain and findings trend. |
| `/history_detail` | `<scan_id>` | Displays full findings breakdown and uploads raw JSON report. |
| `/addsite` | `<domain> <note>` | Adds or re-activates domain on the approved allowlist. |
| `/removesite` | `<domain>` | Revokes approval for a domain (subsequent scans will be denied). |
| `/listsites` | None | Lists all active approved domains and authorization notes. |
| `/audit` | None | Shows the last 10 security audit records (allowed/denied attempts). |

---

## 🛠️ Security Tool Integrations

1. **TLS / SSL Health**:
   - Performs deep certificate audits (expiry date, SAN verification, trust chain).
   - Flags deprecated protocol negotiation (TLS 1.0, TLS 1.1).
   - Audits presence of HTTP Strict Transport Security (`Strict-Transport-Security`).
2. **ProjectDiscovery Nuclei**:
   - Executes non-intrusive template tags: `cve,misconfig,exposure,tech`.
   - Normalizes findings directly into unified severity tiers.
3. **OWASP ZAP (REST API)**:
   - Queries ZAP daemon (`/JSON/core/view/alerts/`).
   - Maps risk scores to standard severities with CWE/WASC references.
4. **Nikto**:
   - Flags outdated web server software and misconfigurations.
5. **Gitleaks**:
   - Audits connected repository commit history for accidentally committed credentials.
   - Any secret detected is automatically escalated to **CRITICAL** for immediate alert.
6. **Have I Been Pwned**:
   - Audits project-associated email addresses against public breach datasets without touching target infrastructure.

---

## 🧪 Running Tests

Execute the complete test suite using `pytest`:
```powershell
.\.venv\Scripts\pytest -v
```
Output:
```
tests/test_allowlist.py::test_normalize_domain PASSED
tests/test_allowlist.py::test_unapproved_domain_is_strictly_rejected PASSED
tests/test_allowlist.py::test_approved_domain_is_authorized PASSED
tests/test_allowlist.py::test_revoked_domain_refuses_subsequent_scans PASSED
tests/test_auth.py::test_settings_user_authorization PASSED
tests/test_auth.py::test_restricted_access_decorator_blocks_unauthorized PASSED
tests/test_auth.py::test_restricted_access_decorator_allows_authorized PASSED
tests/test_orchestrator.py::test_orchestrator_full_lifecycle PASSED
tests/test_scanners.py::test_report_formatter_prioritization PASSED
tests/test_scanners.py::test_nuclei_parser PASSED
tests/test_scanners.py::test_zap_parser PASSED
tests/test_scanners.py::test_gitleaks_finding_is_critical PASSED
tests/test_tls_scanner.py::test_tls_scanner_on_live_domain PASSED
tests/test_tls_scanner.py::test_tls_scanner_connection_failure PASSED
```
