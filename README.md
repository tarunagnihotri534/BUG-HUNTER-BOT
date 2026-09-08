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
| `/checkall` | None | Batch queues automated health checks across all approved domains. |
| `/status` | None | Displays currently active background scans and elapsed time. |
| `/history` | `<domain>` | Displays past 5 scans for the domain, health grades, and trends. |
| `/history_detail` | `<scan_id>` | Displays full findings breakdown and raw report. |
| `/export` | `<scan_id>` | Generates and sends a downloadable Executive Markdown Audit Report. |
| `/schedule` | `<domain> <daily\|weekly>` | Enrolls an authorized domain in recurring automated health checks. |
| `/unschedule` | `<domain>` | Cancels recurring automated monitoring for a domain. |
| `/schedules` | None | Lists all active recurring monitoring schedules. |
| `/addsite` | `<domain> <note>` | Adds or re-activates domain on the approved allowlist. |
| `/removesite` | `<domain>` | Revokes approval for a domain (subsequent scans will be denied). |
| `/listsites` | None | Lists all approved domains and their latest security health score/grade. |
| `/audit` | None | Shows the last 10 security audit records (allowed/denied attempts). |

---

## 🛠️ Security Tool Integrations

### Built-in Scanners (Zero External Binaries Required)
1. **TLS / SSL Health**:
   - Performs deep certificate audits (expiry date, SAN verification, trust chain).
   - Flags deprecated protocol negotiation (TLS 1.0, TLS 1.1).
   - Audits presence of HTTP Strict Transport Security (`Strict-Transport-Security`).
2. **HTTP Security Headers & Web Posture**:
   - Audits essential defense headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
   - Detects cookie security deficiencies (`Secure`, `HttpOnly`, `SameSite`).
   - Flags technology version disclosures (`Server`, `X-Powered-By`).
   - Passive probe for critical sensitive file exposures (`.env`, `/.git/HEAD`).
3. **DNS & Email Security Posture**:
   - Inspects SPF TXT records (flags permissive `+all` wildcards or missing records).
   - Audits DMARC policies (`p=reject`, `p=quarantine`, `p=none`).
   - Verifies active MX mail exchanges and DNSSEC posture.
4. **Security Health Scoring Engine**:
   - Standardized 0–100 score and letter grade (`A+` to `F`) with visual progress gauge.

### Optional External Scanners (Gracefully Degradable)
5. **ProjectDiscovery Nuclei**:
   - Executes non-intrusive template tags: `cve,misconfig,exposure,tech`.
6. **OWASP ZAP (REST API)**:
   - Queries ZAP daemon (`/JSON/core/view/alerts/`) and maps findings to unified severities.
7. **Nikto**:
   - Flags outdated web server software and server misconfigurations.
8. **Gitleaks**:
   - Audits repository history for committed credentials and automatically flags critical leaks.
9. **Have I Been Pwned**:
   - Audits project-associated accounts against public breach datasets without touching target infrastructure.

---

## 🧪 Running Tests

Execute the complete test suite (24 unit and integration tests) using `pytest`:
```powershell
.\.venv\Scripts\pytest -v
```
Output:
```
============================= 24 passed in 13.87s =============================
```
