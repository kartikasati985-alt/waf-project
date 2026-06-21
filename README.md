# Web Application Firewall (WAF) Project

A Flask-based Web Application Firewall that detects and blocks common web attacks while exposing a vulnerable demo app for testing.

## Features

- SQL Injection detection
- XSS detection
- CSRF checks for mutating requests
- Path Traversal detection
- LFI/RFI signature checks
- Command Injection detection
- XXE signature checks
- Request analysis for query, body, form, and headers
- IP whitelist/blacklist and rate limiting
- SQLite request/event logging
- Dashboard with event timeline and stats

## Project Structure

```
waf-project/
├── main.py
├── waf_engine.py
├── threat_detector.py
├── rules.py
├── vulnerable_app.py
├── dashboard.py
├── logger.py
├── config.py
├── requirements.txt
├── static/style.css
├── templates/dashboard.html
└── tests/test_waf.py
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

- Vulnerable app: `http://127.0.0.1:5000/`
- Dashboard: `http://127.0.0.1:5000/dashboard`

## Example Attack Payloads

- SQLi: `/search?q=' OR 1=1 --`
- XSS: `POST /comment` JSON `{"message":"<script>alert(1)</script>"}`
- Path Traversal: `/file?name=../../etc/passwd`
- Command Injection: `/run?cmd=ls; cat /etc/passwd`
- XXE: `POST /xml` with `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>`

## Testing

```bash
python -m unittest discover -s tests -v
```
