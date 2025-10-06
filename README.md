# SecurityCheckTool v1.0.0 🚀

A lightweight Java CLI tool for **passive website security checks**.  
Check headers, TLS, robots.txt, and basic server info quickly from your terminal.

---

## Features

- HTTPS/TLS certificate validation
- Common security headers:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Server header exposure check
- `.git` folder exposure
- `robots.txt` existence and preview
- Simple HTML secret pattern scan

⚠️ **Passive checks only** — no active attacks are performed.

---

## Usage

### Direct Java

Download the JAR from [GitHub Releases](https://github.com/Harsha5659/SecurityCheckTool/releases):

```bash
java -jar security-check-tool-v1.0.0.jar https://example.com
