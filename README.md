# 🌐 Webscan CLI by B Dev
v. 1.5

**Webscan CLI** is a command-line tool to scan and analyze websites.  
It supports **standard text output** or **rich output** (colored tables and panels) for supported terminals.  

This tool can check website status, server info, CDN/firewall, TLS, security headers, `robots.txt`, Whois information, and classify websites (School / Organization / Personal).  

> ⚠️ **Important:** Only scan websites you own or have permission to test.

---

## ✨ Features

- ✅ Check website status (online/offline) and response time
- 🖥️ Display server headers, X-Powered-By, cookies, and redirect chains
- 🤖 Read and display `robots.txt`
- 📡 Retrieve Whois information and IPs with reverse DNS
- 🔒 TLS certificate information (validity, issuer, subject)
- 🛡️ Security header analysis
- 🕵️ Fingerprint web technologies (e.g., WordPress, PHP)
- 🏷️ Classify website content: School / Organization / Personal
- 📊 Output in standard text, rich (colored), or JSON
- ⚙️ Optional flags: `--json`, `--rich`

---

## 🖥️ Requirements

- Python 3.8+
- Python libraries:
  - `requests`
  - `beautifulsoup4`
  - `rich` (optional for colored output)
  - `python-whois` (optional for Whois info)

Install dependencies:

```bash
pip install -r requirements.txt


---

⚡ Installation

1. Clone the repository:

git clone https://github.com/Bestther2021/Web-scan.git
cd Web-scan

2. Create a virtual environment (optional but recommended):



python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

3. Install dependencies:



pip install -r requirements.txt

4. Install the ws command globally:



chmod +x install.sh
./install.sh
# or sudo ./install.sh if root privileges are required


---

🏃 Usage

Standard text output

ws http://example.com

Rich output (colored tables and panels)

ws http://example.com --rich

JSON output

ws http://example.com --json

Example output:

🌐 Webscan by B Dev
Scan successfully
----------------------------------
URL        : http://example.com
Web name   : Example Domain
Web status : 200 OK (online)
Response   : 0.345s
Host       : example.com
IPs        : 93.184.216.34
Server     : ECS (dcb/7F13)
CDN / Firewall: Cloudflare
Redirect chain: http://example.com -> https://example.com
Security headers missing: Content-Security-Policy, X-Frame-Options
Robots.txt: found
Fingerprint hints: wordpress
Classification (content analysis): Personal / Blog
Whois Info:
  Domain: example.com
  Registrar: IANA
  Organization: Example Organization
  Country: US
TLS Info:
  Subject: {...}
  Issuer: {...}
  Valid from: Jun 1 00:00:00 2025
  Valid to: Jun 1 00:00:00 2026
  Days left: 270
----------------------------------


---

📌 Notes

ws command works with or without the extra Ws argument for backward compatibility.

Use this tool responsibly and only on sites you are authorized to scan.

For best results, install optional packages rich and python-whois.

Supports emojis in output for better readability! 🎨

---

📄 License

This project is licensed under the MIT License.
See the LICENSE file for details.
