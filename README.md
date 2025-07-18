# 🛠️ PHToolBox - Offensive Security Toolkit

**PHToolBox** is an advanced penetration testing toolbox powered by Node.js. It offers a powerful web-based interface for running vulnerability assessments, subdomain and content discovery, security header checks, and proxying traffic via Tor.

> ✅ Developed for bug bounty hunters, red teamers, and security researchers.

---

## 🔍 Features

- 🔸 **HTTP Verb Scanner** – Detect supported HTTP methods.
- 🔸 **Security Headers Checker** – Identify missing security headers.
- 🔸 **Weak SSL Scanner** – Analyze weak SSL configurations.
- 🔸 **Server Header Analyzer** – Reveal server fingerprinting headers.
- 🔸 **Host Header Injection Test** – Check for host header vulnerabilities.
- 🔸 **Content Discovery** – Perform brute-force endpoint discovery with custom wordlists.
- 🔸 **Subdomain Discovery** – Discover subdomains via VirusTotal, Wayback Machine, and brute-force.
- 🔸 **Checklist Viewer** – Load and view pre-built application checklists.
- 🔸 **AI Integration (Gemini)** – De-obfuscate JS code or generate text via Google Gemini API.
- 🔸 **Tor Proxy Integration** – Route traffic through Tor and rotate IPs.
- 🔸 **System Proxy Toggle** – Set/unset system-wide proxy settings via the web UI.
- 🔸 **Wordlist Upload Support** – Upload and manage `.txt` wordlists directly.

---

## 🖥️ Demo

> Runs locally on:  
`http://localhost:9999`

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/PHToolBox.git
cd PHToolBox
npm install
````

---

## 🗝️ Configuration

Create a `keys.js` file in the root with your API keys:

```js
module.exports = {
  GEMINI_API_KEY: 'your-google-gemini-api-key',
  VIRUSTOTAL_API_KEY: 'your-virustotal-api-key'
};
```

---

## 🚀 Usage

> ⚠️ **Run as Administrator/root**

```bash
node run.js
```

Then open your browser to:
`http://localhost:9999`

---

## 🔐 Endpoints

### 🔍 Security APIs

| Method | Endpoint                          | Description                |
| ------ | --------------------------------- | -------------------------- |
| POST   | `/API/testAllMethods`             | Test HTTP methods          |
| POST   | `/API/checkSecurityHeaders`       | Check security headers     |
| POST   | `/API/checkWeakSSL`               | Analyze SSL security       |
| GET    | `/api/getServerHeader?url=`       | Fetch server headers       |
| GET    | `/api/host-header-injection?url=` | Host header injection test |
| GET    | `/getDomainIP?domain=`            | Get IP of domain           |
| GET    | `/waybackurls?domain=`            | Extract archived URLs      |

### 📂 Wordlist Management

| Method | Endpoint                         | Description               |
| ------ | -------------------------------- | ------------------------- |
| POST   | `/api/upload-wordlist`           | Upload wordlist           |
| GET    | `/api/wordlists`                 | List uploaded wordlists   |
| GET    | `/api/wordlist-count?path=`      | Count wordlist entries    |
| POST   | `/api/subdomain-upload-wordlist` | Upload subdomain wordlist |
| GET    | `/api/subdomain-wordlists`       | List subdomain wordlists  |

### 🔎 Discovery

| Method | Endpoint                          | Description                  |
| ------ | --------------------------------- | ---------------------------- |
| GET    | `/api/discovery-stream`           | Stream endpoint discovery    |
| GET    | `/api/subdomain-discovery-stream` | Stream subdomain brute force |
| GET    | `/api/subdomains-online?domain=`  | Get known subdomains         |

### 🤖 Gemini AI

| Method | Endpoint              | Description                 |
| ------ | --------------------- | --------------------------- |
| POST   | `/gemini-AI-generate` | Process prompt using Gemini |

### 🕵️‍♂️ Tor + Proxy

| Method | Endpoint              | Description              |
| ------ | --------------------- | ------------------------ |
| GET    | `/start-tor`          | Start Tor process        |
| POST   | `/tor-rotate`         | Rotate Tor IP            |
| GET    | `/tor-ip`             | Get current Tor IP       |
| GET    | `/stop-tor`           | Stop Tor & disable proxy |
| GET    | `/set-system-proxy`   | Enable system proxy      |
| GET    | `/unset-system-proxy` | Disable system proxy     |
| GET    | `/proxy-status`       | Check proxy status       |

---

## 📁 Directory Structure

```
PHToolBox/
├── API/
│   ├── getVerbRequest.js
│   ├── getMissingSecurityHeader.js
│   ├── getWeakSSL.js
│   ├── getServerHeader.js
│   └── getHostHeaderInjection.js
├── Json/
│   └── static_web_application_checklist.json
├── public/
│   ├── index.html
│   ├── Checklist/
│   └── WaybackUrlView.html
├── wordlists/
├── subdomain_wordlists/
├── tor.exe
├── run.js
└── keys.js
```

---


## 🛡️ Disclaimer

This tool is for **educational** and **authorized testing** purposes only. Use responsibly. The author is not liable for misuse.

---

## 📬 Contact

Created by **kr rathod**
Website: [https://pentesterhelper.in](https://pentesterhelper.in)

---

## ⭐ Support

If you like this project, give it a ⭐ on GitHub!

```
