# 🐕 ErrorHound

**Verbose Error Detection Scanner for Burp Suite**

ErrorHound is a Burp Suite extension that automatically detects and analyzes verbose error messages in web applications. It intelligently hunts down information leaks through stack traces, database errors, framework exceptions, and sensitive data exposure.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional-orange)](https://portswigger.net/burp)
[![Python 2.7](https://img.shields.io/badge/Python-2.7-blue)](https://www.python.org/)

---

## Features

### **Intelligent Detection Engine**
- **Multi-Layer Detection**: Status codes, regex patterns, behavioral analysis
- **100+ Error Patterns**: Stack traces, database errors, framework exceptions
- **Confidence Scoring**: 0-100 scale with false positive filtering
- **Syntax Highlighting**: RED highlights on payloads & errors in Burp Issues

### **Smart Testing Methods**
- **HTTP Method Fuzzing**: GET, POST, PUT, DELETE, PATCH, OPTIONS, and custom methods
- **Header Manipulation**: Dynamic header extraction and testing
- **Structure Breaking**: JSON/XML/Form syntax corruption
- **Parameter Injection**: SQL injection, type confusion, boundary testing

### **Advanced Capabilities**
- 🚀 **Early Exit Strategy**: Stops after first finding per category (saves 70-90% requests)
- 🎛️ **3 Scan Modes**: Strict, Balanced, Sensitive (adjustable thresholds)
- 🛑 **Stop Control**: Stop scan anytime with one click
- 📈 **Real-time Statistics**: Track scans, vulnerabilities, and requests
- 🎨 **Modern UI**: Clean interface with results table, logs, and configuration

---

## Installation

### **Prerequisites**
- Burp Suite Professional (tested on 2023.x and newer)
- Jython Standalone JAR (2.7.3 or newer)

### **Steps**

1. **Download ErrorHound**
```bash
   git clone https://github.com/rohmatariow/ErrorHound.git
   cd errorhound
```

2. **Configure Jython in Burp**
   - Go to: `Extender` → `Options` → `Python Environment`
   - Set location of Jython standalone JAR file

3. **Load Extension**
   - Go to: `Extender` → `Extensions` → `Add`
   - Extension type: `Python`
   - Extension file: Select `src/main.py`
   - Click `Next`

4. **Verify Installation**
   - Check `Output` tab for: `[+] ErrorHound loaded successfully`
   - New tab `ErrorHound` should appear in Burp

---

## 📖 Usage

### **Quick Start**

1. **Configure Scanner**
   - Navigate to `ErrorHound` tab
   - Select scan mode: `Strict`, `Balanced`, or `Sensitive`
   - Adjust threshold if needed (default: 15)

2. **Run Active Scan**
   - Right-click any request in Burp
   - Select: `ErrorHound: Scan for Verbose Errors`
   - Watch real-time progress in `Results` tab

3. **View Findings**
   - Check `Results` tab in ErrorHound
   - Check `Target` → `Site map` → `Issues`
   - Click any finding to see highlighted request/response

### **Scan Modes**

| Mode | Threshold | Use Case |
|------|-----------|----------|
| **Strict** | 30 | High confidence only, minimal false positives |
| **Balanced** | 15 | Recommended for most scenarios |
| **Sensitive** | 5 | Catch everything, may have false positives |

### **Understanding Results**

**Severity Levels:**
- 🔴 **HIGH**: Credentials, API keys, secrets exposed
- 🟡 **MEDIUM**: Sensitive config, internal paths (3+ indicators)
- 🟢 **LOW**: General error disclosure (default)

**Results Table Columns:**
- `#` - Finding number
- `Host` - Target hostname
- `Method` - HTTP method tested
- `URL` - Request path
- `Status` - HTTP status code
- `Length` - Response body length
- `Severity` - Risk level
- `Category` - Error type detected
- `Location` - Where payload was injected
- `Score` - Confidence score (0-100)
- `Time` - Detection timestamp

---

## Detection Capabilities

### **Stack Traces**
- Java (Spring, Tomcat, JBoss)
- Python (Django, Flask)
- PHP (Laravel, Symfony)
- .NET (ASP.NET, MVC)
- Node.js (Express)
- Ruby (Rails)
- Go

### **Database Errors**
- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- MongoDB
- SQLite

### **Framework Errors**
- Spring Boot
- Laravel
- Django
- Flask
- Express.js
- ASP.NET
- Ruby on Rails

### **Sensitive Information**
- File paths (`/var/www/`, `C:\inetpub\`, etc.)
- Internal IPs (`192.168.x.x`, `10.x.x.x`)
- Version numbers
- Configuration details
- Database connection strings

---

## Screenshots

### Main Interface
*ErrorHound tab showing configuration, results, and logs*

### Detection Example
*Burp Issues showing detected verbose error with highlighted payload*

### Real-time Statistics
*Live tracking of scans, vulnerabilities, and requests*

---

## Configuration

### **Threshold Settings**

Adjust detection sensitivity:
```
Lower threshold = More sensitive = More findings (may include false positives)
Higher threshold = More strict = High confidence only
```

### **Scan Control**

- **Start Scan**: Right-click request → `ErrorHound: Scan for Verbose Errors`
- **Stop Scan**: Click `Stop Scan` button in Configuration tab
- **Clear Results**: Click `Clear Results` in Results tab
- **Clear Statistics**: Click `Clear Statistics` in Statistics tab

---

## Architecture
```
ErrorHound/
├── Detection Engine
│   ├── Pattern Matching (100+ regex patterns)
│   ├── Behavioral Analysis (response size, timing)
│   └── Confidence Scoring (0-100 scale)
├── Testing Modules
│   ├── Method Tester (HTTP method fuzzing)
│   ├── Header Tester (dynamic header manipulation)
│   ├── Structure Tester (JSON/XML/Form breaking)
│   └── Parameter Tester (injection payloads)
└── Optimization
    ├── Early Exit (stop after first finding per category)
    ├── Baseline Comparison (reduce false positives)
    └── Request Counting (accurate statistics)
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### **Development Setup**
```bash
git clone https://github.com/rohmatariow/ErrorHound.git
cd ErrorHound
# Make changes
# Test in Burp Suite
```

### **Reporting Issues**
Found a bug? [Open an issue](https://github.com/rohmatariow/ErrorHound/issues)

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**@rohmatariow**

- GitHub: [@rohmatariow](https://github.com/rohmatariow)
- X: [@rohmatariow](https://x.com/rohmatariow)

---

## Acknowledgments

- Burp Suite by PortSwigger
- Security research community
- All contributors

---

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before testing any systems you do not own.

---

**Happy Hunting!**
```

---
