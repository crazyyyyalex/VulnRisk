# 🛡️ VulnRisk - Open Source Vulnerability Risk Assessment Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![License: Commercial](https://img.shields.io/badge/License-Commercial-blue.svg)](https://www.animogovcon.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

> **Stop chasing CVSS scores. Start managing real risk.**

VulnRisk is an open-source vulnerability risk assessment platform that provides transparent, context-aware risk scoring beyond basic CVSS. Perfect for local development and testing.

## 🚀 **Quick Start (5 minutes)**

```bash
# Clone the repository
git clone https://github.com/GurkhaShieldForce/vulnrisk_public.git vulnrisk
cd vulnrisk

# Run the setup script
./setup.sh
```

**What You Get** (default ports; configurable via `.env`):
- ✅ **Frontend**: http://localhost:3000  
- ✅ **Backend API**: http://localhost:8000  
- ✅ **API Docs**: http://localhost:8000/docs  
- ✅ **Database**: PostgreSQL on localhost:5432  

If a default port is already in use, `./setup.sh` picks the next free port and writes it to `.env`. Copy `.env.example` to customize ports before setup.

## 🎯 **Why VulnRisk?**

| Problem | Solution |
|---------|----------|
| **10,000+ vulnerability alerts** | **90% noise reduction** through context-aware scoring |
| **CVSS scores don't reflect real risk** | **Transparent risk scoring** with complete calculation breakdown |
| **Expensive enterprise tools** | **Open source** with zero cost |
| **Black-box AI scoring** | **100% transparent** methodology |

## 🏗️ **Local Development Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend API   │    │   Database      │
│   (React/TS)    │◄──►│   (FastAPI)     │◄──►│   (PostgreSQL)  │
│   Port: 3000    │    │   Port: 8000    │    │   Port: 5432    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔒 **Security Features**

- **Input Validation**: SQL injection, XSS protection  
- **Security Headers**: CSP, HSTS, X-Frame-Options  
- **Rate Limiting**: Request throttling  
- **Audit Logging**: Comprehensive activity tracking  

## 📊 **Key Features**

### **Core Risk Assessment**
- ✅ Vulnerability scanning and analysis  
- ✅ Risk scoring with AI/ML models  
- ✅ Exportable reports (PDF/Excel)

### **Resilient CVE Data**
- ✅ **Multi-source lookups** — NVD first, [Shodan CVEDB](https://cvedb.shodan.io) as a keyless backup  
- ✅ **Survives NVD throttling** and CVEs still awaiting NVD analysis  
- ✅ **Source provenance** on every result, so you know which feed answered  

See [CVE Data Sources](DEVELOPER_SETUP.md#-cve-data-sources) for configuration.

### **AI/ML Analytics**
- ✅ Risk prediction models  
- ✅ Anomaly detection  
- ✅ Trend analysis  
- ✅ Intelligent recommendations  

## 🛠️ **Development Setup**

### **Prerequisites**
- Docker & Docker Compose  
- Git  

For running the backend outside Docker, install [uv](https://docs.astral.sh/uv/) and Python 3.13+, then `cd backend && uv sync --all-groups && make dev`.

### **Local Development**
```bash
# Clone and setup
git clone https://github.com/GurkhaShieldForce/vulnrisk_public.git vulnrisk
cd vulnrisk
./setup.sh

# Development commands
docker compose logs -f          # View logs
docker compose restart          # Restart services
docker compose down            # Stop services
docker compose down -v         # Reset everything
```

## 🤝 **Contributing**

We welcome community contributions!  
Please see our [Contributing Guide](CONTRIBUTING.md) for details.

> **Note:** Contributions made to this public repository apply only to the **open-source (MIT)** version.  
> Our **commercial edition** is maintained separately in a private repository and does not include community code.

### **Quick Start for Contributors**
```bash
# Fork the repository
git clone https://github.com/GurkhaShieldForce/vulnrisk_public.git vulnrisk
cd vulnrisk

# Set up development environment
./setup.sh

# Make your changes
git checkout -b feature/amazing-feature
# ... make changes ...

# Submit a pull request
git push origin feature/amazing-feature
```

## 📚 **Documentation**

- **[Developer Setup](DEVELOPER_SETUP.md)** - Detailed setup guide  
- **[API Documentation](http://localhost:8000/docs)** - Interactive API docs  

## 🆘 **Support**

- **GitHub Issues**: [Report bugs and request features](https://github.com/GurkhaShieldForce/vulnrisk_public/issues)

## 📄 **License**

VulnRisk is **dual-licensed** under:

- **🟢 MIT License** – For open-source, personal, and research use.  
- **💼 Commercial License** – Required for enterprise, SaaS, or for-profit use.  

See the [LICENSE](LICENSE) file for full terms.  
For commercial licensing or enterprise inquiries, visit **[www.animogovcon.com](https://www.animogovcon.com)**.

## 🎉 **Getting Started**

**Ready to start?** Run `./setup.sh` and you'll have a fully functional VulnRisk environment in 5 minutes!  

**Need help?** Check our [Developer Setup Guide](DEVELOPER_SETUP.md) for detailed instructions.
