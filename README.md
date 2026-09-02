# CyberFusion

**Unified Security Scanning & Intelligence Platform**

CyberFusion is a comprehensive security scanning platform that fuses the best capabilities of multiple security tools (Nettacker, scan4all, and RapidScan) into a single, modular, and scalable framework.

## 🎯 Vision

CyberFusion transforms fragmented security scanning into a unified intelligence platform by:

- **Fusing** discovery, scanning, correlation, and risk analysis
- **Orchestrating** multiple security engines seamlessly
- **Correlating** findings across tools to reduce false positives
- **Scoring** risk with comprehensive analysis
- **Visualizing** threats on an interactive global dashboard (Control Layer)

## 🏗️ Architecture

```
CYBERFUSION
    │
    ├── FusionCore        → Core scanning engine
    ├── FusionScan        → Multiple scanners (nmap, nuclei, etc)
    ├── FusionRecon       → Reconnaissance modules
    ├── FusionDetect      → Detection & correlation
    ├── FusionRisk        → Risk analysis & scoring
    ├── FusionReport      → Report generation
    ├── FusionWeb         → Dashboard & API
    └── FusionAI          → Intelligent analysis
```

## 📦 Project Structure

```
cyberfusion/
├── cmd/cyberfusion/          # CLI entry point
│   └── cmd/                  # Cobra commands
├── internal/
│   ├── domain/              # Core models
│   ├── database/            # Database layer (GORM)
│   ├── orchestrator/        # Scan orchestration
│   └── integration/         # Scanner adapters
├── Dockerfile               # Container image
├── docker-compose.yml       # Development environment
└── README.md
```

## 🚀 Quick Start

### Prerequisites

- Go 1.22+
- Docker & Docker Compose
- nmap, nuclei (for full functionality)

### Installation

```bash
git clone https://github.com/bijoian/CyberFusion.git
cd CyberFusion
go mod download
```

### Build

```bash
go build -o cyberfusion ./cmd/cyberfusion
```

### Run a Scan

```bash
./cyberfusion scan --targets 192.168.1.0/24 --modules port_scan,service_detection
```

### Docker

```bash
docker-compose up
```

## 📋 Features (V0.1)

- ✅ Modular architecture
- ✅ Multi-target scanning
- ✅ Port discovery
- ✅ Service detection
- ✅ Finding correlation
- ✅ Risk scoring (0-100)
- ✅ HTML/JSON reporting
- ✅ SQLite database
- ✅ CLI interface
- ✅ GeoLocation support

## 🔜 Roadmap

### V0.2 (Control Layer)
- REST API
- PostgreSQL support
- Multiple agent management
- Central dashboard

### V0.3 (Intelligence)
- Threat intelligence integration
- CVE/CWE correlation
- Advanced risk analysis
- ML-based detection

### V0.4 (Global Dashboard)
- Interactive threat map (FortiGuard-style)
- Real-time visualization
- Global threat analytics
- Multi-region support

## 📄 License

Apache License 2.0 - See LICENSE file for details

## 🙏 Acknowledgments

Built by integrating concepts from:
- [OWASP Nettacker](https://github.com/OWASP/Nettacker)
- [scan4all](https://github.com/GhostTroops/scan4all)
- [RapidScan](https://github.com/skavngr/rapidscan)

## 📞 Support

For issues and questions, please open a GitHub issue.
