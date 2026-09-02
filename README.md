# CyberFusion

** Security Scanning & Intelligence Platform**

CyberFusion is a comprehensive security scanning platform that fuses the best capabilities of multiple security tools inspirada a single, modular, and scalable framework.

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
│       ├── nmap/            # Nmap integration
│       └── nuclei/          # Nuclei integration
├── Dockerfile               # Container image
├── docker-compose.yml       # Development environment
└── README.md
```

## 🚀 Quick Start

### Prerequisites

- Go 1.22+
- Docker & Docker Compose
- **nmap** (for port scanning)
- **nuclei** (optional; required only with `--modules nuclei`)

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
# Single target
./cyberfusion scan --targets 192.168.1.1

# Multiple targets
./cyberfusion scan --targets 192.168.1.1,192.168.1.2,192.168.1.3

# CIDR range
./cyberfusion scan --targets 192.168.1.0/24

# With specific ports
./cyberfusion scan --targets example.com --options '{"ports": "22,80,443"}'

# Debug mode
./cyberfusion scan --targets example.com --debug

# Nuclei vulnerability scan against an explicitly supplied target
./cyberfusion scan --targets https://example.com --modules nuclei
```

### Docker

```bash
# Build image
docker build -t cyberfusion .

# Run scan
docker run --rm cyberfusion scan --targets 192.168.1.1
```

## 📋 Features (V0.1)

### ✅ Implemented
- Modular architecture
- Multi-target scanning
- **Port discovery (nmap)** ✨ NEW
- **Service detection (nmap)** ✨ NEW
- **Vulnerability detection** ✨ NEW
- Finding correlation
- Risk scoring (0-100)
- HTML/JSON reporting
- SQLite database
- CLI interface
- GeoLocation support

### 🔄 In Progress
- Nuclei integration
- Full CVE database
- API REST endpoints

## 📊 Example Output

```
$ ./cyberfusion scan --targets 192.168.1.1

CYBERFUSION
════════════════════════════════════════════════════

Target: 192.168.1.1
Scan ID: CF-2026-000001

[1] Discovery ............... DONE
[2] Ports ................... DONE ✓
[3] Services ................ DONE ✓
[4] HTTP .................... DONE
[5] Fingerprint ............. DONE ✓
[6] Vulnerability ........... DONE ✓
[7] Correlation ............. DONE
[8] Risk Analysis ........... DONE

════════════════════════════════════════════════════
RESULTS
════════════════════════════════════════════════════

Assets             1
Open ports         4
Services           4
Technologies       3

Critical           0
High               2
Medium             1
Low                1
Info               0

Risk Score: 35/100
Duration: 12 seconds
════════════════════════════════════════════════════
```

## 🎯 Roadmap

### V0.1 ✅ (Current)
- Nmap integration (port scanning, service detection)
- Basic findings correlation
- Risk scoring
- Local CLI scanning

### V0.2 (Next - 2-3 weeks)
- REST API endpoints
- PostgreSQL support
- Multiple agent management
- Central Control dashboard

### V0.3 (3-4 weeks)
- Nuclei vulnerability scanning
- CVE/CWE database integration
- Advanced risk analysis
- ML-based detection

### V0.4 (Control Layer - 4-5 weeks)
- Interactive threat map (FortiGuard-style)
- Real-time visualization
- Global threat analytics
- Multi-region support

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific test
go test -run TestParsePortLine ./internal/integration/nmap

# Generate coverage report
go test -cover ./...
```

## 📝 Documentation

- [Installation Guide](docs/INSTALL.md)
- [Usage Guide](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)

## 📜 License

Apache License 2.0 - See LICENSE file for details

## 🙏 Acknowledgments

Built with inspiration from the Repertories :
- [OWASP Nettacker](https://github.com/OWASP/Nettacker)
- [scan4all](https://github.com/GhostTroops/scan4all)
- [RapidScan](https://github.com/skavngr/rapidscan)

## 📞 Support

For issues and questions, please open a GitHub issue.

---

