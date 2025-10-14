# 🔍 SBOM Support Level Analyzer

<div align="center">

**Analyze your Software Bill of Materials (SBOM) to determine component support status and end-of-support dates**

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![SBOM Formats](https://img.shields.io/badge/SBOM-CycloneDX%20%7C%20SPDX-orange)](https://cyclonedx.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](sbom_support_analyzer.py)
[![Security](https://img.shields.io/badge/use-defensive%20security-red)](LICENSE)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Examples](#-examples) • [Contributing](#-contributing) • [Docs](docs/)

</div>

---

## 📋 Overview

A production-ready tool that analyzes SBOM components using **real data** from package registries and repositories to determine:

- 🟢 **Support Level** (Actively Maintained, Maintenance Mode, No Longer Maintained, Abandoned)
- 📅 **End-of-Life Dates** (Data-driven calculations)
- 📊 **Confidence Levels** (Based on data quality)
- 🔍 **Repository Activity** (GitHub commit analysis)
- 📈 **Component Age** (Days since last release)

### Why Use This Tool?

- ✅ **100% Real Data** - No fake data, all from public APIs
- ✅ **Zero Dependencies** - Pure Python standard library
- ✅ **Multi-Format Support** - CycloneDX and SPDX
- ✅ **Production Ready** - Error handling, caching, rate limiting
- ✅ **Open Source** - MIT License with defensive security clause

## 🎯 Features

### Supported SBOM Formats

| Format | Versions | Status |
|--------|----------|--------|
| **CycloneDX** | 1.4, 1.5, 1.6 | ✅ Full Support |
| **SPDX** | 2.2, 2.3 | ✅ Full Support |

### Supported Package Ecosystems

| Ecosystem | API | Repository Analysis |
|-----------|-----|---------------------|
| 🟦 **NuGet** | api.nuget.org | ✅ GitHub |
| 🟥 **NPM** | registry.npmjs.org | ✅ GitHub |
| 🟨 **PyPI** | pypi.org | ✅ GitHub |
| 🟧 **Maven** | search.maven.org | ⚠️ Limited |
| 🟪 **CocoaPods** | trunk.cocoapods.org | ✅ GitHub |
| ⚫ **GitHub** | api.github.com | ✅ Native |

### Support Level Classifications

| Level | Criteria | Action Required |
|-------|----------|----------------|
| 🟢 **ACTIVELY_MAINTAINED** | Release within 12 months + active commits | ✅ Safe to use |
| 🟡 **MAINTENANCE_MODE** | Release within 24 months + security fixes | ⚠️ Monitor updates |
| 🟠 **NO_LONGER_MAINTAINED** | Release within 48 months, no activity | ⚠️ Plan migration |
| 🔴 **ABANDONED** | No release in 48+ months OR archived | ❌ Replace immediately |
| ⚪ **UNKNOWN** | Insufficient data | 🔍 Manual review needed |

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- Internet connection for API access
- (Optional) GitHub Personal Access Token for higher rate limits

### Installation

```bash
# Clone the repository
git clone https://github.com/bharambetejas/sbom-support-analyzer.git
cd sbom-support-analyzer

# Make scripts executable
chmod +x sbom_support_analyzer.py analyze_results.py run_analysis.sh

# Verify installation
python3 sbom_support_analyzer.py --help
```

### Basic Usage

```bash
# 1. (Optional) Set GitHub token for higher rate limits
export GITHUB_TOKEN="ghp_your_token_here"

# 2. Analyze your SBOM
python3 sbom_support_analyzer.py your_sbom.json

# 3. View detailed report
python3 analyze_results.py your_sbom_analyzed_summary.json
```

### Example Output

```
Loading SBOM from: your_sbom.json
Detected format: CycloneDX 1.6
Analyzing 125 components

[1/125] ============================================================
Analyzing: express @ 4.18.0
  Ecosystem: npm
  Last release: 2025-08-15 (59 days ago)
  Fetching repository data from GitHub...
  Last commit: 2025-09-30 (13 days ago)
  Support Level: ACTIVELY_MAINTAINED (Confidence: HIGH)
  End of Life: 2030-08-14

============================================================
ANALYSIS SUMMARY
============================================================
Total components analyzed: 125
  Actively Maintained:     52 ✅
  Maintenance Mode:        28 ⚠️
  No Longer Maintained:    15 ⚠️
  Abandoned:               10 ❌
  Unknown:                 20 🔍

Writing enriched SBOM to: your_sbom_analyzed.json
Writing summary report to: your_sbom_analyzed_summary.json
Done!
```

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Complete user guide with examples (this file) |
| [QUICKSTART.md](docs/QUICKSTART.md) | 5-minute setup guide |
| [STRATEGY.md](docs/STRATEGY.md) | Technical methodology and algorithms |
| [EOL_INDUSTRY_ANALYSIS.md](docs/EOL_INDUSTRY_ANALYSIS.md) | Industry data validating our EOL strategy |
| [SPDX_SUPPORT.md](docs/SPDX_SUPPORT.md) | SPDX-specific documentation |
| [PROJECT_SUMMARY.md](docs/PROJECT_SUMMARY.md) | Project architecture and details |
| [INDEX.md](docs/INDEX.md) | Complete file directory |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |

## 💡 Examples

### Analyze with Limited Components (Testing)

```bash
python3 sbom_support_analyzer.py your_sbom.json --limit 10
```

### Analyze with Custom Output Path

```bash
python3 sbom_support_analyzer.py your_sbom.json -o custom_output.json
```

### Use Easy Launcher Script

```bash
./run_analysis.sh your_sbom.json
```

### Filter Critical Components

```bash
# Show only ABANDONED components
python3 -c "
import json
data = json.load(open('your_sbom_analyzed_summary.json'))
abandoned = [c for c in data['components'] if c['support_level'] == 'ABANDONED']
print(f'Found {len(abandoned)} abandoned components:')
for c in abandoned:
    print(f\"  - {c['name']} @ {c['version']}\")
"
```

### Export to CSV

```bash
python3 -c "
import json, csv
data = json.load(open('your_sbom_analyzed_summary.json'))
with open('report.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, ['name', 'version', 'support_level', 'end_of_support', 'confidence'])
    writer.writeheader()
    writer.writerows([{
        'name': c['name'],
        'version': c['version'],
        'support_level': c['support_level'],
        'end_of_support': c['end_of_support'],
        'confidence': c['confidence']
    } for c in data['components']])
"
```

## 🏗️ How It Works

```
┌─────────────────┐
│  Load SBOM      │
│  (Auto-detect)  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│  Normalize Components       │
│  (SPDX → Common Format)     │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Query Package Registries   │
│  • NuGet, NPM, PyPI, etc.   │
│  • Extract release dates    │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Analyze Repositories       │
│  • GitHub commit activity   │
│  • Archive/deprecated status│
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Calculate Support Level    │
│  • Apply decision matrix    │
│  • Determine EOS date       │
│  • Assess confidence        │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Generate Outputs           │
│  • Enriched SBOM            │
│  • Summary report           │
│  • Analysis statistics      │
└─────────────────────────────┘
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick contribution guide:**
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📊 Project Stats

- **Lines of Code:** ~1,400+
- **Documentation:** 6 comprehensive guides
- **Supported Formats:** 2 (CycloneDX, SPDX)
- **Supported Ecosystems:** 6 package managers
- **External Dependencies:** 0 (Pure Python)
- **Test Coverage:** Manual validation with real SBOMs

## 🔒 Security & Privacy

- ✅ All data processing is local
- ✅ No data sent to third parties
- ✅ Read-only API operations
- ✅ Tokens stored in memory only
- ✅ Defensive security use only

See [LICENSE](LICENSE) for defensive security clause.

## 📝 License

This project is licensed under the MIT License with a defensive security clause - see the [LICENSE](LICENSE) file for details.

**TL;DR:** Free to use for defensive security purposes. Not for malicious use.

## 🙏 Acknowledgments

- Package registry providers (NuGet, NPM, PyPI, Maven, CocoaPods)
- GitHub API for repository analysis
- CycloneDX and SPDX communities

## 📞 Support

- **Documentation:** See [docs/](docs/) folder
- **Issues:** [GitHub Issues](https://github.com/bharambetejas/sbom-support-analyzer/issues)
- **Discussions:** [GitHub Discussions](https://github.com/bharambetejas/sbom-support-analyzer/discussions)

## ⭐ Star History

If you find this tool useful, please consider giving it a star!

---

<div align="center">

**Made with ❤️ for the security community**

[Report Bug](https://github.com/bharambetejas/sbom-support-analyzer/issues) • [Request Feature](https://github.com/bharambetejas/sbom-support-analyzer/issues) • [Documentation](docs/)

</div>
