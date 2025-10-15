# 🔍 SBOM Support Level Analyzer

<div align="center">

**Analyze your Software Bill of Materials (SBOM) to determine component support status and end-of-support dates**

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![SBOM Formats](https://img.shields.io/badge/SBOM-CycloneDX%20%7C%20SPDX-orange)](https://cyclonedx.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](sbom_support_analyzer.py)
[![Security](https://img.shields.io/badge/use-defensive%20security-red)](LICENSE)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Examples](#-examples) • [Docs](docs/)

</div>

---

## 📋 Overview

A production-ready tool that analyzes SBOM components using **real data** from package registries and repositories to determine:

- 🟢 **Support Level** (FDA-aligned: Actively Maintained, No Longer Maintained, Abandoned)
- 📅 **End-of-Life Dates** (Product lifecycle-based)
- 📊 **Confidence Levels** (Based on data quality)
- 🔍 **Repository Activity** (GitHub commit analysis)
- 📈 **Component Age** (Days since last release)

### Why Use This Tool?

- ✅ **100% Real Data** - No fake data, all from public APIs
- ✅ **Version-Specific Analysis** - Analyzes the exact version in your SBOM, not just latest releases
- ✅ **Framework-Aware** - Detects .NET, Java, Python, Node.js runtime components and uses framework support lifecycle
- ✅ **Product-Based EOL** - Component EOL tied to product lifecycle (realistic vendor model)
- ✅ **Realistic Strategy** - Only marks as ABANDONED when explicitly deprecated/archived
- ✅ **Zero Dependencies** - Pure Python standard library
- ✅ **Multi-Format Support** - CycloneDX and SPDX
- ✅ **URL Fallback** - Works with packages that don't have PURLs but have repository URLs
- ✅ **Production Ready** - Error handling, caching, rate limiting

## 🎯 Features

### 🎯 Key Capabilities

#### Version-Specific Analysis
The analyzer determines support status based on the **exact version** specified in your SBOM, not just the latest version of the package. This is crucial for security and compliance:

```
Example: Google.Protobuf @ 3.21.7
✅ Analyzes version 3.21.7 (released 2022-09-29)
❌ Does NOT use latest version 4.x (released 2025)
Result: Correctly classified based on version age and activity
```

#### URL Fallback for Packages Without PURLs
Components without Package URLs (PURLs) are still analyzed using repository URLs from `externalReferences`:

```
Example: JamesNK/Newtonsoft.Json @ Json.NET 2.0
✅ No PURL → Falls back to GitHub URL
✅ Finds version-specific release tag
✅ Accurately classifies based on version age
```

#### Smart Version Pattern Matching
Handles various version formats and tag naming conventions:
- Standard versions: `1.2.3`, `v1.2.3`
- Named versions: `Json.NET 2.0`, `Release 4.5`
- Tag formats: `v1.2.3`, `1.2.3-release`, `package_1.2.3`

#### Framework-Aware Classification
Runtime and framework components are classified based on their parent framework's support lifecycle:

```
Example: runtime.native.System.IO.Ports @ 8.0.0
✅ Detected as .NET 8 framework component
✅ Uses .NET 8 LTS support lifecycle (EOL: 2026-11-10)
✅ HIGH confidence classification
```

**Supported Frameworks:**
- **.NET:** 6.0-9.0, Framework 4.x (detects `System.*`, `Microsoft.*`, `runtime.*`)
- **Java:** 8, 11, 17, 21 (detects `java.*`, `javax.*`, `jakarta.*`)
- **Python:** 3.8-3.13 (detects `python`, `cpython`)
- **Node.js:** 14-22 (detects `node`, `nodejs`)
- **Spring:** Framework 5.x-6.x, Boot 2.x-3.x (detects `spring-*`, `org.springframework.*`)

### Supported SBOM Formats

| Format | Versions | Status |
|--------|----------|--------|
| **CycloneDX** | 1.4, 1.5, 1.6 | ✅ Full Support |
| **SPDX** | 2.2, 2.3 | ✅ Full Support |

### Supported Package Ecosystems

| Ecosystem | API | Repository Analysis | Version-Specific |
|-----------|-----|---------------------|------------------|
| 🟦 **NuGet** | api.nuget.org | ✅ GitHub | ✅ Yes |
| 🟥 **NPM** | registry.npmjs.org | ✅ GitHub | ✅ Yes |
| 🟨 **PyPI** | pypi.org | ✅ GitHub | ✅ Yes |
| 🟧 **Maven** | search.maven.org | ⚠️ Limited | ⚠️ Latest only |
| 🟪 **CocoaPods** | trunk.cocoapods.org | ✅ GitHub | ⚠️ Latest only |
| ⚫ **GitHub** | api.github.com | ✅ Native | ✅ Tag/Release lookup |
| 🔵 **GitLab** | gitlab.com API | ✅ Native | ⚠️ Latest only |
| 🟠 **Bitbucket** | bitbucket.org API | ✅ Native | ⚠️ Latest only |

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

# 2. Analyze your SBOM with product EOL date
python3 sbom_support_analyzer.py your_sbom.json -e 2030-12-31

# Or use interactive mode (prompts for EOL date)
python3 sbom_support_analyzer.py your_sbom.json

# 3. View detailed report
python3 analyze_results.py your_sbom_analyzed_summary.json
```

### Example Output

```
======================================================================
PRODUCT END-OF-LIFE DATE
======================================================================
Enter the product's end-of-life date. This date will be used as the
EOL for all actively maintained and maintenance mode components.
Format: YYYY-MM-DD (e.g., 2030-12-31)
----------------------------------------------------------------------
Product EOL Date: 2030-12-31
✓ Using product EOL date: 2030-12-31
======================================================================

Loading SBOM from: your_sbom.json
Detected format: CycloneDX 1.6
Analyzing 125 components
Product End-of-Life Date: 2030-12-31

[1/125] ============================================================
Analyzing: express @ 4.18.0
  Ecosystem: npm
  Last release: 2022-08-15 (1157 days ago)
  Fetching repository data from GitHub...
  Last commit: 2023-09-30 (743 days ago)
  Support Level: MAINTENANCE_MODE (Confidence: MEDIUM)
  End of Life: 2030-12-31

============================================================
ANALYSIS SUMMARY
============================================================
Total components analyzed: 125
  Actively Maintained:     120 ✅
  No Longer Maintained:    3 ⚠️
  Abandoned:               2 ❌
  Unknown:                 0 🔍

Writing enriched SBOM to: your_sbom_analyzed.json
Writing summary report to: your_sbom_analyzed_summary.json
Done!
```

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Complete user guide with examples (this file) |
| [QUICK_START.md](docs/QUICK_START.md) | Quick reference guide |
| [STRATEGY.md](docs/STRATEGY.md) | Analysis strategy and methodology |
| [EOL_APPROACH.md](docs/EOL_APPROACH.md) | Product-based EOL model explanation |
| [CHANGELOG.md](CHANGELOG.md) | Version history and changes |

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
