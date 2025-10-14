# SBOM Support Level Analyzer - File Index

## Quick Start
👉 **New users start here**: [QUICKSTART.md](QUICKSTART.md)

## Core Files

### Scripts (Executable)

1. **[sbom_support_analyzer.py](sbom_support_analyzer.py)** ⭐ MAIN SCRIPT
   - Complete SBOM analysis tool
   - Queries package registries and repositories
   - Calculates support levels and end-of-life dates
   - Generates enriched SBOM and summary reports
   - ~800 lines, production-ready

2. **[analyze_results.py](analyze_results.py)** 📊 REPORTING TOOL
   - Generates detailed analysis reports
   - Shows support level breakdowns
   - Lists critical components
   - Provides actionable recommendations
   - ~350 lines

3. **[run_analysis.sh](run_analysis.sh)** 🚀 EASY LAUNCHER
   - User-friendly wrapper script
   - Automatic validation and checks
   - Colored output and progress tracking
   - Combines analyzer + report generation

### Documentation

4. **[README.md](README.md)** 📖 USER GUIDE
   - Complete usage documentation
   - Command-line options
   - Output format descriptions
   - Troubleshooting guide
   - Examples and best practices
   - ~400 lines

5. **[STRATEGY.md](STRATEGY.md)** 🧠 METHODOLOGY
   - Detailed analysis strategy
   - Support level definitions
   - Data sources and APIs
   - Calculation algorithms
   - Decision logic flowcharts
   - ~300 lines

6. **[QUICKSTART.md](QUICKSTART.md)** ⚡ 5-MINUTE GUIDE
   - Step-by-step setup
   - Quick examples
   - Common commands
   - Pro tips and tricks
   - ~200 lines

7. **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** 📋 OVERVIEW
   - Project architecture
   - Technical details
   - Validation results
   - Performance characteristics
   - ~300 lines

9. **[INDEX.md](INDEX.md)** 📑 THIS FILE
9. **[SPDX_SUPPORT.md](SPDX_SUPPORT.md)** 📘 SPDX Guide
   - SPDX 2.3 support details
   - Format differences and mapping
   - SPDX-specific examples
   - File directory and descriptions

## Data Files

Your SBOM files go here. After running the analyzer, you'll have:

- **`your_sbom.cdx.json`** - Your original CycloneDX or SPDX SBOM (input)
- **`your_sbom_analyzed.json`** - Enriched SBOM with support data (output)
- **`your_sbom_analyzed_summary.json`** - Analysis summary report (output)

## File Organization

```
.
├── Core Scripts
│   ├── sbom_support_analyzer.py  ⭐ Main analysis script
│   ├── analyze_results.py        📊 Report generator
│   └── run_analysis.sh            🚀 Easy launcher
│
├── Documentation
│   ├── QUICKSTART.md              ⚡ Start here (5 min)
│   ├── README.md                  📖 Full user guide
│   ├── STRATEGY.md                🧠 Technical methodology
│   ├── PROJECT_SUMMARY.md         📋 Project overview
│   └── INDEX.md                   📑 This file
│
└── Data Files (your SBOM files go here)
    ├── your_sbom.cdx.json                 📦 Input SBOM
    ├── your_sbom_analyzed.json            ✓ Enriched output
    └── your_sbom_analyzed_summary.json    ✓ Analysis report
```

## Usage Workflows

### Workflow 1: First Time User (Recommended)
```bash
1. Read QUICKSTART.md (5 minutes)
2. Run: ./run_analysis.sh your_sbom.cdx.json --limit 10
3. Review output and summary
4. Run full analysis: ./run_analysis.sh your_sbom.cdx.json
```

### Workflow 2: Python Developer
```bash
1. Read STRATEGY.md for methodology
2. Run: python3 sbom_support_analyzer.py --help
3. Execute: python3 sbom_support_analyzer.py your_sbom.cdx.json
4. Analyze: python3 analyze_results.py your_sbom_analyzed_summary.json
```

### Workflow 3: Quick Analysis
```bash
1. Set token: export GITHUB_TOKEN="ghp_xxx"
2. Run: ./run_analysis.sh your_sbom.cdx.json
3. Review console output for summary
```

## Key Features by File

### sbom_support_analyzer.py
- ✅ Supports 6 ecosystems (NuGet, NPM, PyPI, Maven, CocoaPods, GitHub)
- ✅ Real API integrations (no mock data)
- ✅ GitHub repository analysis
- ✅ Smart caching
- ✅ Rate limiting
- ✅ Progress tracking
- ✅ Error handling
- ✅ Confidence scoring

### analyze_results.py
- ✅ Support level breakdown
- ✅ Confidence distribution
- ✅ Age distribution analysis
- ✅ Upcoming EOL warnings
- ✅ Critical component lists
- ✅ Actionable recommendations

### run_analysis.sh
- ✅ Interactive prompts
- ✅ Token validation
- ✅ File existence checks
- ✅ Colored output
- ✅ Error handling
- ✅ Auto-report generation

## File Sizes

| File | Lines | Size | Type |
|------|-------|------|------|
| sbom_support_analyzer.py | ~800 | 35KB | Python |
| analyze_results.py | ~350 | 13KB | Python |
| run_analysis.sh | ~150 | 5KB | Bash |
| README.md | ~400 | 20KB | Markdown |
| STRATEGY.md | ~300 | 15KB | Markdown |
| QUICKSTART.md | ~200 | 10KB | Markdown |
| PROJECT_SUMMARY.md | ~300 | 18KB | Markdown |

## Dependencies

**All scripts**: Python 3.7+ standard library only
- ✅ No pip install required
- ✅ No external packages
- ✅ Zero dependencies

## Support Level Definitions (Quick Reference)

| Level | Symbol | Meaning | Action |
|-------|--------|---------|--------|
| ACTIVELY_MAINTAINED | 🟢 | Recent releases, active commits | ✅ Safe |
| MAINTENANCE_MODE | 🟡 | Security fixes only | ⚠️ Monitor |
| NO_LONGER_MAINTAINED | 🟠 | No recent activity | ⚠️ Plan migration |
| ABANDONED | 🔴 | Dead project | ❌ Replace |
| UNKNOWN | ⚪ | Cannot determine | 🔍 Investigate |

## Output Files (Generated)

When you run the analyzer, it creates:

1. **`<sbom>_analyzed.json`**
   - Original SBOM + support metadata
   - Same structure, enhanced properties
   - Import into security tools

2. **`<sbom>_analyzed_summary.json`**
   - Analysis statistics
   - Component-by-component results
   - Timestamps and metadata

## Common Commands

```bash
# Basic analysis
python3 sbom_support_analyzer.py your_sbom.cdx.json

# With GitHub token
python3 sbom_support_analyzer.py your_sbom.cdx.json --token ghp_xxx

# Limited test run
python3 sbom_support_analyzer.py your_sbom.cdx.json --limit 10

# Generate report
python3 analyze_results.py your_sbom_analyzed_summary.json

# Easy mode (all-in-one)
./run_analysis.sh your_sbom.cdx.json
```

## Getting Help

1. **Quick start**: Read [QUICKSTART.md](QUICKSTART.md)
2. **Full guide**: Read [README.md](README.md)
3. **Methodology**: Read [STRATEGY.md](STRATEGY.md)
4. **Technical details**: Read [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)
5. **Command help**: Run `python3 sbom_support_analyzer.py --help`

## What Makes This Special

### 100% Real Data
- ✅ Actual API calls to public registries
- ✅ Live repository analysis
- ✅ Real release dates
- ✅ Authentic commit history
- ❌ NO fake data
- ❌ NO random values
- ❌ NO placeholders

### Production Quality
- ✅ Comprehensive error handling
- ✅ Rate limiting and caching
- ✅ Progress tracking
- ✅ Detailed logging
- ✅ Confidence levels
- ✅ Validated results

### Zero Dependencies
- ✅ Python standard library only
- ✅ No pip install needed
- ✅ No version conflicts
- ✅ Works anywhere

## API Integrations

The analyzer connects to these real APIs:

1. **NuGet API** - `api.nuget.org`
2. **NPM Registry** - `registry.npmjs.org`
3. **PyPI** - `pypi.org`
4. **Maven Central** - `search.maven.org`
5. **CocoaPods Trunk** - `trunk.cocoapods.org`
6. **GitHub API** - `api.github.com`

All connections use standard HTTPS REST APIs with proper error handling.

## Version Information

- **Created**: October 13, 2025
- **Format**: CycloneDX 1.6
- **Python**: 3.7+ required
- **Status**: Production ready

## License

Provided for defensive security analysis purposes only.

---

**👉 Ready to start? Open [QUICKSTART.md](QUICKSTART.md) and follow the 5-minute guide!**
