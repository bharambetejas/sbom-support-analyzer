# Quick Start Guide - Updated SBOM Support Analyzer

## What's New?
The analyzer now uses a **realistic strategy** that only marks components as "Abandoned" or "No longer maintained" when there's explicit evidence. Most stable, mature libraries are now correctly classified as "Actively Maintained" or "Maintenance Mode".

## Run Analysis

### Basic Command
```bash
python3 sbom_support_analyzer.py your_sbom.json
```

### With GitHub Token (Recommended)
```bash
export GITHUB_TOKEN="your_github_token_here"
python3 sbom_support_analyzer.py your_sbom.json
```

### Test First (analyze only 10 components)
```bash
python3 sbom_support_analyzer.py your_sbom.json --limit 10
```

## Expected Results

You should now see:
- ✅ **Most components in "Actively Maintained"** (within 5 years)
- ✅ **Few components in "No Longer Maintained"** (>5 years old, not deprecated)
- ✅ **Very few in "Abandoned"** (only explicitly deprecated/archived)

### Example Output
```
Total components analyzed: 237
  Actively Maintained:     230  ← Within 5 years (active + stable)
  No Longer Maintained:    5    ← Old but not explicitly abandoned
  Abandoned:               2    ← Only explicit evidence
  Unknown:                 0
```

## What Each Category Means (FDA-Aligned)

### 🟢 ACTIVELY_MAINTAINED
- Release within 5 years
- Covers both active development AND stable libraries
- **Action:** Safe to use

### 🟡 NO_LONGER_MAINTAINED
- Release >5 years ago
- Not explicitly deprecated or archived
- May still be functional but poses risk
- **Action:** Review and consider updating

### 🔴 ABANDONED
- Repository explicitly archived, OR
- Package explicitly deprecated in registry, OR
- Official abandonment statement on website
- **Action:** Plan migration immediately

### ⚪ UNKNOWN
- Cannot access data
- **Action:** Manual review required

## Next Steps

1. **Run the analyzer** on your SBOM
2. **Review ABANDONED components** (should be very few)
3. **Check UNKNOWN components** (may need manual review)
4. **Trust MAINTENANCE_MODE** for stable libraries (crypto, compression, etc.)

## Key Philosophy

> Lack of recent releases ≠ Abandoned software

Many mature libraries are stable and don't need updates. The analyzer now recognizes this reality.
