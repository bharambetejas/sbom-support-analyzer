# Quick Start Guide

## 5-Minute Setup

### Step 1: Verify Python
```bash
python3 --version
# Should show Python 3.7 or higher
```

### Step 2: Get a GitHub Token (Optional but Recommended)

1. Visit: https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Name: "SBOM Analyzer"
4. Scope: Check `public_repo`
5. Click "Generate token"
6. Copy the token (starts with `ghp_`)

### Step 3: Set Your Token
```bash
export GITHUB_TOKEN="ghp_your_token_here"
```

### Step 4: Run Analysis
```bash
# Test with 10 components first
python3 sbom_support_analyzer.py your_sbom.cdx.json --limit 10

# If successful, run full analysis
python3 sbom_support_analyzer.py your_sbom.cdx.json
```

### Step 5: Review Results
```bash
# View summary statistics
python3 -m json.tool your_sbom.cdx_analyzed_summary.json | head -30

# Count by support level
python3 -c "
import json
data = json.load(open('your_sbom.cdx_analyzed_summary.json'))
print('Support Level Summary:')
for level, count in data['summary'].items():
    print(f'  {level}: {count}')
"
```

## Expected Runtime

- **10 components**: ~30 seconds
- **50 components**: ~3 minutes
- **100-150 components**: ~8-12 minutes
- **500+ components**: ~30-45 minutes

## What You'll Get

1. **`*_analyzed.json`** - Your original SBOM with support data added
2. **`*_summary.json`** - Detailed analysis report with statistics

## Interpreting Results

### Support Levels Quick Reference

| Level | What It Means | Action |
|-------|---------------|--------|
| 🟢 ACTIVELY_MAINTAINED | Regular updates, active development | ✅ Safe to use |
| 🟡 MAINTENANCE_MODE | Security fixes only, stable | ⚠️ Monitor for updates |
| 🟠 NO_LONGER_MAINTAINED | No recent activity | ⚠️ Plan migration |
| 🔴 ABANDONED | Dead project, no support | ❌ Replace urgently |
| ⚪ UNKNOWN | Cannot determine | 🔍 Manual review needed |

## Common Issues

### "Rate limited (403)"
**Fix**: Add GitHub token (see Step 2)

### "Failed to fetch package data"
**Meaning**: Package not found in public registry
**Action**: Check if it's a private/internal package

### Script runs slowly
**Normal**: Each component requires 2-3 API calls
**Tip**: Use `--limit` to test first

## Next Steps

After analysis, you can:

1. **Identify Risks**: Focus on ABANDONED and NO_LONGER_MAINTAINED components
2. **Plan Updates**: Review components near end-of-support
3. **Track Changes**: Re-run monthly to monitor status changes
4. **Share Results**: Import enriched SBOM into security tools

## Need Help?

- Review [README.md](README.md) for full documentation
- Check [STRATEGY.md](STRATEGY.md) for methodology details
- Verify your SBOM is CycloneDX 1.6 format

## Pro Tips

### Batch Processing
```bash
# Analyze multiple SBOMs
for sbom in *.json; do
    echo "Analyzing $sbom..."
    python3 sbom_support_analyzer.py "$sbom"
done
```

### Filter Results
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
# Create CSV report
python3 -c "
import json
import csv
data = json.load(open('your_sbom_analyzed_summary.json'))
with open('support_report.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['name', 'version', 'support_level', 'end_of_support', 'confidence'])
    writer.writeheader()
    for c in data['components']:
        writer.writerow({
            'name': c['name'],
            'version': c['version'],
            'support_level': c['support_level'],
            'end_of_support': c['end_of_support'],
            'confidence': c['confidence']
        })
print('Report saved to support_report.csv')
"
```

## Automation

### Cron Job (Weekly Analysis)
```bash
# Add to crontab (crontab -e)
0 9 * * 1 cd /path/to/sbom && python3 sbom_support_analyzer.py sbom.json
```

### CI/CD Integration
```bash
# Add to your pipeline
- name: Analyze SBOM
  run: |
    export GITHUB_TOKEN="${{ secrets.GITHUB_TOKEN }}"
    python3 sbom_support_analyzer.py sbom.json
    python3 check_abandoned.py  # Your custom check
```

## Success Example

```
$ python3 sbom_support_analyzer.py your_sbom.cdx.json

Loading SBOM from: your_sbom.cdx.json
Analyzing 125 components
[1/125] ============================================================
Analyzing: example-package @ 2.5.0
  Ecosystem: npm
  Last release: 2025-08-15 (59 days ago)
  Support Level: ACTIVELY_MAINTAINED (Confidence: HIGH)
  End of Support: N/A (actively maintained)
...

============================================================
ANALYSIS SUMMARY
============================================================
Total components analyzed: 125
  Actively Maintained:     52 ✅
  Maintenance Mode:        28 ⚠️
  No Longer Maintained:    15 ⚠️
  Abandoned:               10 ❌
  Unknown:                 20 🔍

API Request counts:
  npm: 45
  nuget: 38
  github: 62

Writing enriched SBOM to: your_sbom_analyzed.json
Writing summary report to: your_sbom_analyzed_summary.json
Done!
```

You're all set! 🚀
