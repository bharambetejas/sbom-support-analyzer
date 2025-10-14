# Examples

This directory contains sample SBOM files for testing and demonstration purposes.

## Files

### `sample_cyclonedx.json`
- **Format:** CycloneDX 1.6
- **Components:** 3 (express, lodash, requests)
- **Use:** Test CycloneDX format analysis

### `sample_spdx.json`
- **Format:** SPDX 2.3
- **Packages:** 3 (express, lodash, requests)
- **Use:** Test SPDX format analysis

## Usage

### Analyze Sample CycloneDX SBOM

```bash
python3 sbom_support_analyzer.py examples/sample_cyclonedx.json
```

Expected output:
- Detects CycloneDX 1.6 format
- Analyzes 3 components
- Queries NPM and PyPI registries
- Fetches GitHub repository data
- Generates enriched SBOM and summary

### Analyze Sample SPDX SBOM

```bash
python3 sbom_support_analyzer.py examples/sample_spdx.json
```

Expected output:
- Detects SPDX 2.3 format
- Normalizes SPDX packages
- Analyzes 3 packages
- Same analysis as CycloneDX
- Adds results as annotations

### Test Both Formats

```bash
# Analyze both formats
python3 sbom_support_analyzer.py examples/sample_cyclonedx.json -o examples/output_cdx.json
python3 sbom_support_analyzer.py examples/sample_spdx.json -o examples/output_spdx.json

# Compare results
python3 analyze_results.py examples/output_cdx_summary.json
python3 analyze_results.py examples/output_spdx_summary.json
```

## Creating Your Own Test SBOM

### Minimal CycloneDX

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "name": "package-name",
      "version": "1.0.0",
      "purl": "pkg:npm/package-name@1.0.0"
    }
  ]
}
```

### Minimal SPDX

```json
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test",
  "creationInfo": {"created": "2025-10-13T00:00:00Z"},
  "packages": [
    {
      "name": "package-name",
      "versionInfo": "1.0.0",
      "externalRefs": [
        {
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/package-name@1.0.0"
        }
      ]
    }
  ]
}
```

## Expected Analysis Results

For the sample SBOMs provided:

| Component | Ecosystem | Expected Support Level |
|-----------|-----------|----------------------|
| express 4.18.0 | NPM | ACTIVELY_MAINTAINED |
| lodash 4.17.21 | NPM | ACTIVELY_MAINTAINED or MAINTENANCE_MODE |
| requests 2.31.0 | PyPI | ACTIVELY_MAINTAINED |

**Note:** Actual results may vary based on current dates and package activity.

## Troubleshooting

### "No PURL available"
Ensure your SBOM includes PURLs:
- **CycloneDX:** `"purl": "pkg:npm/name@version"`
- **SPDX:** Add to `externalRefs` array

### "Failed to fetch package data"
- Check internet connection
- Verify package names are correct
- Check if package exists in public registry

### Rate Limiting
If you see 403 errors:
```bash
export GITHUB_TOKEN="your_token_here"
python3 sbom_support_analyzer.py examples/sample_cyclonedx.json
```

## Next Steps

1. Try the samples: `python3 sbom_support_analyzer.py examples/sample_cyclonedx.json`
2. Create your own test SBOM
3. Read [QUICKSTART.md](../QUICKSTART.md) for detailed usage
4. Check [README.md](../README.md) for full documentation
