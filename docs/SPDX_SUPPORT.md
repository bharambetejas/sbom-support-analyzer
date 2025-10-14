# SPDX 2.3 Support Guide

## Overview

The SBOM Support Level Analyzer now supports both CycloneDX and SPDX formats. This document explains SPDX-specific features and differences.

## Supported Versions

- **SPDX 2.2** - Full support
- **SPDX 2.3** - Full support
- **CycloneDX 1.4, 1.5, 1.6** - Full support

## Format Detection

The analyzer automatically detects the SBOM format:

```bash
$ python3 sbom_support_analyzer.py your_sbom.spdx.json
Loading SBOM from: your_sbom.spdx.json
Detected format: SPDX 2.3
Analyzing 125 packages
...
```

Detection logic:
1. Checks for `spdxVersion` field (SPDX)
2. Checks for `bomFormat` field (CycloneDX)
3. Falls back to structural analysis

## SPDX vs CycloneDX Differences

### Component Structure

**SPDX 2.3:**
```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "package-name",
      "SPDXID": "SPDXRef-Package-1",
      "versionInfo": "1.0.0",
      "externalRefs": [
        {
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/package-name@1.0.0"
        }
      ],
      "homepage": "https://example.com"
    }
  ]
}
```

**CycloneDX 1.6:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "name": "package-name",
      "version": "1.0.0",
      "purl": "pkg:npm/package-name@1.0.0",
      "externalReferences": [
        {
          "type": "website",
          "url": "https://example.com"
        }
      ]
    }
  ]
}
```

### Package URL (PURL) Extraction

**SPDX:** PURLs are in `externalRefs` array with `referenceType: "purl"`

**CycloneDX:** PURLs are in direct `purl` field

### Support Data Storage

#### CycloneDX
Support data is added to component `properties`:

```json
{
  "components": [
    {
      "name": "example-package",
      "version": "1.0.0",
      "properties": [
        {"name": "supportLevel", "value": "ACTIVELY_MAINTAINED"},
        {"name": "supportEndOfSupport", "value": "N/A"},
        {"name": "supportConfidence", "value": "HIGH"}
      ]
    }
  ]
}
```

#### SPDX
Support data is added as `annotations` (SPDX standard approach):

```json
{
  "packages": [
    {
      "name": "example-package",
      "versionInfo": "1.0.0",
      "annotations": [
        {
          "annotator": "Tool: SBOM-Support-Analyzer",
          "annotationType": "REVIEW",
          "annotationDate": "2025-10-13T18:21:25Z",
          "comment": "supportLevel: ACTIVELY_MAINTAINED"
        },
        {
          "annotator": "Tool: SBOM-Support-Analyzer",
          "annotationType": "REVIEW",
          "annotationDate": "2025-10-13T18:21:25Z",
          "comment": "supportEndOfSupport: N/A"
        }
      ]
    }
  ]
}
```

## Usage Examples

### Analyzing SPDX SBOM

```bash
# Same command works for both formats
python3 sbom_support_analyzer.py sbom.spdx.json

# With GitHub token
export GITHUB_TOKEN="ghp_xxxxx"
python3 sbom_support_analyzer.py sbom.spdx.json

# Test with limited packages
python3 sbom_support_analyzer.py sbom.spdx.json --limit 10
```

### Mixed Format Analysis

```bash
# Analyze both formats in the same workflow
python3 sbom_support_analyzer.py cyclonedx.json -o cyclonedx_analyzed.json
python3 sbom_support_analyzer.py spdx.json -o spdx_analyzed.json

# Compare results
python3 analyze_results.py cyclonedx_analyzed_summary.json
python3 analyze_results.py spdx_analyzed_summary.json
```

## SPDX-Specific Features

### Field Mapping

| SPDX Field | CycloneDX Field | Analyzer Use |
|------------|----------------|--------------|
| `name` | `name` | Component identification |
| `versionInfo` | `version` | Version identification |
| `externalRefs[type=purl]` | `purl` | Package ecosystem detection |
| `homepage` | `externalReferences[type=website]` | Repository discovery |
| `downloadLocation` | N/A | Fallback PURL source |
| `sourceInfo` | N/A | Additional metadata |

### Annotation Format

The analyzer uses SPDX 2.3 standard annotation format:

- **annotator**: Always "Tool: SBOM-Support-Analyzer"
- **annotationType**: Always "REVIEW" (most appropriate for analysis results)
- **annotationDate**: ISO 8601 timestamp
- **comment**: Key-value format "key: value"

## PURL Requirements

Both SPDX and CycloneDX require Package URLs (PURLs) for analysis:

### SPDX with PURL
```json
{
  "name": "express",
  "versionInfo": "4.18.0",
  "externalRefs": [
    {
      "referenceType": "purl",
      "referenceLocator": "pkg:npm/express@4.18.0"
    }
  ]
}
```

### SPDX without PURL (Limited Analysis)
```json
{
  "name": "express",
  "versionInfo": "4.18.0",
  "downloadLocation": "https://registry.npmjs.org/express/-/express-4.18.0.tgz"
}
```

Without a PURL, the analyzer will:
- Mark the package as UNKNOWN support level
- Skip ecosystem-specific analysis
- Note "No PURL available" in logs

## Common SPDX Scenarios

### Scenario 1: Complete SPDX Package
```json
{
  "name": "lodash",
  "SPDXID": "SPDXRef-Package-lodash-4.17.21",
  "versionInfo": "4.17.21",
  "supplier": "Organization: Lodash",
  "downloadLocation": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
  "externalRefs": [
    {
      "referenceCategory": "PACKAGE-MANAGER",
      "referenceType": "purl",
      "referenceLocator": "pkg:npm/lodash@4.17.21"
    }
  ],
  "homepage": "https://lodash.com"
}
```

✅ Full analysis possible

### Scenario 2: SPDX Package with Repository
```json
{
  "name": "react",
  "versionInfo": "18.2.0",
  "externalRefs": [
    {
      "referenceType": "purl",
      "referenceLocator": "pkg:npm/react@18.2.0"
    },
    {
      "referenceType": "vcs",
      "referenceLocator": "https://github.com/facebook/react"
    }
  ]
}
```

✅ Full analysis with GitHub commit history

### Scenario 3: Minimal SPDX Package
```json
{
  "name": "unknown-lib",
  "versionInfo": "1.0.0",
  "downloadLocation": "NOASSERTION"
}
```

⚠️ Limited analysis (UNKNOWN support level)

## Conversion Between Formats

The analyzer normalizes both formats internally:

```python
# Internal normalized format (used during analysis)
{
    'name': 'package-name',
    'version': '1.0.0',
    'purl': 'pkg:npm/package-name@1.0.0',
    'externalReferences': [
        {'type': 'website', 'url': 'https://example.com'}
    ]
}
```

This allows the same analysis logic to work for both formats.

## Output Format Comparison

### CycloneDX Output
```json
{
  "bomFormat": "CycloneDX",
  "components": [
    {
      "name": "express",
      "version": "4.18.0",
      "properties": [
        {"name": "supportLevel", "value": "ACTIVELY_MAINTAINED"}
      ]
    }
  ]
}
```

### SPDX Output
```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "express",
      "versionInfo": "4.18.0",
      "annotations": [
        {
          "annotator": "Tool: SBOM-Support-Analyzer",
          "annotationType": "REVIEW",
          "annotationDate": "2025-10-13T18:21:25Z",
          "comment": "supportLevel: ACTIVELY_MAINTAINED"
        }
      ]
    }
  ]
}
```

## Compatibility Notes

### SPDX 2.2 vs 2.3
- Both versions fully supported
- Minor field differences handled automatically
- Annotation format identical

### SPDX Lite
- Subset of SPDX 2.3
- May lack `externalRefs` for PURLs
- Analysis may be limited

## Best Practices

### For SPDX SBOMs

1. **Always include PURLs** in `externalRefs`
   ```json
   "externalRefs": [
     {
       "referenceCategory": "PACKAGE-MANAGER",
       "referenceType": "purl",
       "referenceLocator": "pkg:npm/package@1.0.0"
     }
   ]
   ```

2. **Include repository references** when available
   ```json
   "externalRefs": [
     {
       "referenceType": "vcs",
       "referenceLocator": "https://github.com/owner/repo"
     }
   ]
   ```

3. **Set accurate version info**
   ```json
   "versionInfo": "1.2.3"  // Not "NOASSERTION"
   ```

4. **Include homepage** for better analysis
   ```json
   "homepage": "https://example.com"
   ```

## Troubleshooting

### "No PURL available"
**Problem:** Package marked as UNKNOWN

**Solution:** Add PURL to `externalRefs`:
```json
"externalRefs": [
  {
    "referenceType": "purl",
    "referenceLocator": "pkg:npm/package-name@version"
  }
]
```

### "Failed to fetch package data"
**Problem:** Same as CycloneDX - package not in public registry

**Solution:** Check if package is private or internal

### Missing Annotations
**Problem:** Output SBOM doesn't have annotations

**Solution:** Verify output file was generated with `-o` flag

## Summary

The analyzer provides:
- ✅ Transparent format detection
- ✅ Automatic normalization
- ✅ Format-appropriate output
- ✅ Same analysis quality for both formats
- ✅ Consistent summary reports

Both SPDX and CycloneDX SBOMs receive the same level of analysis - the format is just a different way to represent the same data!
