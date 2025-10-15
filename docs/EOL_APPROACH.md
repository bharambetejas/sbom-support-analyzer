# Product-Based End-of-Life Approach

## Overview
The SBOM Support Analyzer now uses a **product-centric EOL model** where component end-of-life dates are tied to the product's end-of-life, not individual component release dates.

## Rationale

### Why Product-Based EOL?

In real-world enterprise software support:
- **Vendors support products, not individual components**
- A product supported until 2030 will have ALL its dependencies maintained until 2030
- Security patches are applied to all components during the product support window
- Component age is less relevant than the product lifecycle

### Examples from Industry

#### Red Hat Enterprise Linux (RHEL)
- RHEL 8 supported until 2029
- All packages in RHEL 8 (including old libraries) receive security updates until 2029
- Individual package release dates don't determine EOL

#### Ubuntu LTS
- Ubuntu 20.04 LTS supported until 2025
- All components in the repositories are maintained until 2025
- Even if a library was last updated in 2018, it receives security patches

#### Microsoft Windows
- Windows Server 2019 supported until 2029
- All included components and dependencies are supported until 2029
- Component maintenance status is irrelevant to user support

## How It Works

### User Input
At the start of analysis, the script prompts:
```
======================================================================
PRODUCT END-OF-LIFE DATE
======================================================================
Enter the product's end-of-life date. This date will be used as the
EOL for all actively maintained and maintenance mode components.
Format: YYYY-MM-DD (e.g., 2030-12-31)
Leave blank to skip (components will show 'Not specified')
----------------------------------------------------------------------
Product EOL Date:
```

Or provide via command line:
```bash
python3 sbom_support_analyzer.py your_sbom.json -e 2030-12-31
```

### EOL Assignment Logic (FDA-Aligned)

| Support Level | EOL Assignment |
|---------------|----------------|
| **ACTIVELY_MAINTAINED** | Product EOL date |
| **NO_LONGER_MAINTAINED** | Last release date of component |
| **ABANDONED** | Last release date of component |
| **UNKNOWN** | "Cannot determine" |

### Example Scenario

**Product:** Enterprise Application v5.0
**Product EOL:** 2030-12-31

**Components:**
1. **JSON.NET** (released 2024-06-01)
   - Status: ACTIVELY_MAINTAINED
   - Component EOL: **2030-12-31** (product EOL)

2. **Newtonsoft.Json** (released 2020-02-15)
   - Status: ACTIVELY_MAINTAINED (within 5 years)
   - Component EOL: **2030-12-31** (product EOL)

3. **VeryOldLibrary** (released 2015-01-01, no explicit deprecation)
   - Status: NO_LONGER_MAINTAINED (>5 years old)
   - Component EOL: **2015-01-01** (component's last release)

4. **DeprecatedLibrary** (released 2018-01-01, explicitly deprecated)
   - Status: ABANDONED
   - Component EOL: **2018-01-01** (component's last release)

5. **UnknownPackage** (no data available)
   - Status: UNKNOWN
   - Component EOL: **Cannot determine**

## Benefits

### 1. Aligns with Real-World Support Models
Enterprise vendors commit to supporting products, which includes all dependencies.

### 2. Reduces False Alarms
An old but stable library in your product is supported as long as your product is supported.

### 3. Clearer Risk Assessment
- Components with product EOL → Supported throughout product lifecycle
- ABANDONED components → Immediate risk (no security patches)
- UNKNOWN components → Manual review needed

### 4. Vendor Accountability
Product EOL date creates clear accountability for component maintenance.

## Usage Examples

### Example 1: Specify EOL via Command Line
```bash
python3 sbom_support_analyzer.py my_app_sbom.json -e 2032-06-30
```

### Example 2: Interactive Prompt
```bash
python3 sbom_support_analyzer.py my_app_sbom.json

# Script prompts:
Product EOL Date: 2032-06-30
✓ Using product EOL date: 2032-06-30
```

### Example 3: Skip EOL Input
```bash
python3 sbom_support_analyzer.py my_app_sbom.json

# Script prompts:
Product EOL Date: [press Enter]
⚠ No EOL date provided. Proceeding without EOL date.

# Components will show: "Not specified"
```

## Output Examples

### With Product EOL
```json
{
  "name": "SomeLibrary",
  "version": "3.2.1",
  "support_level": "ACTIVELY_MAINTAINED",
  "end_of_life": "2030-12-31",
  "confidence": "HIGH"
}
```

### Without Product EOL
```json
{
  "name": "SomeLibrary",
  "version": "3.2.1",
  "support_level": "ACTIVELY_MAINTAINED",
  "end_of_life": "Not specified",
  "confidence": "HIGH"
}
```

### Abandoned Component (Uses Component Date)
```json
{
  "name": "DeprecatedLib",
  "version": "1.0.0",
  "support_level": "ABANDONED",
  "end_of_life": "2018-05-15",
  "confidence": "HIGH"
}
```

## Integration with CI/CD

### Check Product EOL is Set
```bash
#!/bin/bash

# Ensure product EOL is always provided
if [ -z "$PRODUCT_EOL_DATE" ]; then
  echo "ERROR: PRODUCT_EOL_DATE environment variable not set"
  exit 1
fi

python3 sbom_support_analyzer.py sbom.json -e "$PRODUCT_EOL_DATE"
```

### Automated with Environment Variable
```bash
export PRODUCT_EOL_DATE="2030-12-31"

# In CI/CD pipeline
python3 sbom_support_analyzer.py sbom.json -e "$PRODUCT_EOL_DATE"
```

## Comparison: Old vs New Approach

### Old Approach (Component-Based EOL)
```
Component: OldCryptoLibrary (released 2019-01-01, 5 years ago)
Status: ABANDONED
EOL: 2019-01-01

Problem: Library is stable and receives security patches in product.
False positive causes unnecessary migration effort.
```

### New Approach (Product-Based EOL)
```
Component: OldCryptoLibrary (released 2019-01-01, 5 years ago)
Status: MAINTENANCE_MODE
EOL: 2030-12-31 (product EOL)

Benefit: Correctly reflects that vendor maintains this component
as part of product support until 2030.
```

## Best Practices

### 1. Always Provide Product EOL
- Set via command line or environment variable in CI/CD
- Ensures accurate risk assessment

### 2. Update Product EOL When Extended
- Re-run analysis when product support is extended
- Updates all component EOL dates automatically

### 3. Review ABANDONED Components Separately
- These have component-specific EOL dates
- Represent real risk requiring immediate action

### 4. Document Product Support Policy
- Clearly state product EOL in documentation
- Link SBOM analysis results to product roadmap

## FAQ

**Q: What if I don't know the product EOL?**
A: Skip the prompt or leave blank. Components will show "Not specified". You can re-run analysis later with the EOL date.

**Q: What if the product has different EOL dates for different versions?**
A: Run separate analyses for each product version, each with its respective EOL date.

**Q: Do ABANDONED components still use product EOL?**
A: No. ABANDONED components use their last release date as EOL, indicating they're already unsupported.

**Q: Can I override EOL for specific components?**
A: Not currently. The tool applies product EOL uniformly to all maintained components, reflecting vendor support models.

**Q: What if a component is older than the product EOL?**
A: As long as it's ACTIVELY_MAINTAINED or MAINTENANCE_MODE, it inherits the product EOL. Vendors backport security fixes to old components.

## Technical Details

### Date Format
- Required format: `YYYY-MM-DD`
- Example: `2030-12-31`
- Validation occurs at input time

### Storage in SBOM
For CycloneDX:
```json
{
  "properties": [
    {
      "name": "supportEndOfLife",
      "value": "2030-12-31"
    }
  ]
}
```

For SPDX:
```json
{
  "annotations": [
    {
      "annotationDate": "2025-10-14T12:00:00Z",
      "comment": "supportLevel: ACTIVELY_MAINTAINED"
    },
    {
      "annotationDate": "2025-10-14T12:00:00Z",
      "comment": "supportEndOfLife: 2030-12-31"
    },
    {
      "annotationDate": "2025-10-14T12:00:00Z",
      "comment": "supportConfidence: HIGH"
    }
  ]
}
```

### Command Line Priority
1. `-e/--eol-date` flag (highest priority)
2. Interactive prompt
3. None/Not specified (default)
