---
name: Bug Report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description
A clear and concise description of what the bug is.

## Steps to Reproduce
1. Run command: `python3 sbom_support_analyzer.py ...`
2. With SBOM file: `...`
3. See error: `...`

## Expected Behavior
A clear description of what you expected to happen.

## Actual Behavior
A clear description of what actually happened.

## Error Messages
```
Paste any error messages here
```

## Environment
- **Python version:** [e.g., 3.9.5]
- **OS:** [e.g., Ubuntu 22.04, macOS 13, Windows 11]
- **SBOM format:** [e.g., CycloneDX 1.6, SPDX 2.3]
- **Number of components:** [e.g., 125]

## Sample SBOM (Sanitized)
If possible, provide a minimal sanitized SBOM that reproduces the issue:
```json
{
  "bomFormat": "CycloneDX",
  "components": [
    ...
  ]
}
```

## Additional Context
Add any other context about the problem here.

## Checklist
- [ ] I have checked the [documentation](../docs/)
- [ ] I have searched existing issues
- [ ] I have tested with the latest version
- [ ] I have sanitized sensitive data from examples
