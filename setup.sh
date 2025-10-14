#!/bin/bash
# Setup script for SBOM Support Analyzer

set -e

echo "========================================="
echo "  SBOM Support Analyzer - Setup"
echo "========================================="
echo ""

# Check Python version
echo "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "Found Python $PYTHON_VERSION"

# Check if Python version is 3.7+
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
    echo "Error: Python 3.7 or higher is required (found $PYTHON_VERSION)"
    exit 1
fi

echo "✓ Python version OK"
echo ""

# Make scripts executable
echo "Making scripts executable..."
chmod +x sbom_support_analyzer.py
chmod +x analyze_results.py
chmod +x run_analysis.sh
echo "✓ Scripts are now executable"
echo ""

# Verify script syntax
echo "Verifying script syntax..."
python3 -m py_compile sbom_support_analyzer.py
python3 -m py_compile analyze_results.py
echo "✓ Script syntax validated"
echo ""

# Test with sample SBOM
echo "Testing with sample CycloneDX SBOM..."
if python3 sbom_support_analyzer.py examples/sample_cyclonedx.json --limit 1 > /dev/null 2>&1; then
    echo "✓ CycloneDX analysis test passed"
else
    echo "⚠ CycloneDX analysis test failed (this may be due to rate limits)"
fi
echo ""

echo "Testing with sample SPDX SBOM..."
if python3 sbom_support_analyzer.py examples/sample_spdx.json --limit 1 > /dev/null 2>&1; then
    echo "✓ SPDX analysis test passed"
else
    echo "⚠ SPDX analysis test failed (this may be due to rate limits)"
fi
echo ""

# Check for GitHub token
if [ -z "$GITHUB_TOKEN" ]; then
    echo "⚠ WARNING: GITHUB_TOKEN not set"
    echo "  Without a token, you'll be limited to 60 GitHub API requests per hour"
    echo "  Get a token at: https://github.com/settings/tokens"
    echo "  Then set it: export GITHUB_TOKEN='ghp_your_token'"
    echo ""
else
    echo "✓ GitHub token detected"
    echo ""
fi

echo "========================================="
echo "  Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Read the documentation: less README.md"
echo "  2. Try the quick start: python3 sbom_support_analyzer.py examples/sample_cyclonedx.json"
echo "  3. Analyze your SBOM: python3 sbom_support_analyzer.py your_sbom.json"
echo ""
echo "For help: python3 sbom_support_analyzer.py --help"
echo ""
