#!/bin/bash
# Quick launcher script for SBOM Support Analyzer

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  SBOM Support Level Analyzer${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Check if SBOM file is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: No SBOM file specified${NC}"
    echo ""
    echo "Usage: ./run_analysis.sh <sbom_file.json> [options]"
    echo ""
    echo "Options:"
    echo "  --limit N     Analyze only first N components (for testing)"
    echo "  --token TOKEN Use GitHub token for higher rate limits"
    echo "  --no-report   Skip generating detailed report"
    echo ""
    echo "Example:"
    echo "  ./run_analysis.sh your_sbom.cdx.json"
    echo "  ./run_analysis.sh sbom.json --limit 10"
    echo "  ./run_analysis.sh sbom.json --token ghp_xxxxx"
    exit 1
fi

SBOM_FILE="$1"
shift

# Check if file exists
if [ ! -f "$SBOM_FILE" ]; then
    echo -e "${RED}Error: File not found: $SBOM_FILE${NC}"
    exit 1
fi

# Parse additional arguments
EXTRA_ARGS=""
SKIP_REPORT=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --limit)
            EXTRA_ARGS="$EXTRA_ARGS --limit $2"
            shift 2
            ;;
        --token)
            EXTRA_ARGS="$EXTRA_ARGS --token $2"
            shift 2
            ;;
        --no-report)
            SKIP_REPORT=true
            shift
            ;;
        *)
            echo -e "${YELLOW}Warning: Unknown option: $1${NC}"
            shift
            ;;
    esac
done

# Check for GitHub token
if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${YELLOW}⚠ Warning: No GITHUB_TOKEN environment variable set${NC}"
    echo -e "${YELLOW}  Rate limits will be restrictive (60 requests/hour)${NC}"
    echo ""
    echo "To fix this:"
    echo "  1. Get token from: https://github.com/settings/tokens"
    echo "  2. Run: export GITHUB_TOKEN=\"ghp_your_token\""
    echo ""
    echo -n "Continue anyway? [y/N] "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
else
    echo -e "${GREEN}✓ GitHub token found${NC}"
fi
echo ""

# Determine output filename
BASE_NAME="${SBOM_FILE%.json}"
OUTPUT_FILE="${BASE_NAME}_analyzed.json"
SUMMARY_FILE="${BASE_NAME}_analyzed_summary.json"

echo -e "${BLUE}Input File:${NC}   $SBOM_FILE"
echo -e "${BLUE}Output File:${NC}  $OUTPUT_FILE"
echo -e "${BLUE}Summary File:${NC} $SUMMARY_FILE"
echo ""

# Run the analyzer
echo -e "${GREEN}Starting analysis...${NC}"
echo ""

if python3 sbom_support_analyzer.py "$SBOM_FILE" -o "$OUTPUT_FILE" $EXTRA_ARGS; then
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  Analysis Complete!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""

    # Generate detailed report if not skipped
    if [ "$SKIP_REPORT" = false ]; then
        echo -e "${BLUE}Generating detailed report...${NC}"
        echo ""

        if python3 analyze_results.py "$SUMMARY_FILE"; then
            echo ""
            echo -e "${GREEN}✓ Report generated successfully${NC}"
        else
            echo -e "${YELLOW}⚠ Report generation failed, but analysis completed${NC}"
        fi
    fi

    echo ""
    echo -e "${BLUE}Output Files:${NC}"
    echo "  • $OUTPUT_FILE (enriched SBOM)"
    echo "  • $SUMMARY_FILE (analysis summary)"
    echo ""
    echo -e "${GREEN}Next Steps:${NC}"
    echo "  1. Review the summary file for quick overview"
    echo "  2. Use enriched SBOM for further processing"
    echo "  3. Address any ABANDONED or NO_LONGER_MAINTAINED components"
    echo ""

else
    echo ""
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}  Analysis Failed${NC}"
    echo -e "${RED}============================================${NC}"
    echo ""
    echo "Check the error messages above for details."
    echo ""
    echo "Common issues:"
    echo "  • Network connectivity problems"
    echo "  • Invalid SBOM format"
    echo "  • API rate limits exceeded"
    echo ""
    exit 1
fi
