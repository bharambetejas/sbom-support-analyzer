#!/usr/bin/env python3
"""
Results Analyzer - Helper script to analyze and report on SBOM support analysis results
"""

import json
import sys
from datetime import datetime
from collections import defaultdict


def load_summary(file_path):
    """Load summary JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {file_path}")
        sys.exit(1)


def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 80)
    print(title.center(80))
    print("=" * 80)


def analyze_by_support_level(data):
    """Analyze components by support level"""
    print_section("SUPPORT LEVEL ANALYSIS")

    summary = data.get('summary', {})
    total = data.get('total_components', 0)

    print(f"\nTotal Components: {total}")
    print("\nBreakdown:")

    # Sort by severity
    order = ['ABANDONED', 'NO_LONGER_MAINTAINED', 'MAINTENANCE_MODE', 'ACTIVELY_MAINTAINED', 'UNKNOWN']

    for level in order:
        count = summary.get(level, 0)
        percentage = (count / total * 100) if total > 0 else 0

        # Add emoji indicators
        emoji = {
            'ACTIVELY_MAINTAINED': '🟢',
            'MAINTENANCE_MODE': '🟡',
            'NO_LONGER_MAINTAINED': '🟠',
            'ABANDONED': '🔴',
            'UNKNOWN': '⚪'
        }.get(level, '')

        print(f"  {emoji} {level:25} {count:4} ({percentage:5.1f}%)")


def analyze_by_confidence(data):
    """Analyze confidence levels"""
    print_section("CONFIDENCE LEVEL ANALYSIS")

    confidence_counts = defaultdict(int)
    components = data.get('components', [])

    for component in components:
        conf = component.get('confidence', 'NONE')
        confidence_counts[conf] += 1

    total = len(components)
    print(f"\nTotal Components: {total}")
    print("\nConfidence Distribution:")

    for level in ['HIGH', 'MEDIUM', 'LOW', 'NONE']:
        count = confidence_counts.get(level, 0)
        percentage = (count / total * 100) if total > 0 else 0
        print(f"  {level:10} {count:4} ({percentage:5.1f}%)")


def list_critical_components(data, level='ABANDONED'):
    """List components at critical support level"""
    print_section(f"COMPONENTS: {level}")

    components = data.get('components', [])
    critical = [c for c in components if c.get('support_level') == level]

    if not critical:
        print(f"\n  No {level} components found. ✅")
        return

    print(f"\nFound {len(critical)} {level} components:\n")

    for i, comp in enumerate(critical, 1):
        name = comp.get('name', 'Unknown')
        version = comp.get('version', 'Unknown')
        eos = comp.get('end_of_support', 'Unknown')
        last_release = comp.get('last_release_date', 'Unknown')
        confidence = comp.get('confidence', 'UNKNOWN')

        print(f"{i:3}. {name}")
        print(f"     Version: {version}")
        print(f"     Last Release: {last_release}")
        print(f"     End of Support: {eos}")
        print(f"     Confidence: {confidence}")
        print()


def analyze_by_ecosystem(data):
    """Analyze components by ecosystem"""
    print_section("ECOSYSTEM ANALYSIS")

    # This would require the full SBOM, not just summary
    # For now, just note it's not available in summary
    print("\n  (Ecosystem breakdown available in full SBOM only)")


def show_upcoming_eos(data, days=365):
    """Show components with upcoming end-of-support"""
    print_section(f"END OF SUPPORT WITHIN {days} DAYS")

    components = data.get('components', [])
    upcoming = []
    today = datetime.now()

    for comp in components:
        eos_str = comp.get('end_of_support', '')

        # Skip N/A and Cannot determine
        if not eos_str or 'N/A' in eos_str or 'Cannot' in eos_str or 'Unknown' in eos_str:
            continue

        # Parse date (handle "expired" suffix)
        eos_str = eos_str.replace(' (expired)', '')

        try:
            eos_date = datetime.strptime(eos_str, '%Y-%m-%d')
            days_until = (eos_date - today).days

            if 0 <= days_until <= days:
                upcoming.append({
                    'component': comp,
                    'eos_date': eos_date,
                    'days_until': days_until
                })
        except:
            continue

    if not upcoming:
        print(f"\n  No components with EOS in next {days} days. ✅")
        return

    # Sort by days until EOS
    upcoming.sort(key=lambda x: x['days_until'])

    print(f"\nFound {len(upcoming)} components:\n")

    for item in upcoming:
        comp = item['component']
        name = comp.get('name', 'Unknown')
        version = comp.get('version', 'Unknown')
        eos_date = item['eos_date']
        days_until = item['days_until']

        urgency = '🔴 URGENT' if days_until <= 90 else '🟡 SOON' if days_until <= 180 else '🟢 PLANNED'

        print(f"  {urgency} - {days_until} days")
        print(f"    {name} @ {version}")
        print(f"    End of Support: {eos_date.strftime('%Y-%m-%d')}")
        print()


def show_age_distribution(data):
    """Show distribution of component ages"""
    print_section("COMPONENT AGE DISTRIBUTION")

    components = data.get('components', [])

    buckets = {
        '0-6 months': 0,
        '6-12 months': 0,
        '1-2 years': 0,
        '2-3 years': 0,
        '3-4 years': 0,
        '4+ years': 0,
        'Unknown': 0
    }

    for comp in components:
        days = comp.get('days_since_release')

        if days is None:
            buckets['Unknown'] += 1
        elif days <= 180:
            buckets['0-6 months'] += 1
        elif days <= 365:
            buckets['6-12 months'] += 1
        elif days <= 730:
            buckets['1-2 years'] += 1
        elif days <= 1095:
            buckets['2-3 years'] += 1
        elif days <= 1460:
            buckets['3-4 years'] += 1
        else:
            buckets['4+ years'] += 1

    total = len(components)
    print(f"\nTotal Components: {total}")
    print("\nAge Since Last Release:")

    for bucket, count in buckets.items():
        percentage = (count / total * 100) if total > 0 else 0
        bar = '█' * int(percentage / 2)
        print(f"  {bucket:15} {count:4} ({percentage:5.1f}%) {bar}")


def generate_recommendations(data):
    """Generate actionable recommendations"""
    print_section("RECOMMENDATIONS")

    summary = data.get('summary', {})

    abandoned = summary.get('ABANDONED', 0)
    no_longer = summary.get('NO_LONGER_MAINTAINED', 0)
    unknown = summary.get('UNKNOWN', 0)

    print()

    if abandoned > 0:
        print(f"🔴 HIGH PRIORITY: {abandoned} ABANDONED components detected")
        print("   Action: Immediately plan replacement or migration")
        print("   Risk: No security updates, potential vulnerabilities")
        print()

    if no_longer > 0:
        print(f"🟠 MEDIUM PRIORITY: {no_longer} NO_LONGER_MAINTAINED components")
        print("   Action: Evaluate alternatives, plan migration timeline")
        print("   Risk: No new features, security fixes may be limited")
        print()

    if unknown > 0:
        print(f"⚪ REVIEW NEEDED: {unknown} components with UNKNOWN status")
        print("   Action: Manual investigation required")
        print("   Risk: Cannot assess, may include private/internal packages")
        print()

    if abandoned == 0 and no_longer == 0:
        print("✅ GOOD: No abandoned or unmaintained components detected!")
        print("   Continue monitoring for changes in support status")
        print()

    print("📊 Best Practices:")
    print("   1. Re-run this analysis monthly to track changes")
    print("   2. Subscribe to security advisories for all components")
    print("   3. Prioritize updates for components near end-of-support")
    print("   4. Document decisions for UNKNOWN components")
    print("   5. Establish process for evaluating new dependencies")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_results.py <summary_file.json>")
        print("\nExample:")
        print("  python3 analyze_results.py your_sbom_analyzed_summary.json")
        sys.exit(1)

    summary_file = sys.argv[1]

    print("\n")
    print("=" * 80)
    print("SBOM SUPPORT ANALYSIS REPORT".center(80))
    print("=" * 80)

    data = load_summary(summary_file)

    analysis_date = data.get('analysis_date', 'Unknown')
    sbom_file = data.get('sbom_file', 'Unknown')

    print(f"\nAnalysis Date: {analysis_date}")
    print(f"SBOM File: {sbom_file}")

    # Run all analyses
    analyze_by_support_level(data)
    analyze_by_confidence(data)
    show_age_distribution(data)
    show_upcoming_eos(data, days=365)

    # List critical components
    list_critical_components(data, 'ABANDONED')
    list_critical_components(data, 'NO_LONGER_MAINTAINED')

    # Generate recommendations
    generate_recommendations(data)

    print("\n" + "=" * 80)
    print("END OF REPORT".center(80))
    print("=" * 80 + "\n")


if __name__ == '__main__':
    main()
