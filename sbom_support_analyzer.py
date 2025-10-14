#!/usr/bin/env python3
"""
SBOM Support Level Analyzer
Analyzes CycloneDX and SPDX SBOM components to determine support level and end-of-life dates
based on real data from package registries and repositories.

Supported formats:
- CycloneDX 1.4, 1.5, 1.6
- SPDX 2.2, 2.3
"""

import json
import sys
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse


class SupportLevel:
    """Support level classifications"""
    ACTIVELY_MAINTAINED = "ACTIVELY_MAINTAINED"
    MAINTENANCE_MODE = "MAINTENANCE_MODE"
    NO_LONGER_MAINTAINED = "NO_LONGER_MAINTAINED"
    ABANDONED = "ABANDONED"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel:
    """Confidence in the analysis"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class SBOMFormat:
    """SBOM format types"""
    CYCLONEDX = "CycloneDX"
    SPDX = "SPDX"
    UNKNOWN = "Unknown"


def detect_sbom_format(sbom_data: Dict) -> Tuple[str, Optional[str]]:
    """
    Detect SBOM format and version
    Returns: (format_type, version)
    """
    # Check for CycloneDX
    if 'bomFormat' in sbom_data and sbom_data['bomFormat'] == 'CycloneDX':
        version = sbom_data.get('specVersion', 'Unknown')
        return (SBOMFormat.CYCLONEDX, version)

    # Check for SPDX
    if 'spdxVersion' in sbom_data:
        version = sbom_data['spdxVersion'].replace('SPDX-', '')
        return (SBOMFormat.SPDX, version)

    # Try to infer from structure
    if 'packages' in sbom_data and 'creationInfo' in sbom_data:
        # Likely SPDX without version field
        return (SBOMFormat.SPDX, 'Unknown')

    if 'components' in sbom_data and 'metadata' in sbom_data:
        # Likely CycloneDX without bomFormat
        return (SBOMFormat.CYCLONEDX, 'Unknown')

    return (SBOMFormat.UNKNOWN, None)


def normalize_spdx_component(spdx_package: Dict) -> Dict:
    """
    Convert SPDX package to normalized component format

    SPDX structure:
    {
        "name": "package-name",
        "SPDXID": "SPDXRef-Package-...",
        "versionInfo": "1.0.0",
        "downloadLocation": "...",
        "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:..."}],
        "homepage": "...",
        "sourceInfo": "..."
    }
    """
    component = {
        'name': spdx_package.get('name', 'Unknown'),
        'version': spdx_package.get('versionInfo', 'Unknown'),
        'purl': None,
        'externalReferences': []
    }

    # Extract PURL from externalRefs
    external_refs = spdx_package.get('externalRefs', [])
    for ref in external_refs:
        ref_type = ref.get('referenceType', '')
        if ref_type == 'purl':
            component['purl'] = ref.get('referenceLocator')
        elif ref_type in ['vcs', 'website', 'repository']:
            component['externalReferences'].append({
                'type': ref_type,
                'url': ref.get('referenceLocator', '')
            })

    # Add homepage as external reference
    if spdx_package.get('homepage'):
        component['externalReferences'].append({
            'type': 'website',
            'url': spdx_package['homepage']
        })

    # Try to extract PURL from downloadLocation if not found
    if not component['purl']:
        download_loc = spdx_package.get('downloadLocation', '')
        if download_loc and download_loc.startswith('pkg:'):
            component['purl'] = download_loc

    return component


def add_support_data_to_spdx(spdx_package: Dict, result: Dict) -> None:
    """
    Add support analysis data to SPDX package
    SPDX doesn't have a standard 'properties' field, so we add custom annotations
    """
    # Create annotations array if it doesn't exist
    if 'annotations' not in spdx_package:
        spdx_package['annotations'] = []

    # Add support analysis as annotations
    timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

    annotations = [
        {
            'annotator': 'Tool: SBOM-Support-Analyzer',
            'annotationType': 'REVIEW',
            'annotationDate': timestamp,
            'comment': f"supportLevel: {result['support_level']}"
        },
        {
            'annotator': 'Tool: SBOM-Support-Analyzer',
            'annotationType': 'REVIEW',
            'annotationDate': timestamp,
            'comment': f"supportEndOfLife: {result['end_of_life']}"
        },
        {
            'annotator': 'Tool: SBOM-Support-Analyzer',
            'annotationType': 'REVIEW',
            'annotationDate': timestamp,
            'comment': f"supportConfidence: {result['confidence']}"
        },
        {
            'annotator': 'Tool: SBOM-Support-Analyzer',
            'annotationType': 'REVIEW',
            'annotationDate': timestamp,
            'comment': f"supportLastReleaseDate: {result['last_release_date'] or 'Unknown'}"
        },
        {
            'annotator': 'Tool: SBOM-Support-Analyzer',
            'annotationType': 'REVIEW',
            'annotationDate': timestamp,
            'comment': f"supportDaysSinceRelease: {result['days_since_release'] if result['days_since_release'] else 'Unknown'}"
        }
    ]

    spdx_package['annotations'].extend(annotations)


class ComponentAnalyzer:
    """Analyzes individual components for support status"""

    def __init__(self, github_token: Optional[str] = None, use_cache: bool = True):
        self.github_token = github_token
        self.use_cache = use_cache
        self.cache = {}
        self.request_count = {"github": 0, "nuget": 0, "npm": 0, "pypi": 0, "maven": 0}
        self.today = datetime.now(timezone.utc)

    def _make_request(self, url: str, headers: Optional[Dict] = None, timeout: int = 10) -> Optional[Dict]:
        """Make HTTP request with error handling and caching"""
        # Check cache
        if self.use_cache and url in self.cache:
            return self.cache[url]

        try:
            if headers is None:
                headers = {}
            headers['User-Agent'] = 'SBOM-Support-Analyzer/1.0'

            request = Request(url, headers=headers)
            with urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode('utf-8'))
                if self.use_cache:
                    self.cache[url] = data
                return data
        except HTTPError as e:
            if e.code == 404:
                print(f"  [404] Resource not found: {url}", file=sys.stderr)
            elif e.code == 403:
                print(f"  [403] Rate limited or forbidden: {url}", file=sys.stderr)
            else:
                print(f"  [HTTP {e.code}] Error fetching {url}", file=sys.stderr)
            return None
        except URLError as e:
            print(f"  [URL Error] {e.reason}: {url}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"  [Error] {str(e)}: {url}", file=sys.stderr)
            return None

    def _parse_purl(self, purl: str) -> Optional[Dict[str, str]]:
        """Parse package URL (PURL) to extract components"""
        if not purl or not purl.startswith('pkg:'):
            return None

        try:
            # Remove pkg: prefix
            purl = purl[4:]

            # Split by /
            parts = purl.split('/')
            ecosystem = parts[0]

            # Handle namespace (e.g., maven group.id/artifact.id)
            if len(parts) > 2:
                namespace = parts[1]
                name_version = parts[2]
            else:
                namespace = None
                name_version = parts[1] if len(parts) > 1 else parts[0]

            # Extract name and version
            if '@' in name_version:
                name, version = name_version.rsplit('@', 1)
            else:
                name = name_version
                version = None

            # Remove qualifiers (? suffix)
            if '?' in name:
                name = name.split('?')[0]
            if version and '?' in version:
                version = version.split('?')[0]

            return {
                'ecosystem': ecosystem,
                'namespace': namespace,
                'name': name,
                'version': version
            }
        except Exception as e:
            print(f"  [Error] Failed to parse PURL '{purl}': {e}", file=sys.stderr)
            return None

    def _get_github_repo_info(self, repo_url: str) -> Optional[Dict]:
        """Get GitHub repository information"""
        try:
            # Extract owner/repo from URL
            match = re.search(r'github\.com[/:]([^/]+)/([^/\.]+)', repo_url)
            if not match:
                return None

            owner, repo = match.groups()

            # Clean repo name
            repo = repo.replace('.git', '')

            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            headers = {}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'

            self.request_count['github'] += 1
            repo_data = self._make_request(api_url, headers)

            if not repo_data:
                return None

            # Get commit activity
            commits_url = f"{api_url}/commits"
            commits_data = self._make_request(commits_url, headers)

            last_commit_date = None
            if commits_data and isinstance(commits_data, list) and len(commits_data) > 0:
                commit_date_str = commits_data[0].get('commit', {}).get('committer', {}).get('date')
                if commit_date_str:
                    last_commit_date = datetime.strptime(commit_date_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)

            return {
                'archived': repo_data.get('archived', False),
                'pushed_at': repo_data.get('pushed_at'),
                'created_at': repo_data.get('created_at'),
                'updated_at': repo_data.get('updated_at'),
                'last_commit_date': last_commit_date,
                'open_issues': repo_data.get('open_issues_count', 0),
                'forks': repo_data.get('forks_count', 0),
                'stargazers': repo_data.get('stargazers_count', 0)
            }
        except Exception as e:
            print(f"  [Error] GitHub repo analysis failed: {e}", file=sys.stderr)
            return None

    def _analyze_nuget_package(self, name: str, version: str) -> Dict:
        """Analyze NuGet package"""
        self.request_count['nuget'] += 1

        # NuGet API v3
        base_url = f"https://api.nuget.org/v3/registration5-semver1/{name.lower()}/index.json"
        data = self._make_request(base_url)

        if not data:
            return {'success': False}

        # Extract all versions and their published dates
        versions = []
        repo_url = None

        for item in data.get('items', []):
            for package_item in item.get('items', []):
                catalog_entry = package_item.get('catalogEntry', {})
                versions.append({
                    'version': catalog_entry.get('version'),
                    'published': catalog_entry.get('published'),
                    'deprecated': catalog_entry.get('deprecation') is not None
                })

                # Extract repository URL
                if not repo_url:
                    repo_url = catalog_entry.get('projectUrl') or catalog_entry.get('licenseUrl')

        if not versions:
            return {'success': False}

        # Sort by published date
        versions = sorted(versions, key=lambda x: x['published'] if x['published'] else '', reverse=True)
        latest = versions[0]

        # Parse latest published date
        latest_date = None
        if latest['published']:
            try:
                # Handle various date formats
                date_str = latest['published'].replace('Z', '+00:00')
                if '.' in date_str:
                    latest_date = datetime.fromisoformat(date_str.split('.')[0]).replace(tzinfo=timezone.utc)
                else:
                    latest_date = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)
            except:
                pass

        return {
            'success': True,
            'latest_version': latest['version'],
            'latest_date': latest_date,
            'deprecated': latest['deprecated'],
            'version_count': len(versions),
            'repo_url': repo_url
        }

    def _analyze_npm_package(self, name: str, version: str) -> Dict:
        """Analyze NPM package"""
        self.request_count['npm'] += 1

        # NPM Registry API
        url = f"https://registry.npmjs.org/{name}"
        data = self._make_request(url)

        if not data:
            return {'success': False}

        # Get time information for all versions
        times = data.get('time', {})
        versions = data.get('versions', {})

        # Get latest version info
        latest_version = data.get('dist-tags', {}).get('latest')
        latest_time_str = times.get(latest_version)

        latest_date = None
        if latest_time_str:
            try:
                latest_date = datetime.strptime(latest_time_str.split('T')[0], '%Y-%m-%d').replace(tzinfo=timezone.utc)
            except:
                pass

        # Get repository URL
        repo_url = None
        if latest_version and latest_version in versions:
            repo_info = versions[latest_version].get('repository')
            if isinstance(repo_info, dict):
                repo_url = repo_info.get('url')
            elif isinstance(repo_info, str):
                repo_url = repo_info

        # Check deprecation
        deprecated = False
        if latest_version and latest_version in versions:
            deprecated = 'deprecated' in versions[latest_version]

        return {
            'success': True,
            'latest_version': latest_version,
            'latest_date': latest_date,
            'deprecated': deprecated,
            'version_count': len(versions),
            'repo_url': repo_url
        }

    def _analyze_pypi_package(self, name: str, version: str) -> Dict:
        """Analyze PyPI package"""
        self.request_count['pypi'] += 1

        # PyPI JSON API
        url = f"https://pypi.org/pypi/{name}/json"
        data = self._make_request(url)

        if not data:
            return {'success': False}

        # Get release information
        releases = data.get('releases', {})
        info = data.get('info', {})

        # Get latest version
        latest_version = info.get('version')

        # Get upload time for latest version
        latest_date = None
        if latest_version and latest_version in releases:
            release_files = releases[latest_version]
            if release_files and len(release_files) > 0:
                upload_time_str = release_files[0].get('upload_time_iso_8601')
                if upload_time_str:
                    try:
                        parsed_date = datetime.fromisoformat(upload_time_str.replace('Z', '+00:00'))
                        # Ensure timezone-aware
                        if parsed_date.tzinfo is None:
                            latest_date = parsed_date.replace(tzinfo=timezone.utc)
                        else:
                            latest_date = parsed_date
                    except:
                        pass

        # Get repository URL
        repo_url = None
        project_urls = info.get('project_urls', {})
        if project_urls:
            repo_url = (project_urls.get('Source') or
                       project_urls.get('Repository') or
                       project_urls.get('Homepage'))

        return {
            'success': True,
            'latest_version': latest_version,
            'latest_date': latest_date,
            'deprecated': False,  # PyPI doesn't have explicit deprecation
            'version_count': len(releases),
            'repo_url': repo_url
        }

    def _analyze_maven_package(self, group_id: str, artifact_id: str, version: str) -> Dict:
        """Analyze Maven package"""
        self.request_count['maven'] += 1

        # Maven Central Search API
        query = f"g:{group_id}+AND+a:{artifact_id}"
        url = f"https://search.maven.org/solrsearch/select?q={query}&rows=20&wt=json"

        data = self._make_request(url)

        if not data or data.get('response', {}).get('numFound', 0) == 0:
            return {'success': False}

        docs = data['response']['docs']
        if not docs:
            return {'success': False}

        # Get latest version (first in results)
        latest = docs[0]
        latest_version = latest.get('latestVersion') or latest.get('v')

        # Timestamp is in milliseconds
        timestamp_ms = latest.get('timestamp')
        latest_date = None
        if timestamp_ms:
            latest_date = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)

        return {
            'success': True,
            'latest_version': latest_version,
            'latest_date': latest_date,
            'deprecated': False,
            'version_count': len(docs),
            'repo_url': None
        }

    def _analyze_cocoapods_package(self, name: str, version: str) -> Dict:
        """Analyze CocoaPods package"""
        # CocoaPods API
        url = f"https://trunk.cocoapods.org/api/v1/pods/{name}"
        data = self._make_request(url)

        if not data:
            return {'success': False}

        # Get versions
        versions = data.get('versions', [])
        if not versions:
            return {'success': False}

        # Latest version is first
        latest = versions[0]
        latest_version = latest.get('name')

        # Parse created_at
        latest_date = None
        created_at = latest.get('created_at')
        if created_at:
            try:
                parsed_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                # Ensure timezone-aware
                if parsed_date.tzinfo is None:
                    latest_date = parsed_date.replace(tzinfo=timezone.utc)
                else:
                    latest_date = parsed_date
            except:
                pass

        # Get source URL
        repo_url = None
        source = data.get('source', {})
        if isinstance(source, dict):
            repo_url = source.get('git') or source.get('http')

        return {
            'success': True,
            'latest_version': latest_version,
            'latest_date': latest_date,
            'deprecated': data.get('deprecated', False),
            'version_count': len(versions),
            'repo_url': repo_url
        }

    def _calculate_support_level(
        self,
        package_data: Dict,
        repo_data: Optional[Dict],
        days_since_release: Optional[int]
    ) -> Tuple[str, str, str]:
        """
        Calculate support level and end of life date
        Returns: (support_level, end_of_life, confidence)
        """

        # Check if explicitly deprecated or archived
        if package_data.get('deprecated') or (repo_data and repo_data.get('archived')):
            return (
                SupportLevel.ABANDONED,
                package_data.get('latest_date').strftime('%Y-%m-%d') if package_data.get('latest_date') else 'Unknown',
                ConfidenceLevel.HIGH if repo_data else ConfidenceLevel.MEDIUM
            )

        # If we don't have release date, mark as unknown
        if days_since_release is None:
            return (
                SupportLevel.UNKNOWN,
                'Cannot determine',
                ConfidenceLevel.NONE
            )

        # Check repository commit activity if available
        recent_commits = False
        some_commits = False

        if repo_data and repo_data.get('last_commit_date'):
            days_since_commit = (self.today - repo_data['last_commit_date']).days
            if days_since_commit <= 180:  # 6 months
                recent_commits = True
                some_commits = True
            elif days_since_commit <= 365:  # 12 months
                some_commits = True

        # Decision matrix
        confidence = ConfidenceLevel.HIGH if repo_data else ConfidenceLevel.MEDIUM
        latest_date = package_data.get('latest_date')

        # ACTIVELY_MAINTAINED: release within 12 months AND recent commits
        if days_since_release <= 365:
            if recent_commits or not repo_data:  # If no repo data, trust the release date
                return (
                    SupportLevel.ACTIVELY_MAINTAINED,
                    self._calculate_eol_date(latest_date, years=5) if latest_date else 'Unknown',
                    confidence
                )
            else:
                # Released recently but no commits - might be stable/mature
                return (
                    SupportLevel.MAINTENANCE_MODE,
                    self._calculate_eol_date(latest_date, years=3) if latest_date else 'Unknown',
                    confidence
                )

        # MAINTENANCE_MODE: release within 24 months, some commits
        elif days_since_release <= 730:
            if some_commits or not repo_data:
                return (
                    SupportLevel.MAINTENANCE_MODE,
                    self._calculate_eol_date(latest_date, years=2) if latest_date else 'Unknown',
                    confidence
                )
            else:
                return (
                    SupportLevel.NO_LONGER_MAINTAINED,
                    self._calculate_eol_date(latest_date, years=2) if latest_date else 'Unknown',
                    ConfidenceLevel.MEDIUM
                )

        # NO_LONGER_MAINTAINED: release within 48 months
        elif days_since_release <= 1460:
            return (
                SupportLevel.NO_LONGER_MAINTAINED,
                self._calculate_eol_date(latest_date, years=1) if latest_date else 'Unknown',
                ConfidenceLevel.MEDIUM
            )

        # ABANDONED: release more than 48 months ago
        else:
            return (
                SupportLevel.ABANDONED,
                latest_date.strftime('%Y-%m-%d') if latest_date else 'Unknown',
                ConfidenceLevel.MEDIUM
            )

    def _calculate_eol_date(self, release_date: datetime, years: int) -> str:
        """Calculate end of life date"""
        if not release_date:
            return 'Unknown'

        eol_date = release_date + timedelta(days=365 * years)

        # If EOL is in the past, return as past date
        if eol_date < self.today:
            return f"{eol_date.strftime('%Y-%m-%d')} (expired)"

        return eol_date.strftime('%Y-%m-%d')

    def analyze_component(self, component: Dict) -> Dict:
        """Analyze a single component and return support information"""
        name = component.get('name', 'Unknown')
        version = component.get('version', 'Unknown')
        purl = component.get('purl')

        print(f"\nAnalyzing: {name} @ {version}")

        result = {
            'name': name,
            'version': version,
            'support_level': SupportLevel.UNKNOWN,
            'end_of_life': 'Cannot determine',
            'confidence': ConfidenceLevel.NONE,
            'last_release_date': None,
            'days_since_release': None,
            'last_commit_date': None,
            'analysis_timestamp': self.today.isoformat()
        }

        # Parse PURL if available
        if not purl:
            print(f"  No PURL available, skipping")
            return result

        purl_data = self._parse_purl(purl)
        if not purl_data:
            print(f"  Failed to parse PURL: {purl}")
            return result

        ecosystem = purl_data['ecosystem']
        pkg_name = purl_data['name']
        pkg_version = purl_data['version'] or version

        print(f"  Ecosystem: {ecosystem}")

        # Fetch package data based on ecosystem
        package_data = {'success': False}

        if ecosystem == 'nuget':
            package_data = self._analyze_nuget_package(pkg_name, pkg_version)
        elif ecosystem == 'npm':
            package_data = self._analyze_npm_package(pkg_name, pkg_version)
        elif ecosystem == 'pypi':
            package_data = self._analyze_pypi_package(pkg_name, pkg_version)
        elif ecosystem == 'maven':
            if purl_data['namespace']:
                package_data = self._analyze_maven_package(
                    purl_data['namespace'],
                    pkg_name,
                    pkg_version
                )
        elif ecosystem == 'cocoapods':
            package_data = self._analyze_cocoapods_package(pkg_name, pkg_version)
        elif ecosystem == 'github':
            # Direct GitHub component
            repo_url = f"https://github.com/{purl_data.get('namespace', '')}/{pkg_name}"
            repo_data = self._get_github_repo_info(repo_url)
            if repo_data:
                package_data = {
                    'success': True,
                    'latest_date': repo_data.get('last_commit_date'),
                    'deprecated': repo_data.get('archived', False)
                }

        if not package_data.get('success'):
            print(f"  Failed to fetch package data")
            return result

        # Calculate days since last release
        latest_date = package_data.get('latest_date')
        days_since_release = None
        if latest_date:
            days_since_release = (self.today - latest_date).days
            result['last_release_date'] = latest_date.strftime('%Y-%m-%d')
            result['days_since_release'] = days_since_release
            print(f"  Last release: {latest_date.strftime('%Y-%m-%d')} ({days_since_release} days ago)")

        # Fetch repository data if URL available
        repo_data = None
        repo_url = package_data.get('repo_url')

        # Also check externalReferences for repo URL
        if not repo_url:
            for ref in component.get('externalReferences', []):
                if ref.get('type') in ['vcs', 'website']:
                    url = ref.get('url', '')
                    if 'github.com' in url:
                        repo_url = url
                        break

        if repo_url and 'github.com' in repo_url:
            print(f"  Fetching repository data from GitHub...")
            repo_data = self._get_github_repo_info(repo_url)
            if repo_data and repo_data.get('last_commit_date'):
                result['last_commit_date'] = repo_data['last_commit_date'].strftime('%Y-%m-%d')
                days_since_commit = (self.today - repo_data['last_commit_date']).days
                print(f"  Last commit: {repo_data['last_commit_date'].strftime('%Y-%m-%d')} ({days_since_commit} days ago)")

        # Calculate support level
        support_level, eol, confidence = self._calculate_support_level(
            package_data,
            repo_data,
            days_since_release
        )

        result['support_level'] = support_level
        result['end_of_life'] = eol
        result['confidence'] = confidence

        print(f"  Support Level: {support_level} (Confidence: {confidence})")
        print(f"  End of Life: {eol}")

        return result


def analyze_sbom(
    sbom_path: str,
    output_path: Optional[str] = None,
    github_token: Optional[str] = None,
    max_workers: int = 5,
    limit: Optional[int] = None
) -> Dict:
    """
    Analyze all components in a CycloneDX or SPDX SBOM

    Args:
        sbom_path: Path to SBOM JSON file (CycloneDX or SPDX)
        output_path: Path to write enriched SBOM (optional)
        github_token: GitHub API token for higher rate limits
        max_workers: Number of parallel workers for API requests
        limit: Limit number of components to analyze (for testing)
    """
    print(f"Loading SBOM from: {sbom_path}")

    with open(sbom_path, 'r') as f:
        sbom = json.load(f)

    # Detect SBOM format
    sbom_format, version = detect_sbom_format(sbom)
    print(f"Detected format: {sbom_format} {version}")

    if sbom_format == SBOMFormat.UNKNOWN:
        print("ERROR: Unknown SBOM format. Supported formats: CycloneDX 1.4+, SPDX 2.2+")
        sys.exit(1)

    # Extract components based on format
    if sbom_format == SBOMFormat.CYCLONEDX:
        components = sbom.get('components', [])
        is_spdx = False
    else:  # SPDX
        # SPDX stores packages, need to normalize them
        spdx_packages = sbom.get('packages', [])
        components = [normalize_spdx_component(pkg) for pkg in spdx_packages]
        is_spdx = True

    total = len(components)

    if limit:
        components = components[:limit]
        if is_spdx:
            spdx_packages = spdx_packages[:limit]
        print(f"Analyzing {len(components)} of {total} components (limited)")
    else:
        print(f"Analyzing {total} components")

    analyzer = ComponentAnalyzer(github_token=github_token)

    # Analyze components
    results = []

    # Use sequential processing to respect rate limits
    # For production, implement proper rate limiting with ThreadPoolExecutor
    for i, component in enumerate(components, 1):
        print(f"\n[{i}/{len(components)}]", "=" * 60)
        result = analyzer.analyze_component(component)
        results.append(result)

        # Add support data based on format
        if is_spdx:
            # For SPDX, add annotations to original package
            add_support_data_to_spdx(spdx_packages[i-1], result)
        else:
            # For CycloneDX, add properties
            properties = component.get('properties', [])

            # Remove existing support analysis properties
            properties = [p for p in properties if not p.get('name', '').startswith('support')]

            # Add new properties
            properties.extend([
                {'name': 'supportLevel', 'value': result['support_level']},
                {'name': 'supportEndOfLife', 'value': result['end_of_life']},
                {'name': 'supportConfidence', 'value': result['confidence']},
                {'name': 'supportLastReleaseDate', 'value': result['last_release_date'] or 'Unknown'},
                {'name': 'supportDaysSinceRelease', 'value': str(result['days_since_release']) if result['days_since_release'] else 'Unknown'},
                {'name': 'supportLastCommitDate', 'value': result['last_commit_date'] or 'Unknown'},
                {'name': 'supportAnalysisTimestamp', 'value': result['analysis_timestamp']}
            ])

            component['properties'] = properties

            # Update original SBOM component
            original_components = sbom.get('components', [])
            if i-1 < len(original_components):
                original_components[i-1]['properties'] = properties

        # Rate limiting pause
        time.sleep(0.5)

    # Print summary
    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)

    summary = {
        SupportLevel.ACTIVELY_MAINTAINED: 0,
        SupportLevel.MAINTENANCE_MODE: 0,
        SupportLevel.NO_LONGER_MAINTAINED: 0,
        SupportLevel.ABANDONED: 0,
        SupportLevel.UNKNOWN: 0
    }

    for result in results:
        summary[result['support_level']] += 1

    print(f"Total components analyzed: {len(results)}")
    print(f"  Actively Maintained:     {summary[SupportLevel.ACTIVELY_MAINTAINED]}")
    print(f"  Maintenance Mode:        {summary[SupportLevel.MAINTENANCE_MODE]}")
    print(f"  No Longer Maintained:    {summary[SupportLevel.NO_LONGER_MAINTAINED]}")
    print(f"  Abandoned:               {summary[SupportLevel.ABANDONED]}")
    print(f"  Unknown:                 {summary[SupportLevel.UNKNOWN]}")

    print(f"\nAPI Request counts:")
    for api, count in analyzer.request_count.items():
        print(f"  {api}: {count}")

    # Write enriched SBOM
    if output_path:
        print(f"\nWriting enriched SBOM to: {output_path}")
        with open(output_path, 'w') as f:
            json.dump(sbom, f, indent=2)
        print("Done!")

    # Write summary report
    summary_path = output_path.replace('.json', '_summary.json') if output_path else 'sbom_summary.json'
    print(f"\nWriting summary report to: {summary_path}")

    summary_report = {
        'analysis_date': datetime.now().isoformat(),
        'sbom_file': sbom_path,
        'total_components': len(results),
        'summary': summary,
        'components': results
    }

    with open(summary_path, 'w') as f:
        json.dump(summary_report, f, indent=2)

    return summary_report


def main():
    parser = argparse.ArgumentParser(
        description='Analyze CycloneDX or SPDX SBOM components for support levels and end-of-life dates'
    )
    parser.add_argument(
        'sbom_file',
        help='Path to SBOM JSON file (CycloneDX 1.4+ or SPDX 2.2+)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Path to write enriched SBOM (default: adds _analyzed suffix)'
    )
    parser.add_argument(
        '-t', '--token',
        help='GitHub API token for higher rate limits (recommended)'
    )
    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=5,
        help='Number of parallel workers (default: 5)'
    )
    parser.add_argument(
        '-l', '--limit',
        type=int,
        help='Limit number of components to analyze (for testing)'
    )

    args = parser.parse_args()

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        base = args.sbom_file.replace('.json', '')
        output_path = f"{base}_analyzed.json"

    # Check for GitHub token in environment
    github_token = args.token or os.environ.get('GITHUB_TOKEN')

    if not github_token:
        print("WARNING: No GitHub token provided. Rate limits will be restrictive (60 req/hour).")
        print("Consider setting GITHUB_TOKEN environment variable or using --token option.")
        print()

    try:
        analyze_sbom(
            args.sbom_file,
            output_path,
            github_token,
            args.workers,
            args.limit
        )
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
