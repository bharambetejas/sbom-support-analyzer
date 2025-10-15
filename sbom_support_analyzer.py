#!/usr/bin/env python3
"""
SBOM Support Level Analyzer
Analyzes CycloneDX and SPDX SBOM components to determine support level and end-of-life dates
based on real data from package registries and repositories.

Supported formats:
- CycloneDX 1.4, 1.5, 1.6
- SPDX 2.2, 2.3

Strategy Philosophy:
This analyzer uses a realistic, lenient approach recognizing that mature, stable libraries
don't require frequent updates. Components are only marked as ABANDONED when there is
explicit evidence (archived repository, deprecation notice). Stable libraries with
infrequent releases are considered ACTIVELY_MAINTAINED or MAINTENANCE_MODE rather than
being penalized for stability.
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
    """Support level classifications (FDA-aligned)"""
    ACTIVELY_MAINTAINED = "ACTIVELY_MAINTAINED"
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


# Framework support lifecycle database
# Each entry contains: (EOL date, support status)
FRAMEWORK_SUPPORT = {
    # .NET / NuGet ecosystem
    'dotnet': {
        '.NET 9.0': ('2026-05-12', 'STS'),  # Standard Term Support
        '.NET 8.0': ('2026-11-10', 'LTS'),  # Long Term Support
        '.NET 7.0': ('2024-05-14', 'EOL'),  # End of Life
        '.NET 6.0': ('2024-11-12', 'EOL'),  # End of Life
        '.NET 5.0': ('2022-05-10', 'EOL'),
        '.NET Core 3.1': ('2022-12-13', 'EOL'),
        '.NET Core 3.0': ('2020-03-03', 'EOL'),
        '.NET Core 2.1': ('2021-08-21', 'EOL'),
        '.NET Framework 4.8': ('2028-01-11', 'LTS'),  # Follows Windows lifecycle
        '.NET Framework 4.7': ('2028-01-11', 'LTS'),
        '.NET Framework 4.6': ('2028-01-11', 'LTS'),
    },

    # Java ecosystem
    'java': {
        'Java 21': ('2031-09-01', 'LTS'),
        'Java 17': ('2029-09-01', 'LTS'),
        'Java 11': ('2026-09-01', 'LTS'),
        'Java 8': ('2030-12-01', 'LTS'),  # Extended support
        'Java 7': ('2022-07-01', 'EOL'),
        'Java 6': ('2018-12-01', 'EOL'),
    },

    # Python ecosystem
    'python': {
        'Python 3.13': ('2029-10-01', 'Active'),
        'Python 3.12': ('2028-10-01', 'Active'),
        'Python 3.11': ('2027-10-01', 'Active'),
        'Python 3.10': ('2026-10-01', 'Active'),
        'Python 3.9': ('2025-10-01', 'Security'),
        'Python 3.8': ('2024-10-01', 'EOL'),
        'Python 3.7': ('2023-06-27', 'EOL'),
        'Python 3.6': ('2021-12-23', 'EOL'),
        'Python 2.7': ('2020-01-01', 'EOL'),
    },

    # Node.js ecosystem
    'nodejs': {
        'Node.js 22': ('2027-04-30', 'LTS'),
        'Node.js 20': ('2026-04-30', 'LTS'),
        'Node.js 18': ('2025-04-30', 'LTS'),
        'Node.js 16': ('2023-09-11', 'EOL'),
        'Node.js 14': ('2023-04-30', 'EOL'),
        'Node.js 12': ('2022-04-30', 'EOL'),
    },

    # Spring Framework (Java)
    'spring': {
        'Spring Boot 3.x': ('2025-11-01', 'Active'),  # Approximate
        'Spring Boot 2.x': ('2023-11-24', 'EOL'),
        'Spring Framework 6.x': ('2026-12-01', 'Active'),
        'Spring Framework 5.x': ('2024-12-31', 'EOL'),
    }
}

# Framework component patterns
# Maps component name patterns to framework identification
FRAMEWORK_PATTERNS = {
    'dotnet': [
        r'^System\.',
        r'^Microsoft\.NETCore\.',
        r'^Microsoft\.Extensions\.',
        r'^runtime\.native\.',
        r'^runtime\.',
        r'^NETStandard\.Library$',
    ],
    'java': [
        r'^java\.',
        r'^javax\.',
        r'^jakarta\.',
    ],
    'python': [
        r'^python$',
        r'^cpython$',
    ],
    'nodejs': [
        r'^node$',
        r'^nodejs$',
    ],
    'spring': [
        r'^spring-',
        r'^org\.springframework\.',
    ]
}


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
            'annotationDate': timestamp,
            'comment': f"supportLevel: {result['support_level']}"
        },
        {
            'annotationDate': timestamp,
            'comment': f"supportEndOfLife: {result['end_of_life']}"
        },
        {
            'annotationDate': timestamp,
            'comment': f"supportConfidence: {result['confidence']}"
        },
        {
            'annotationDate': timestamp,
            'comment': f"supportLastReleaseDate: {result['last_release_date'] or 'Unknown'}"
        },
        {
            'annotationDate': timestamp,
            'comment': f"supportDaysSinceRelease: {result['days_since_release'] if result['days_since_release'] else 'Unknown'}"
        }
    ]

    spdx_package['annotations'].extend(annotations)


class ComponentAnalyzer:
    """Analyzes individual components for support status"""

    def __init__(self, github_token: Optional[str] = None, use_cache: bool = True, product_eol_date: Optional[str] = None):
        self.github_token = github_token
        self.use_cache = use_cache
        self.cache = {}
        self.request_count = {"github": 0, "nuget": 0, "npm": 0, "pypi": 0, "maven": 0}
        self.today = datetime.now(timezone.utc)
        self.product_eol_date = product_eol_date  # Product end-of-life date

    def _detect_framework(self, name: str, ecosystem: Optional[str] = None) -> Optional[str]:
        """
        Detect if a component belongs to a known framework
        Returns: framework key (e.g., 'dotnet', 'java') or None
        """
        # Check against each framework's patterns
        for framework, patterns in FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.match(pattern, name, re.IGNORECASE):
                    return framework

        # Additional ecosystem-based hints
        if ecosystem == 'nuget':
            # If it's a NuGet package and starts with certain prefixes, it's likely .NET
            if name.startswith(('System.', 'Microsoft.', 'runtime.')):
                return 'dotnet'

        return None

    def _get_framework_support(self, framework: str, version: str) -> Optional[Tuple[str, str]]:
        """
        Get framework support information
        Returns: (eol_date, support_status) or None
        """
        if framework not in FRAMEWORK_SUPPORT:
            return None

        framework_versions = FRAMEWORK_SUPPORT[framework]

        # For .NET, try to infer version from component version or name
        if framework == 'dotnet':
            # Try to match version patterns
            # Common patterns: "8.0.0", "8.0.1", "6.0.0", etc.
            version_match = re.match(r'^(\d+)\.(\d+)', version)
            if version_match:
                major = version_match.group(1)
                minor = version_match.group(2)

                # Try exact match first
                for fw_version, (eol_date, status) in framework_versions.items():
                    if f'.NET {major}.{minor}' in fw_version or f'.NET {major}' in fw_version:
                        return (eol_date, status)

                # Try without minor version
                for fw_version, (eol_date, status) in framework_versions.items():
                    if f'.NET {major}' in fw_version:
                        return (eol_date, status)

        # For other frameworks, try direct matching
        for fw_version, (eol_date, status) in framework_versions.items():
            if version in fw_version:
                return (eol_date, status)

        return None

    def _is_framework_supported(self, framework: str, version: str) -> Optional[Tuple[bool, Optional[str], Optional[str]]]:
        """
        Check if a framework version is currently supported
        Returns: (is_supported, eol_date, support_status) or None if unknown
        """
        support_info = self._get_framework_support(framework, version)
        if not support_info:
            return None

        eol_date_str, support_status = support_info

        try:
            eol_date = datetime.strptime(eol_date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            is_supported = eol_date > self.today and support_status not in ['EOL']
            return (is_supported, eol_date_str, support_status)
        except:
            return None

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
            # Pattern allows dots in repo name but stops at .git suffix or path separators
            match = re.search(r'github\.com[/:]([^/]+)/([^/\s?#]+)', repo_url)
            if not match:
                return None

            owner, repo = match.groups()

            # Clean repo name - remove .git suffix and any trailing slashes
            repo = repo.rstrip('/').replace('.git', '')

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
                'stargazers': repo_data.get('stargazers_count', 0),
                'owner': owner,
                'repo': repo
            }
        except Exception as e:
            print(f"  [Error] GitHub repo analysis failed: {e}", file=sys.stderr)
            return None

    def _get_github_release_for_version(self, owner: str, repo: str, version: str) -> Optional[datetime]:
        """
        Get the release date for a specific version from GitHub releases/tags
        This is more accurate than using the latest commit date
        """
        try:
            headers = {}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'

            # Try releases API first
            releases_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
            releases_data = self._make_request(releases_url, headers)

            if releases_data and isinstance(releases_data, list):
                # Try to find exact version match
                # Extract numeric version if possible (e.g., "Json.NET 2.0" -> "2.0")
                numeric_version = version
                if ' ' in version:
                    parts = version.split()
                    for part in parts:
                        if any(c.isdigit() for c in part):
                            numeric_version = part
                            break

                version_patterns = [
                    version,  # Exact match (e.g., "Json.NET 2.0")
                    f"v{version}",  # With v prefix
                    numeric_version,  # Numeric part only (e.g., "2.0")
                    f"v{numeric_version}",  # Numeric with v prefix
                    version.replace(' ', '_'),  # Spaces to underscores (e.g., "Json.NET_2.0")
                    version.replace(' ', '-'),  # Spaces to hyphens
                    f"{version}.0" if version.count('.') == 1 else version,  # Add patch if missing
                    version.split('-')[0] if '-' in version else version  # Without pre-release suffix
                ]

                for release in releases_data:
                    tag_name = release.get('tag_name', '').lower()
                    release_name = release.get('name', '').lower()

                    # Check if this release matches our version
                    for pattern in version_patterns:
                        pattern_lower = pattern.lower()
                        if (pattern_lower in tag_name or
                            pattern_lower == tag_name.lstrip('v') or
                            pattern_lower in release_name or
                            tag_name.replace('_', ' ') == pattern_lower or
                            tag_name.replace('-', ' ') == pattern_lower):
                            published_at = release.get('published_at')
                            if published_at:
                                try:
                                    return datetime.strptime(published_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                                except:
                                    pass

            # If no release found, try tags API
            tags_url = f"https://api.github.com/repos/{owner}/{repo}/tags"
            tags_data = self._make_request(tags_url, headers)

            if tags_data and isinstance(tags_data, list):
                for tag in tags_data:
                    tag_name = tag.get('name', '').lower()
                    for pattern in version_patterns:
                        pattern_lower = pattern.lower()
                        if (pattern_lower in tag_name or
                            pattern_lower == tag_name.lstrip('v') or
                            tag_name.replace('_', ' ') == pattern_lower or
                            tag_name.replace('-', ' ') == pattern_lower):
                            # Get commit info for this tag
                            commit_sha = tag.get('commit', {}).get('sha')
                            if commit_sha:
                                commit_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
                                commit_data = self._make_request(commit_url, headers)
                                if commit_data:
                                    commit_date_str = commit_data.get('commit', {}).get('committer', {}).get('date')
                                    if commit_date_str:
                                        try:
                                            return datetime.strptime(commit_date_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                                        except:
                                            pass

            return None

        except Exception as e:
            print(f"  [Debug] GitHub release lookup failed: {e}", file=sys.stderr)
            return None

    def _analyze_from_url(self, url: str, name: str, version: str) -> Dict:
        """
        Analyze a package from a URL (fallback when PURL is not available)
        Supports GitHub, GitLab, Bitbucket, and other repository URLs
        """
        print(f"  Attempting to analyze from URL: {url}")

        # Check if it's a GitHub URL (including github.io project pages)
        if 'github.com' in url:
            repo_data = self._get_github_repo_info(url)
            if repo_data:
                # Try to get version-specific release date
                version_date = self._get_github_release_for_version(
                    repo_data['owner'],
                    repo_data['repo'],
                    version
                )

                # Fall back to latest commit if no version-specific date found
                release_date = version_date if version_date else repo_data.get('last_commit_date')

                if version_date:
                    print(f"  Found release date for version {version}")
                else:
                    print(f"  No version-specific release found, using latest commit date")

                return {
                    'success': True,
                    'latest_date': release_date,
                    'deprecated': repo_data.get('archived', False),
                    'latest_version': version,
                    'version_count': 1,
                    'repo_url': url,
                    'source': 'github_direct'
                }

        # Check for github.io URLs - try to infer the repo
        elif 'github.io' in url:
            # github.io format is usually: username.github.io/reponame
            match = re.search(r'([^/]+)\.github\.io/([^/]+)', url)
            if match:
                username, repo_name = match.groups()
                github_url = f"https://github.com/{username}/{repo_name}"
                repo_data = self._get_github_repo_info(github_url)
                if repo_data:
                    # Try to get version-specific release date
                    version_date = self._get_github_release_for_version(
                        repo_data['owner'],
                        repo_data['repo'],
                        version
                    )

                    # Fall back to latest commit if no version-specific date found
                    release_date = version_date if version_date else repo_data.get('last_commit_date')

                    if version_date:
                        print(f"  Found release date for version {version}")
                    else:
                        print(f"  No version-specific release found, using latest commit date")

                    return {
                        'success': True,
                        'latest_date': release_date,
                        'deprecated': repo_data.get('archived', False),
                        'latest_version': version,
                        'version_count': 1,
                        'repo_url': github_url,
                        'source': 'github_inferred'
                    }

        # Check if it's a GitLab URL
        elif 'gitlab.com' in url or 'gitlab.' in url:
            return self._analyze_gitlab_url(url, name, version)

        # Check if it's a Bitbucket URL
        elif 'bitbucket.org' in url:
            return self._analyze_bitbucket_url(url, name, version)

        # Check if it's a Google Source URL (googlesource.com)
        elif 'googlesource.com' in url:
            # Google Source doesn't have a public API, but we can try to infer from the URL
            # For now, mark as low confidence unknown
            print(f"  [Info] Google Source repositories require manual analysis")
            return {'success': False}

        # Check if it's a known package registry URL
        elif 'npmjs.com' in url or 'npmjs.org' in url:
            # Extract package name from URL
            match = re.search(r'npmjs\.(?:com|org)/package/([^/]+)', url)
            if match:
                pkg_name = match.group(1)
                return self._analyze_npm_package(pkg_name, version)

        elif 'pypi.org' in url or 'pypi.python.org' in url:
            # Extract package name from URL
            match = re.search(r'pypi\.org/project/([^/]+)', url)
            if match:
                pkg_name = match.group(1)
                return self._analyze_pypi_package(pkg_name, version)

        elif 'nuget.org' in url:
            # Extract package name from URL
            match = re.search(r'nuget\.org/packages/([^/]+)', url)
            if match:
                pkg_name = match.group(1)
                return self._analyze_nuget_package(pkg_name, version)

        elif 'maven' in url or 'mvnrepository.com' in url:
            # Try to extract group and artifact from URL
            match = re.search(r'([^/]+)/([^/]+)/([^/]+)', url)
            if match:
                group_id, artifact_id = match.group(1), match.group(2)
                return self._analyze_maven_package(group_id, artifact_id, version)

        # Check if it's a Boost library URL
        elif 'boost.org' in url:
            # Boost is a special case - it's a C++ library with releases on GitHub
            return self._analyze_from_url('https://github.com/boostorg/boost', name, version)

        # Check if it's a c-ares URL
        elif 'c-ares' in url:
            # c-ares is hosted on GitHub
            return self._analyze_from_url('https://github.com/c-ares/c-ares', name, version)

        print(f"  [Warning] Unable to analyze URL: {url}")
        return {'success': False}

    def _analyze_gitlab_url(self, url: str, name: str, version: str) -> Dict:
        """Analyze a GitLab repository URL"""
        try:
            # Extract project path from URL
            match = re.search(r'gitlab\.com/([^/]+/[^/]+)', url)
            if not match:
                # Try generic gitlab instance
                match = re.search(r'gitlab\.[^/]+/([^/]+/[^/]+)', url)

            if not match:
                return {'success': False}

            project_path = match.group(1).replace('.git', '')

            # GitLab API endpoint
            api_url = f"https://gitlab.com/api/v4/projects/{project_path.replace('/', '%2F')}"

            project_data = self._make_request(api_url)
            if not project_data:
                return {'success': False}

            # Get last commit/activity date
            last_activity = project_data.get('last_activity_at')
            last_date = None
            if last_activity:
                try:
                    last_date = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                    if last_date.tzinfo is None:
                        last_date = last_date.replace(tzinfo=timezone.utc)
                except:
                    pass

            return {
                'success': True,
                'latest_date': last_date,
                'deprecated': project_data.get('archived', False),
                'latest_version': version,
                'version_count': 1,
                'repo_url': url,
                'source': 'gitlab_direct'
            }
        except Exception as e:
            print(f"  [Error] GitLab analysis failed: {e}", file=sys.stderr)
            return {'success': False}

    def _analyze_bitbucket_url(self, url: str, name: str, version: str) -> Dict:
        """Analyze a Bitbucket repository URL"""
        try:
            # Extract workspace/repo from URL
            match = re.search(r'bitbucket\.org/([^/]+)/([^/]+)', url)
            if not match:
                return {'success': False}

            workspace, repo_slug = match.groups()
            repo_slug = repo_slug.replace('.git', '')

            # Bitbucket API endpoint
            api_url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}"

            repo_data = self._make_request(api_url)
            if not repo_data:
                return {'success': False}

            # Get last updated date
            updated_on = repo_data.get('updated_on')
            last_date = None
            if updated_on:
                try:
                    last_date = datetime.fromisoformat(updated_on.replace('Z', '+00:00'))
                    if last_date.tzinfo is None:
                        last_date = last_date.replace(tzinfo=timezone.utc)
                except:
                    pass

            return {
                'success': True,
                'latest_date': last_date,
                'deprecated': False,  # Bitbucket doesn't have archived status in same way
                'latest_version': version,
                'version_count': 1,
                'repo_url': url,
                'source': 'bitbucket_direct'
            }
        except Exception as e:
            print(f"  [Error] Bitbucket analysis failed: {e}", file=sys.stderr)
            return {'success': False}

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
        specific_version_data = None

        for item in data.get('items', []):
            # Check if we need to fetch page data
            if 'items' in item:
                # Inline items
                items_to_process = item['items']
            else:
                # Need to fetch page
                page_url = item.get('@id')
                if page_url:
                    page_data = self._make_request(page_url)
                    if page_data:
                        items_to_process = page_data.get('items', [])
                    else:
                        items_to_process = []
                else:
                    items_to_process = []

            for package_item in items_to_process:
                catalog_entry = package_item.get('catalogEntry', {})
                pkg_version = catalog_entry.get('version')
                published = catalog_entry.get('published')
                deprecated = catalog_entry.get('deprecation') is not None

                # NuGet uses 1900-01-01 for unlisted packages - use commitTimeStamp instead
                if published and published.startswith('1900-01-01'):
                    commit_timestamp = package_item.get('commitTimeStamp')
                    if commit_timestamp:
                        published = commit_timestamp
                        print(f"  [Debug] Using commitTimeStamp for unlisted package: {commit_timestamp}", file=sys.stderr)

                versions.append({
                    'version': pkg_version,
                    'published': published,
                    'deprecated': deprecated
                })

                # Check if this is the specific version we're looking for
                if pkg_version == version:
                    specific_version_data = {
                        'version': pkg_version,
                        'published': published,
                        'deprecated': deprecated
                    }

                # Extract repository URL
                if not repo_url:
                    repo_url = catalog_entry.get('projectUrl') or catalog_entry.get('licenseUrl')

        if not versions:
            return {'success': False}

        # Sort by published date
        versions = sorted(versions, key=lambda x: x['published'] if x['published'] else '', reverse=True)

        # Use specific version if found, otherwise use latest
        target_version = specific_version_data if specific_version_data else versions[0]

        # Parse published date
        latest_date = None
        if target_version['published']:
            try:
                # Handle various date formats
                date_str = target_version['published'].replace('Z', '+00:00')
                # Handle milliseconds
                if '.' in date_str and '+' in date_str:
                    # Split at '+' to separate timezone
                    dt_part, tz_part = date_str.rsplit('+', 1)
                    # Remove milliseconds if present
                    if '.' in dt_part:
                        dt_part = dt_part.split('.')[0]
                    date_str = f"{dt_part}+{tz_part}"
                    latest_date = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)
                elif '.' in date_str:
                    latest_date = datetime.fromisoformat(date_str.split('.')[0]).replace(tzinfo=timezone.utc)
                else:
                    latest_date = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)
            except Exception as e:
                print(f"  [Debug] Date parse error: {e}", file=sys.stderr)
                pass

        return {
            'success': True,
            'latest_version': target_version['version'],
            'latest_date': latest_date,
            'deprecated': target_version['deprecated'],
            'version_count': len(versions),
            'repo_url': repo_url,
            'is_specific_version': specific_version_data is not None
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

        # Try to find specific version first
        target_version = version if version in versions else data.get('dist-tags', {}).get('latest')
        target_time_str = times.get(target_version)

        latest_date = None
        if target_time_str:
            try:
                latest_date = datetime.strptime(target_time_str.split('T')[0], '%Y-%m-%d').replace(tzinfo=timezone.utc)
            except:
                pass

        # Get repository URL
        repo_url = None
        if target_version and target_version in versions:
            repo_info = versions[target_version].get('repository')
            if isinstance(repo_info, dict):
                repo_url = repo_info.get('url')
            elif isinstance(repo_info, str):
                repo_url = repo_info

        # Check deprecation for the specific version
        deprecated = False
        if target_version and target_version in versions:
            deprecated = 'deprecated' in versions[target_version]

        return {
            'success': True,
            'latest_version': target_version,
            'latest_date': latest_date,
            'deprecated': deprecated,
            'version_count': len(versions),
            'repo_url': repo_url,
            'is_specific_version': (version in versions)
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

        # Try to find specific version first, otherwise use latest
        target_version = version if version in releases else info.get('version')

        # Get upload time for target version
        latest_date = None
        if target_version and target_version in releases:
            release_files = releases[target_version]
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
            'latest_version': target_version,
            'latest_date': latest_date,
            'deprecated': False,  # PyPI doesn't have explicit deprecation
            'version_count': len(releases),
            'repo_url': repo_url,
            'is_specific_version': (version in releases)
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
        days_since_release: Optional[int],
        name: str = "",
        version: str = "",
        ecosystem: Optional[str] = None
    ) -> Tuple[str, str, str]:
        """
        Calculate support level and end of life date (FDA-aligned categories)
        Returns: (support_level, end_of_life, confidence)

        FDA Categories:
        - ACTIVELY_MAINTAINED: Active development or stable maintenance
        - NO_LONGER_MAINTAINED: Inactive but not explicitly abandoned
        - ABANDONED: Explicitly marked as deprecated/abandoned on website

        EOL Philosophy: Component EOL is tied to product EOL. All maintained components
        inherit the product's end-of-life date, as vendors support all dependencies
        throughout the product lifecycle.

        Framework Detection: Components belonging to supported frameworks (e.g., .NET 8,
        Java 17) are classified based on the framework's support lifecycle, not the
        component's individual release date.
        """

        # STEP 1: Check if component belongs to a framework
        framework = self._detect_framework(name, ecosystem)
        if framework:
            print(f"  Detected framework: {framework}")
            framework_support = self._is_framework_supported(framework, version)
            if framework_support:
                is_supported, eol_date, support_status = framework_support
                print(f"  Framework support: {support_status} (EOL: {eol_date})")

                if is_supported:
                    # Framework is actively supported, use framework EOL
                    return (
                        SupportLevel.ACTIVELY_MAINTAINED,
                        eol_date,
                        ConfidenceLevel.HIGH
                    )
                else:
                    # Framework is EOL
                    return (
                        SupportLevel.NO_LONGER_MAINTAINED,
                        eol_date,
                        ConfidenceLevel.HIGH
                    )

        # STEP 2: Check if explicitly deprecated on package registry (explicit abandonment)
        if package_data.get('deprecated'):
            return (
                SupportLevel.ABANDONED,
                package_data.get('latest_date').strftime('%Y-%m-%d') if package_data.get('latest_date') else 'Unknown',
                ConfidenceLevel.HIGH
            )

        # STEP 3: Check if repository is explicitly archived (explicit abandonment)
        if repo_data and repo_data.get('archived'):
            return (
                SupportLevel.ABANDONED,
                package_data.get('latest_date').strftime('%Y-%m-%d') if package_data.get('latest_date') else 'Unknown',
                ConfidenceLevel.HIGH
            )

        # If we don't have release date, mark as unknown
        if days_since_release is None:
            return (
                SupportLevel.UNKNOWN,
                'Cannot determine',
                ConfidenceLevel.NONE
            )

        # Check repository commit activity if available
        recent_commits = False  # Within 12 months
        some_commits = False    # Within 24 months
        high_community_engagement = False

        if repo_data:
            if repo_data.get('last_commit_date'):
                days_since_commit = (self.today - repo_data['last_commit_date']).days
                if days_since_commit <= 365:  # 12 months
                    recent_commits = True
                    some_commits = True
                elif days_since_commit <= 730:  # 24 months
                    some_commits = True

            # Check community engagement (stars, forks indicate viability)
            stars = repo_data.get('stargazers', 0)
            forks = repo_data.get('forks', 0)
            if stars > 100 or forks > 20:
                high_community_engagement = True

        latest_date = package_data.get('latest_date')

        # ACTIVELY_MAINTAINED: Recent activity (within 5 years) - includes previously "maintenance mode"
        # This covers both active development and stable/mature libraries
        if days_since_release <= 1825:  # 5 years
            return (
                SupportLevel.ACTIVELY_MAINTAINED,
                self.product_eol_date if self.product_eol_date else 'Not specified',
                ConfidenceLevel.HIGH if (recent_commits or some_commits) else ConfidenceLevel.MEDIUM
            )

        # NO_LONGER_MAINTAINED: Old release (>5 years) but not explicitly abandoned
        # Previously categorized as ABANDONED but without explicit deprecation
        else:
            return (
                SupportLevel.NO_LONGER_MAINTAINED,
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

        # Fetch package data based on ecosystem
        package_data = {'success': False}
        purl_data = None

        # Try PURL-based analysis first
        if purl:
            purl_data = self._parse_purl(purl)
            if not purl_data:
                print(f"  Failed to parse PURL: {purl}")
            else:
                ecosystem = purl_data['ecosystem']
                pkg_name = purl_data['name']
                pkg_version = purl_data['version'] or version

                print(f"  Ecosystem: {ecosystem}")

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

        # If PURL-based analysis failed or PURL not available, try URL-based analysis
        if not package_data.get('success'):
            if not purl:
                print(f"  No PURL available, attempting URL-based analysis")
            else:
                print(f"  PURL-based analysis failed, attempting URL-based analysis")

            # Look for URLs in externalReferences
            external_refs = component.get('externalReferences', [])

            # Prioritize different reference types
            priority_order = ['vcs', 'repository', 'website', 'distribution']
            urls_to_try = []

            for ref_type in priority_order:
                for ref in external_refs:
                    if ref.get('type') == ref_type and ref.get('url'):
                        urls_to_try.append(ref.get('url'))

            # Add any remaining URLs
            for ref in external_refs:
                url = ref.get('url')
                if url and url not in urls_to_try:
                    urls_to_try.append(url)

            # Try each URL until we get a successful analysis
            for url in urls_to_try:
                package_data = self._analyze_from_url(url, name, version)
                if package_data.get('success'):
                    break

        if not package_data.get('success'):
            print(f"  Unable to fetch package data from any source")
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
            days_since_release,
            name=name,
            version=version,
            ecosystem=purl_data.get('ecosystem') if purl_data else None
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
    limit: Optional[int] = None,
    product_eol_date: Optional[str] = None
) -> Dict:
    """
    Analyze all components in a CycloneDX or SPDX SBOM

    Args:
        sbom_path: Path to SBOM JSON file (CycloneDX or SPDX)
        output_path: Path to write enriched SBOM (optional)
        github_token: GitHub API token for higher rate limits
        max_workers: Number of parallel workers for API requests
        limit: Limit number of components to analyze (for testing)
        product_eol_date: Product end-of-life date (YYYY-MM-DD format)
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

    if product_eol_date:
        print(f"Product End-of-Life Date: {product_eol_date}")
    else:
        print("Product End-of-Life Date: Not specified")

    analyzer = ComponentAnalyzer(github_token=github_token, product_eol_date=product_eol_date)

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
        SupportLevel.NO_LONGER_MAINTAINED: 0,
        SupportLevel.ABANDONED: 0,
        SupportLevel.UNKNOWN: 0
    }

    for result in results:
        summary[result['support_level']] += 1

    print(f"Total components analyzed: {len(results)}")
    print(f"  Actively Maintained:     {summary[SupportLevel.ACTIVELY_MAINTAINED]}")
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
    parser.add_argument(
        '-e', '--eol-date',
        help='Product end-of-life date in YYYY-MM-DD format (e.g., 2030-12-31)'
    )

    args = parser.parse_args()

    # Prompt for product EOL date if not provided via command line
    product_eol_date = args.eol_date
    if not product_eol_date:
        print("\n" + "=" * 70)
        print("PRODUCT END-OF-LIFE DATE")
        print("=" * 70)
        print("Enter the product's end-of-life date. This date will be used as the")
        print("EOL for all actively maintained and maintenance mode components.")
        print("Format: YYYY-MM-DD (e.g., 2030-12-31)")
        print("Leave blank to skip (components will show 'Not specified')")
        print("-" * 70)

        try:
            user_input = input("Product EOL Date: ").strip()
            if user_input:
                # Validate date format
                try:
                    datetime.strptime(user_input, '%Y-%m-%d')
                    product_eol_date = user_input
                    print(f"✓ Using product EOL date: {product_eol_date}")
                except ValueError:
                    print("⚠ Invalid date format. Proceeding without EOL date.")
                    product_eol_date = None
            else:
                print("⚠ No EOL date provided. Proceeding without EOL date.")
                product_eol_date = None
        except (KeyboardInterrupt, EOFError):
            print("\n⚠ Skipping EOL date input.")
            product_eol_date = None

        print("=" * 70 + "\n")
    else:
        # Validate provided EOL date
        try:
            datetime.strptime(product_eol_date, '%Y-%m-%d')
            print(f"Using product EOL date from command line: {product_eol_date}")
        except ValueError:
            print(f"ERROR: Invalid EOL date format '{product_eol_date}'. Expected YYYY-MM-DD")
            sys.exit(1)

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
            args.limit,
            product_eol_date
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
