# Support Level Analysis Strategy for CycloneDX or SPDX SBOM Components

## Overview
This strategy determines the maintenance status and end-of-life dates for software components by analyzing real-world data from package registries, source repositories, and release patterns.

**Key Principle:** The analyzer evaluates the **specific version** listed in the SBOM, not the latest available version. This ensures accurate risk assessment based on what's actually deployed.

**Philosophy:** Many mature, stable libraries don't require frequent updates. Lack of recent releases often indicates stability rather than abandonment. Components are only marked as abandoned when there is explicit evidence (archived repository, deprecation notice, or critical unfixed vulnerabilities).

## Support Level Definitions (FDA-Aligned)

### 1. ACTIVELY_MAINTAINED
**Criteria:**
- **Framework components:** Part of a currently supported framework (e.g., .NET 8, Java 17)
- **Regular components:** Latest release within last 60 months (5 years)
- Covers both active development AND stable/mature libraries
- No explicit deprecation or archival

**Framework Detection:** Components belonging to known frameworks (.NET, Java, Python, Node.js, Spring) are evaluated based on the framework's support lifecycle rather than individual component age. For example:
- `System.IO.Ports` version 8.0.0 → Classified based on .NET 8 support (EOL: 2026-11-10)
- `runtime.native.System.IO.Ports` → Detected as .NET framework component

**Rationale:** Components with releases in the past 5 years are considered maintained. This includes:
- Actively developed projects with frequent releases
- Stable, mature libraries that don't require frequent updates
- Well-established infrastructure components
- Foundational libraries that "just work"
- Framework runtime components supported by their parent framework

**End of Life:**
- Framework components: Framework EOL date
- Regular components: Product EOL date (tied to product lifecycle)

### 2. NO_LONGER_MAINTAINED
**Criteria:**
- Latest release >60 months (5 years) ago, AND
- No explicit deprecation or archival notice

**Rationale:** Old components that haven't been updated in over 5 years but are not explicitly abandoned. May still be functional but pose potential risks due to lack of recent maintenance.

**End of Life:** Last release date

### 3. ABANDONED
**Criteria (EXPLICIT EVIDENCE REQUIRED):**
- Repository explicitly archived by owner, OR
- Package explicitly marked as deprecated in registry, OR
- Official abandonment statement on project website/README

**Rationale:** Only mark as ABANDONED when there is clear, documented evidence of explicit abandonment. This prevents false positives and focuses on truly deprecated software.

**End of Life:** Last known release date

### 4. UNKNOWN
**Criteria:**
- Cannot access repository data
- API rate limits exceeded
- Package exists but no metadata available
- No release date information found

**End of Life:** Cannot be determined

## Framework-Aware Classification

The analyzer includes framework detection to properly classify runtime and framework components based on their parent framework's support lifecycle rather than individual release dates.

### Supported Frameworks

| Framework | Detection Pattern | Support Tracking |
|-----------|------------------|------------------|
| **.NET** | `System.*`, `Microsoft.NETCore.*`, `Microsoft.Extensions.*`, `runtime.*` | .NET 6, 7, 8, 9, Framework 4.x |
| **Java** | `java.*`, `javax.*`, `jakarta.*` | Java 8, 11, 17, 21 |
| **Python** | `python`, `cpython` | Python 3.8-3.13 |
| **Node.js** | `node`, `nodejs` | Node.js 14-22 |
| **Spring** | `spring-*`, `org.springframework.*` | Spring Framework 5.x, 6.x; Spring Boot 2.x, 3.x |

### Framework Detection Logic

1. **Pattern Matching:** Component name is checked against framework-specific regex patterns
2. **Version Inference:** Component version (e.g., `8.0.0`) is mapped to framework version (e.g., .NET 8.0)
3. **Support Lookup:** Framework version is checked against support lifecycle database
4. **Classification Override:** If framework is supported, component is classified as ACTIVELY_MAINTAINED with framework EOL date

### Example: .NET Runtime Components

**Before Framework Detection:**
```
Component: runtime.native.System.IO.Ports @ 8.0.0
Last Release: 2023-11-14 (701 days ago)
Classification: ACTIVELY_MAINTAINED
EOL: 2030-12-31 (product EOL)
Confidence: MEDIUM
```

**After Framework Detection:**
```
Component: runtime.native.System.IO.Ports @ 8.0.0
Last Release: 2023-11-14 (701 days ago)
Detected Framework: .NET 8.0 (LTS)
Classification: ACTIVELY_MAINTAINED
EOL: 2026-11-10 (framework EOL)
Confidence: HIGH
```

### Benefits

1. **Accurate Risk Assessment:** Framework components inherit framework support lifecycle
2. **Reduced False Positives:** Old but supported runtime components are correctly classified
3. **Vendor Accountability:** Classification reflects actual vendor support commitments
4. **Higher Confidence:** Framework-detected components have HIGH confidence ratings

## Data Sources by Ecosystem

### NuGet Packages
**Primary API:** https://api.nuget.org/v3/index.json
**Data Points:**
- Package metadata from NuGet Gallery API
- Published dates for all versions
- Download statistics
- Deprecation status
- GitHub repository link (if available)

**GitHub Fallback:**
- If repository URL available, fetch commit activity
- Check for archived status
- Analyze release patterns

### NPM Packages
**Primary API:** https://registry.npmjs.org/{package}
**Data Points:**
- Package metadata
- All version timestamps
- Deprecation warnings
- Repository URL
- Maintainer count

**Repository Analysis:**
- Clone/fetch recent commit dates
- Check for active branches
- Issue and PR activity

### PyPI Packages
**Primary API:** https://pypi.org/pypi/{package}/json
**Data Points:**
- Release history with dates
- Project URLs including repository
- Classifiers (Development Status)
- Python version support

**Repository Analysis:**
- Commit activity on main branch
- Release tag patterns
- Issue activity

### Maven/Java Packages
**Primary API:** https://search.maven.org/solrsearch/select
**Data Points:**
- Version history
- Timestamp of releases
- Associated repository

**Repository Analysis:**
- GitHub/GitLab activity if available
- Release patterns

### CocoaPods
**Primary API:** https://trunk.cocoapods.org/api/v1/pods/{pod}
**Data Points:**
- Version history
- Source repository
- Last update timestamp

**Repository Analysis:**
- GitHub activity
- Xcode/Swift version compatibility

### GitHub Components
**Primary API:** https://api.github.com
**Data Points:**
- Repository details (created, updated, pushed dates)
- Archived status
- Commit activity via commits API
- Release history
- Open/closed issues ratio
- Branch activity

### URL Fallback Mechanism

When a component lacks a PURL or PURL-based analysis fails, the analyzer uses repository URLs from the SBOM's `externalReferences` field.

**Supported Repository Types:**
- **GitHub:** Full support with version-specific release/tag lookup
- **GitLab:** API-based analysis using project endpoints
- **Bitbucket:** API-based analysis using repository endpoints
- **github.io:** Infers GitHub repository from page URL

**Version Pattern Matching:**
The analyzer intelligently matches version strings to repository tags/releases:

| SBOM Version | Matched Tags | Notes |
|--------------|--------------|-------|
| `3.21.7` | `3.21.7`, `v3.21.7`, `release-3.21.7` | Standard semver |
| `Json.NET 2.0` | `Json.NET_2.0`, `2.0`, `v2.0` | Extracts numeric portion |
| `1.0` | `1.0`, `v1.0`, `1.0.0` | Adds missing patch version |
| `4.5.1-beta` | `4.5.1-beta`, `4.5.1`, `v4.5.1` | Strips pre-release suffix |

**URL Priority Order:**
1. `vcs` - Version control system URL (highest priority)
2. `repository` - Repository URL
3. `website` - Project website (may contain repository link)
4. `distribution` - Distribution URL

**Special Handling:**
- **boost.org** → Redirects to `github.com/boostorg/boost`
- **c-ares.haxx.se** → Redirects to `github.com/c-ares/c-ares`
- **github.io pages** → Infers repository from URL pattern
- **googlesource.com** → Marked for manual review (no public API)

## Calculation Logic

### Analysis Flow

```
1. Attempt PURL-based analysis:
   a. Parse PURL to extract ecosystem, package name, and version
   b. Query package registry API for the SPECIFIC version
   c. Extract version-specific release date and metadata

2. If PURL unavailable or fails, use URL fallback:
   a. Extract URLs from externalReferences
   b. Prioritize: vcs > repository > website > distribution
   c. Determine repository type (GitHub, GitLab, Bitbucket)
   d. Query repository API for version-specific tags/releases

3. Version-specific lookup (GitHub example):
   a. Try releases API for tag matching the version
   b. Fall back to tags API if no release found
   c. Match patterns: "v1.2.3", "1.2.3", "Package_1.2.3", etc.
   d. Extract published date or commit date for that tag

4. Repository enrichment (if available):
   a. Query repository API for latest commit activity
   b. Check archived/deprecated status
   c. Gather community metrics (stars, forks, open issues)

5. Apply FDA-aligned decision matrix:

   # Check for explicit abandonment first
   IF package_deprecated OR repository_archived:
       RETURN ABANDONED (High confidence)
       # Explicit evidence of abandonment

   ELSE IF last_release_days <= 1825 (5 years):
       # Recent activity - covers active development AND stable libraries
       RETURN ACTIVELY_MAINTAINED
       # Confidence: HIGH if commits, MEDIUM otherwise

   ELSE:
       # Old release (>5 years) but NOT explicitly abandoned
       RETURN NO_LONGER_MAINTAINED (Medium confidence)
       # Inactive but not explicitly deprecated
```

**FDA-Aligned Changes:**
1. Three clear categories: ACTIVELY_MAINTAINED, NO_LONGER_MAINTAINED, ABANDONED
2. ABANDONED requires explicit evidence (deprecated/archived)
3. ACTIVELY_MAINTAINED covers everything within 5 years (active + stable)
4. NO_LONGER_MAINTAINED is old (>5 years) but not explicitly abandoned
5. Simpler, clearer decision process aligned with regulatory needs

### End of Life Date Assignment

**Philosophy:** Component end-of-life is tied to the **product's end-of-life**, not individual component release dates. When the product reaches EOL, all its components are no longer supported, regardless of their individual maintenance status.

```
1. User provides product EOL date at analysis start
2. Assign EOL based on support level:

   ACTIVELY_MAINTAINED:
       end_of_life = product_eol_date
       # Component is maintained and will receive support until product EOL

   NO_LONGER_MAINTAINED:
       end_of_life = last_release_date
       # Component no longer maintained, use its last release date

   ABANDONED:
       end_of_life = last_release_date
       # Component explicitly abandoned, use its last release date

   UNKNOWN:
       end_of_life = "Cannot determine"
       # Insufficient data to determine EOL
```

**Rationale:**
- Components are used within a **product context**
- Product vendors support all components (including dependencies) until product EOL
- Individual component ages are less relevant than product lifecycle
- Security patches are applied to all components during product support window
- This aligns with real-world vendor support models (e.g., Red Hat, Ubuntu LTS)

**Example:**
- Product: Enterprise Application v5.0
- Product EOL: 2030-12-31
- Component: JSON library released in 2020
- Component Status: ACTIVELY_MAINTAINED
- Component EOL: **2030-12-31** (same as product)

**Note:** This approach reflects how enterprise software support actually works. A vendor supporting a product until 2030 will maintain all its components until that date, regardless of when individual components were last updated.

## Implementation Considerations

### Rate Limiting
- Implement exponential backoff for API requests
- Cache responses locally
- Use conditional requests (ETags) where supported
- Batch requests when possible

### Authentication
- Use GitHub token for higher rate limits (5000 req/hour vs 60)
- NuGet API key for private feeds (optional)
- NPM tokens for private registries (optional)

### Error Handling
- Network failures: retry with backoff
- 404 responses: mark as UNKNOWN, log for manual review
- Rate limit exceeded: pause and resume
- Invalid PURL: skip and log

### Performance
- Parallel API requests with thread pool
- Local caching with TTL
- Progressive output (stream results as calculated)

## Output Format

Results will be enriched SBOM with additional properties:
```json
{
  "components": [
    {
      "name": "example-package",
      "version": "1.0.0",
      "properties": [
        {
          "name": "supportLevel",
          "value": "ACTIVELY_MAINTAINED"
        },
        {
          "name": "endOfLife",
          "value": "N/A"
        },
        {
          "name": "lastReleaseDate",
          "value": "2024-11-15"
        },
        {
          "name": "daysSinceLastRelease",
          "value": "332"
        },
        {
          "name": "lastCommitDate",
          "value": "2025-09-30"
        },
        {
          "name": "analysisTimestamp",
          "value": "2025-10-13T18:21:25Z"
        },
        {
          "name": "confidenceLevel",
          "value": "HIGH"
        }
      ]
    }
  ]
}
```

## Confidence Levels

- **HIGH**: Full data available from both registry and repository
- **MEDIUM**: Registry data available, repository data missing or partial
- **LOW**: Limited data, based on heuristics only
- **NONE**: No data available, marked as UNKNOWN
