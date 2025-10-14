# Support Level Analysis Strategy for CycloneDX or SPDX SBOM Components

## Overview
This strategy determines the maintenance status and end-of-life dates for software components by analyzing real-world data from package registries, source repositories, and release patterns.

## Support Level Definitions

### 1. ACTIVELY_MAINTAINED
**Criteria:**
- Latest release within last 12 months
- Active commit activity (commits in last 6 months)
- Open repository with recent activity
- Active issue/PR management

**End of Life:** Last release date + 5 years (estimated ongoing support)

### 2. MAINTENANCE_MODE
**Criteria:**
- Latest release between 12-24 months ago
- Sporadic commit activity (some commits in last 12 months)
- Repository still accessible
- Security fixes still being applied

**End of Life:** Estimated 2-3 years from last major release

### 3. NO_LONGER_MAINTAINED
**Criteria:**
- Latest release between 24-48 months ago
- No recent commit activity (no commits in last 12 months)
- Repository may still be accessible but inactive
- No response to issues/PRs

**End of Life:** Last release date + 2 years

### 4. ABANDONED
**Criteria:**
- Latest release >48 months ago
- No commit activity in 24+ months
- Repository archived or deprecated
- Explicit deprecation notice

**End of Life:** Last known release date

### 5. UNKNOWN
**Criteria:**
- Cannot access repository data
- API rate limits exceeded
- Package exists but no metadata available

**End of Life:** Cannot be determined

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

## Calculation Logic

### Support Level Algorithm

```
1. Parse PURL to extract ecosystem, package name, and version
2. Query primary package registry API for metadata
3. Calculate days since last release
4. If repository URL available:
   a. Query repository API for commit activity
   b. Check archived/deprecated status
   c. Calculate commit recency score
5. Apply decision matrix:

   IF archived OR explicit deprecation:
       RETURN ABANDONED
   ELSE IF last_release_days <= 365 AND recent_commits:
       RETURN ACTIVELY_MAINTAINED
   ELSE IF last_release_days <= 730 AND some_commits:
       RETURN MAINTENANCE_MODE
   ELSE IF last_release_days <= 1460:
       RETURN NO_LONGER_MAINTAINED
   ELSE:
       RETURN ABANDONED
```

### End of Life Date Calculation

```
1. Determine support level from above
2. Calculate based on patterns:

   ACTIVELY_MAINTAINED:
       # Estimate 5 years of ongoing support
       end_of_life = last_release_date + 5_years

   MAINTENANCE_MODE:
       # Conservative estimate for security-only updates
       end_of_life = last_release_date + 3_years

   NO_LONGER_MAINTAINED:
       # Limited support window
       end_of_life = last_release_date + 2_years

   ABANDONED:
       # Already reached end of life
       end_of_life = last_release_date

   UNKNOWN:
       end_of_life = "Cannot determine"
```

**Note:** All EOL dates are estimates based on release patterns and industry standards. Actively maintained projects receive longer EOL estimates (5 years) to reflect ongoing support commitments.

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
