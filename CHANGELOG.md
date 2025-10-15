# Changelog

All notable changes to the SBOM Support Level Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2025-10-15

### Changed
- **BREAKING: FDA-Aligned Support Categories**: Revised classification system to match regulatory requirements
  - **Three categories**: ACTIVELY_MAINTAINED, NO_LONGER_MAINTAINED, ABANDONED
  - Removed MAINTENANCE_MODE category - merged into ACTIVELY_MAINTAINED
  - **ACTIVELY_MAINTAINED**: Components with releases within 5 years (covers active development + stable libraries)
  - **NO_LONGER_MAINTAINED**: Components >5 years old without explicit deprecation
  - **ABANDONED**: Only components with explicit deprecation/archival evidence (registry or repository)
- **Classification Logic Updates**:
  - ACTIVELY_MAINTAINED threshold: Extended to 5 years (from 2 years)
  - All previously "MAINTENANCE_MODE" components now classified as ACTIVELY_MAINTAINED
  - Old components (>5 years) without explicit deprecation classified as NO_LONGER_MAINTAINED
  - ABANDONED requires explicit evidence from package registry website or repository archive status

### Rationale
- Aligns with FDA regulatory framework expectations for medical device software
- Clearer distinction between inactive (NO_LONGER_MAINTAINED) and explicitly abandoned software
- Reduces ambiguity in classification for compliance and regulatory reporting
- Recognizes that stable, mature libraries within 5 years are considered maintained

### Impact
- Expected ACTIVELY_MAINTAINED: ~95% of components (covers both active development and stable libraries)
- Expected NO_LONGER_MAINTAINED: ~3-5% of components (old but not explicitly abandoned)
- Expected ABANDONED: <1% of components (only with explicit evidence)
- Clearer regulatory compliance reporting

## [1.2.0] - 2025-10-14

### Added
- **Product-Based EOL Model**: Component end-of-life dates now tied to product lifecycle instead of individual component ages
  - User prompted for product EOL date at analysis start
  - All maintained components inherit the product's EOL date
  - Aligns with real-world vendor support models (RHEL, Ubuntu, Windows)
  - New `-e/--eol-date` command line flag
- **Interactive EOL Prompt**: Script now prompts user for product EOL date if not provided via command line
- **Community Engagement Metrics**: Analyzer considers GitHub stars (>100) and forks (>20) as viability indicators

### Changed
- **BREAKING: Realistic Support Level Strategy**: Major overhaul to eliminate false positives
  - **ACTIVELY_MAINTAINED** threshold extended from 12 to 24 months
  - **MAINTENANCE_MODE** expanded to cover 24-60 months (was 12-24)
  - **NO_LONGER_MAINTAINED** category eliminated entirely
  - **ABANDONED** now requires explicit evidence (archived repo or deprecation notice)
- **SPDX Annotation Format**: Simplified to remove verbose fields
  - Removed `annotator` field (was "Tool: SBOM-Support-Analyzer")
  - Removed `annotationType` field (was "REVIEW")
  - Cleaner, more concise output while remaining SPDX 2.2/2.3 compliant
- **Philosophy**: Mature, stable libraries no longer penalized for infrequent releases
  - Recognizes that stability ≠ abandonment
  - Only explicit signals (archived/deprecated) trigger ABANDONED classification

### Fixed
- **Issue**: Stable, mature libraries incorrectly marked as NO_LONGER_MAINTAINED or ABANDONED
  - **Fix**: New strategy recognizes stable libraries, drastically reduces false positives
- **Issue**: EOL dates didn't reflect how vendors actually support products
  - **Fix**: Product-based EOL model aligns with industry practice

### Impact
- Expected reduction in ABANDONED classifications: ~50 → ~2 (98% reduction)
- Expected reduction in NO_LONGER_MAINTAINED: ~50 → 0 (100% elimination)
- Expected increase in ACTIVELY_MAINTAINED: ~60 → ~165 (175% increase)
- More accurate risk assessment focusing on truly abandoned software

## [1.1.0] - 2025-10-14

### Added
- **Version-Specific Analysis**: Analyzer now evaluates the exact version specified in the SBOM instead of always using the latest version
  - NuGet packages: Fetches specific version metadata from paginated API responses
  - NPM packages: Looks up specific version from registry data
  - PyPI packages: Retrieves upload date for specific version
  - GitHub releases: Searches for version-specific tags and releases
- **URL Fallback Mechanism**: Components without PURLs can now be analyzed using repository URLs from `externalReferences`
  - GitHub: Full support with version-specific release/tag lookup
  - GitLab: Project API analysis
  - Bitbucket: Repository API analysis
  - github.io: Infers repository from page URL patterns
- **Smart Version Pattern Matching**: Handles various version formats and naming conventions
  - Standard semver: `1.2.3`, `v1.2.3`
  - Named versions: `Json.NET 2.0`, `Release 4.5`
  - Tag variations: `package_1.2.3`, `release-1.2.3`
  - Extracts numeric portions from complex version strings
- **NuGet Pagination Support**: Properly fetches all versions from paginated NuGet API responses
- **GitHub Repository Name Fix**: Corrected regex to support repository names containing dots (e.g., `Newtonsoft.Json`)
- **Special URL Handling**: Built-in redirects for common libraries
  - `boost.org` → `github.com/boostorg/boost`
  - `c-ares.haxx.se` → `github.com/c-ares/c-ares`

### Changed
- **Package Registry Analysis**: All package managers now prioritize specific version lookup over latest version
- **GitHub Analysis**: Repository analysis now attempts version-specific release date before falling back to latest commit
- **Support Level Classification**: Now based on the age of the specific version, not the repository's latest activity
- **Confidence Levels**: Improved accuracy by distinguishing between version-specific data and repository-level data

### Fixed
- **Issue**: Google.Protobuf v3.21.7 (from 2022) was incorrectly classified as ACTIVELY_MAINTAINED using latest version data
  - **Fix**: Now correctly uses 2022-09-29 release date and classifies as NO_LONGER_MAINTAINED
- **Issue**: Packages without PURLs (e.g., `JamesNK/Newtonsoft.Json @ Json.NET 2.0`) were skipped entirely
  - **Fix**: URL fallback mechanism analyzes these packages using repository URLs
- **Issue**: NuGet API pagination wasn't handled, missing many package versions
  - **Fix**: Implemented proper pagination support for all NuGet queries
- **Issue**: Repository names with dots (e.g., `Newtonsoft.Json`) were truncated
  - **Fix**: Updated regex pattern to allow dots in repository names

### Technical Details

**Version-Specific Lookup Example:**
```
Before: Google.Protobuf v3.21.7
  - Used: Latest version (4.x from 2025)
  - Result: ACTIVELY_MAINTAINED ❌

After: Google.Protobuf v3.21.7
  - Used: Specific version 3.21.7 (2022-09-29)
  - Result: NO_LONGER_MAINTAINED ✅
  - Days since release: 1,111 days (~3 years)
```

**URL Fallback Example:**
```
Component: JamesNK/Newtonsoft.Json @ Json.NET 2.0
  - No PURL available
  - Found: GitHub URL in externalReferences
  - Matched: Tag "Json.NET_2.0" from 2019
  - Result: ABANDONED (6 years old) ✅
```

### Documentation Updates
- Updated README.md with version-specific analysis features
- Enhanced STRATEGY.md with URL fallback mechanism documentation
- Added version pattern matching examples
- Documented special URL handling cases

### Breaking Changes
None - All changes are backward compatible. The analyzer produces the same output format but with more accurate data.

## [1.0.0] - 2025-10-13

### Added
- Initial release
- Support for CycloneDX 1.4, 1.5, 1.6
- Support for SPDX 2.2, 2.3
- Package registry analysis (NuGet, NPM, PyPI, Maven, CocoaPods)
- GitHub repository analysis
- Support level classification (ACTIVELY_MAINTAINED, MAINTENANCE_MODE, NO_LONGER_MAINTAINED, ABANDONED, UNKNOWN)
- End-of-life date calculation
- Confidence level assessment
- Zero external dependencies
- Comprehensive documentation
