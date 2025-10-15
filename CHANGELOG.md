# Changelog

All notable changes to the SBOM Support Level Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
